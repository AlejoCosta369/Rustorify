//! rustorify — Transparent proxy through Tor, written in Rust.
//!
//! This is the entry point. It sets up logging, verifies we're running
//! as root, grabs the process lock, then dispatches to the right command
//! based on the flags the user passed.
//!
//! # How it works
//!
//! When you run `--tor`, the program:
//! 1. Backs up your current torrc and resolv.conf
//! 2. Installs a torrc that enables TransPort and DNSPort
//! 3. Points DNS at Tor's local DNS port (127.0.0.1)
//! 4. Starts Tor and waits for it to be ready
//! 5. Blocks IPv6 (Tor doesn't support it in transparent proxy mode)
//! 6. Installs iptables rules that redirect all TCP through Tor
//! 7. Optionally installs a kill switch that restores clearnet if Tor dies
//!
//! When you run `--clearnet`, it undoes all of that in reverse order.

mod checks;
mod cli;
mod config;
mod files;
mod firewall;
mod ipinfo;
mod lock;
mod output;
mod tor;

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Parser;
use colored::Colorize;

use cli::Cli;
use config::{KILLSWITCH_DROPIN_DIR, KILLSWITCH_DROPIN_FILE};

fn main() {
    if let Err(e) = run() {
        err!("{:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging. RUST_LOG env var takes priority over the --log-level flag.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.parse().unwrap_or_default()),
        )
        .without_time()
        .with_target(false)
        .init();

    // Everything below requires root.
    checks::check_root()?;

    // Grab the process lock. It's automatically released when `_lock` goes out of scope.
    let _lock = lock::Lock::acquire()?;

    // Route to the right command.
    if cli.tor {
        cmd_tor(cli.kill_switch)
    } else if cli.clearnet {
        cmd_clearnet()
    } else if cli.restart {
        cmd_restart()
    } else if cli.status {
        cmd_status()
    } else if cli.ipinfo {
        cmd_ipinfo()
    } else {
        bail!("no command specified — run with --help");
    }
}

// ─── Kill switch ─────────────────────────────────────────────────────────────

/// Install a systemd drop-in that automatically runs `--clearnet` if Tor stops.
///
/// This is the kill switch feature. Without it, if the Tor service crashes,
/// your traffic would silently fall back to your real IP. With it, systemd
/// runs our `--clearnet` command the moment Tor stops, blocking traffic
/// before any leakage can happen.
fn install_kill_switch() -> Result<()> {
    info!("Installing kill switch (systemd dropin)…");

    fs::create_dir_all(KILLSWITCH_DROPIN_DIR)?;

    let content = "[Service]\nExecStopPost=/usr/local/bin/rustorify --clearnet\n";
    files::atomic_write(KILLSWITCH_DROPIN_FILE, content)?;

    // Tell systemd to pick up the new drop-in file.
    let _ = Command::new("systemctl")
        .arg("daemon-reload")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status();

    ok!("Kill switch installed — clearnet restored automatically if Tor stops");
    Ok(())
}

/// Remove the kill switch drop-in file, if it exists.
fn remove_kill_switch() {
    if std::path::Path::new(KILLSWITCH_DROPIN_FILE).exists() {
        let _ = fs::remove_file(KILLSWITCH_DROPIN_FILE);
        let _ = Command::new("systemctl")
            .arg("daemon-reload")
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .status();
        ok!("Kill switch removed");
    }
}

// ─── Signal handler ──────────────────────────────────────────────────────────

/// Register a Ctrl-C / SIGTERM handler that performs a clean shutdown.
///
/// If you interrupt the program while it's activating Tor (e.g. Tor hangs
/// during bootstrapping), this handler fires, tears down whatever was set
/// up so far, and exits cleanly — leaving the system in a safe state rather
/// than a half-configured one.
///
/// Pressing Ctrl-C a second time forces an immediate hard exit.
fn setup_signal_handler(interrupted: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        if interrupted.swap(true, Ordering::SeqCst) {
            // Already interrupted once — user is insistent, exit immediately.
            std::process::exit(130);
        }

        eprintln!("\n{} Interrupted — cleaning up…", "[!]".red().bold());

        // Best-effort cleanup — we ignore individual errors here because we're
        // already in a recovery path and want to attempt everything we can.
        firewall::deactivate();
        firewall::unblock_ipv6();
        remove_kill_switch();
        let _ = tor::stop();
        let _ = files::restore_files();
        let _ = files::write_state(false);

        std::process::exit(130);
    })
    .expect("failed to set signal handler");
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// `--tor`: Set up the transparent proxy and route all traffic through Tor.
fn cmd_tor(kill_switch: bool) -> Result<()> {
    println!(
        "\n{}",
        "rustorify — Activating transparent Tor proxy".bold()
    );
    output::separator();

    if files::is_proxy_active() {
        bail!("proxy is already active — run --clearnet first");
    }

    checks::check_dependencies()?;
    checks::check_directories()?;

    // Register the Ctrl-C handler now so any interruption during setup
    // triggers cleanup rather than leaving things in a broken state.
    let interrupted = Arc::new(AtomicBool::new(false));
    setup_signal_handler(interrupted.clone());

    // Step 1: Save copies of the files we're about to modify.
    files::backup_files()?;

    // Step 2: Install the torrc that enables TransPort and DNSPort.
    files::install_torrc()?;

    // Step 3: Point DNS at Tor so lookups don't leak to your ISP.
    files::set_tor_dns()?;

    // Step 4: Start Tor and wait until it's actually ready.
    // We do this before adding firewall rules — if we added them first,
    // traffic would be dropped while Tor is still bootstrapping.
    tor::start()?;

    // Step 5: Block IPv6 so there's no way to bypass Tor via IPv6.
    firewall::block_ipv6()?;

    // Step 6: Install the iptables redirect rules.
    // If anything goes wrong here, activate_with_rollback() will undo
    // the partial rules before returning the error.
    firewall::activate_with_rollback()?;

    // Step 7: Record that the proxy is active.
    files::write_state(true)?;

    // Step 8: Optionally install the kill switch.
    if kill_switch {
        install_kill_switch()?;
    }

    // Step 9: Verify the circuit and check for DNS leaks.
    println!();
    match ipinfo::verify_tor_circuit() {
        Ok(_) => {}
        Err(e) => warn!("Circuit verification failed: {:#}", e),
    }

    if let Err(e) = ipinfo::dns_leak_check() {
        warn!("DNS leak check: {:#}", e);
    }

    output::separator();
    ok!("Transparent Tor proxy is ACTIVE\n");
    Ok(())
}

/// `--clearnet`: Tear down the proxy and restore normal internet access.
fn cmd_clearnet() -> Result<()> {
    println!(
        "\n{}",
        "rustorify — Deactivating transparent Tor proxy".bold()
    );
    output::separator();

    // Don't abort if the state file is missing or says "inactive" — the user may
    // be recovering from a crash, reboot, or failed --tor run. Cleanup is safe to
    // run even if nothing was active (ipt_del ignores missing rules, etc.).
    if !files::is_proxy_active() {
        warn!("proxy state file not found or inactive — attempting cleanup anyway");
    }

    // Step 1: Remove firewall rules first — this immediately stops new
    // connections from being redirected through Tor.
    firewall::deactivate();

    // Step 2: Re-enable IPv6.
    firewall::unblock_ipv6();

    // Step 3: Remove the kill switch drop-in if it's installed.
    remove_kill_switch();

    // Steps 4 and 5 run independently: a Tor stop failure must not prevent
    // DNS and file restoration. Losing DNS is what leaves the user with no internet.
    let tor_err   = tor::stop().err();
    let files_err = files::restore_files().err();

    // Step 6: Update the state file regardless of the above outcomes.
    let _ = files::write_state(false);

    output::separator();
    ok!("Normal clearnet access restored\n");

    if let Some(e) = tor_err {
        warn!("could not stop Tor cleanly: {:#}", e);
    }
    if let Some(e) = files_err {
        bail!("file restoration failed: {:#}", e);
    }

    Ok(())
}

/// `--restart`: Get a fresh Tor circuit with a different exit node.
fn cmd_restart() -> Result<()> {
    println!("\n{}", "rustorify — Restarting Tor (new circuit)".bold());
    output::separator();

    if !files::is_proxy_active() {
        bail!("proxy is not active — run --tor first");
    }

    tor::restart()?;

    // Show the new exit IP after the circuit changes.
    println!();
    match ipinfo::verify_tor_circuit() {
        Ok(_) => {}
        Err(e) => warn!("{:#}", e),
    }

    output::separator();
    ok!("New Tor circuit established\n");
    Ok(())
}

/// `--status`: Show what's currently running and whether traffic is going through Tor.
fn cmd_status() -> Result<()> {
    println!("\n{}", "rustorify — Status".bold());
    output::separator();

    let proxy_active = files::is_proxy_active();
    let tor_running  = tor::is_running();
    let ks_installed = std::path::Path::new(KILLSWITCH_DROPIN_FILE).exists();

    let state_str = if proxy_active {
        "ACTIVE".green().bold().to_string()
    } else {
        "INACTIVE".red().bold().to_string()
    };

    let tor_str = if tor_running {
        "running".green().to_string()
    } else {
        "stopped".red().to_string()
    };

    println!("  Proxy state  : {}", state_str);
    println!("  Tor service  : {}", tor_str);
    println!("  Kill switch  : {}", if ks_installed { "installed".green() } else { "not installed".dimmed() });

    // Only run the live checks if both the proxy and Tor are active —
    // there's no point hitting the network if Tor isn't running.
    if proxy_active && tor_running {
        println!();
        match ipinfo::verify_tor_circuit() {
            Ok(_) => {}
            Err(e) => warn!("{:#}", e),
        }
        if let Err(e) = ipinfo::dns_leak_check() {
            warn!("{:#}", e);
        }
    }

    output::separator();
    println!();
    Ok(())
}

/// `--ipinfo`: Show your current public IP address.
fn cmd_ipinfo() -> Result<()> {
    println!("\n{}", "rustorify — Public IP".bold());
    output::separator();

    match ipinfo::get_public_ip() {
        Ok(ip) => ok!("Public IP: {}", ip.bold()),
        Err(e) => warn!("{:#}", e),
    }

    output::separator();
    println!();
    Ok(())
}
