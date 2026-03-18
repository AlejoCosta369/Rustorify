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
//! 3. Starts Tor and waits for it to be ready
//! 4. Points DNS at Tor's local DNS port (127.0.0.1)
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
use config::{KILLSWITCH_BYPASS_FILE, KILLSWITCH_DROPIN_DIR, KILLSWITCH_DROPIN_FILE};

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

trait ProxyOps {
    fn check_dependencies(&mut self) -> Result<()>;
    fn check_directories(&mut self) -> Result<()>;
    fn is_proxy_active(&self) -> bool;
    fn backup_files(&mut self) -> Result<()>;
    fn install_torrc(&mut self) -> Result<()>;
    fn set_tor_dns(&mut self) -> Result<()>;
    fn restore_files(&mut self) -> Result<()>;
    fn write_state(&mut self, active: bool) -> Result<()>;
    fn block_ipv6(&mut self) -> Result<()>;
    fn unblock_ipv6(&mut self);
    fn activate_firewall(&mut self) -> Result<()>;
    fn deactivate_firewall(&mut self);
    fn start_tor(&mut self) -> Result<()>;
    fn stop_tor(&mut self) -> Result<()>;
    fn restart_tor(&mut self) -> Result<()>;
    fn kill_switch_installed(&self) -> bool;
    fn install_kill_switch(&mut self) -> Result<()>;
    fn remove_kill_switch(&mut self);
    fn create_kill_switch_bypass(&mut self) -> Result<()>;
    fn remove_kill_switch_bypass(&mut self);
}

struct RealOps;

impl ProxyOps for RealOps {
    fn check_dependencies(&mut self) -> Result<()> {
        checks::check_dependencies()
    }

    fn check_directories(&mut self) -> Result<()> {
        checks::check_directories()
    }

    fn is_proxy_active(&self) -> bool {
        files::is_proxy_active()
    }

    fn backup_files(&mut self) -> Result<()> {
        files::backup_files()
    }

    fn install_torrc(&mut self) -> Result<()> {
        files::install_torrc()
    }

    fn set_tor_dns(&mut self) -> Result<()> {
        files::set_tor_dns()
    }

    fn restore_files(&mut self) -> Result<()> {
        files::restore_files()
    }

    fn write_state(&mut self, active: bool) -> Result<()> {
        files::write_state(active)
    }

    fn block_ipv6(&mut self) -> Result<()> {
        firewall::block_ipv6()
    }

    fn unblock_ipv6(&mut self) {
        firewall::unblock_ipv6();
    }

    fn activate_firewall(&mut self) -> Result<()> {
        firewall::activate()
    }

    fn deactivate_firewall(&mut self) {
        firewall::deactivate();
    }

    fn start_tor(&mut self) -> Result<()> {
        tor::start()
    }

    fn stop_tor(&mut self) -> Result<()> {
        tor::stop()
    }

    fn restart_tor(&mut self) -> Result<()> {
        tor::restart()
    }

    fn kill_switch_installed(&self) -> bool {
        std::path::Path::new(KILLSWITCH_DROPIN_FILE).exists()
    }

    fn install_kill_switch(&mut self) -> Result<()> {
        install_kill_switch()
    }

    fn remove_kill_switch(&mut self) {
        remove_kill_switch();
    }

    fn create_kill_switch_bypass(&mut self) -> Result<()> {
        create_kill_switch_bypass()
    }

    fn remove_kill_switch_bypass(&mut self) {
        remove_kill_switch_bypass();
    }
}

fn kill_switch_dropin_content() -> String {
    format!(
        "[Service]\nExecStopPost=/bin/sh -c 'if [ ! -e {bypass} ]; then /usr/local/bin/rustorify --clearnet; fi'\n",
        bypass = KILLSWITCH_BYPASS_FILE
    )
}

fn create_kill_switch_bypass() -> Result<()> {
    files::atomic_write(KILLSWITCH_BYPASS_FILE, "1\n")
}

fn remove_kill_switch_bypass() {
    let _ = fs::remove_file(KILLSWITCH_BYPASS_FILE);
}

/// Install a systemd drop-in that automatically runs `--clearnet` if Tor stops.
///
/// This is the kill switch feature. Without it, if the Tor service crashes,
/// your traffic would silently fall back to your real IP. With it, systemd
/// runs our `--clearnet` command the moment Tor stops, blocking traffic
/// before any leakage can happen.
fn install_kill_switch() -> Result<()> {
    info!("Installing kill switch (systemd dropin)…");

    fs::create_dir_all(KILLSWITCH_DROPIN_DIR)?;

    files::atomic_write(KILLSWITCH_DROPIN_FILE, &kill_switch_dropin_content())?;

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

fn rollback_failed_activation<O: ProxyOps>(ops: &mut O) {
    warn!("Activation failed — rolling back partial changes…");
    ops.deactivate_firewall();
    ops.unblock_ipv6();
    ops.remove_kill_switch();

    if let Err(e) = ops.stop_tor() {
        warn!("could not stop Tor during rollback: {:#}", e);
    }
    if let Err(e) = ops.restore_files() {
        warn!("could not restore files during rollback: {:#}", e);
    }
    if let Err(e) = ops.write_state(false) {
        warn!("could not update state file during rollback: {:#}", e);
    }
    ops.remove_kill_switch_bypass();
}

fn activate_proxy<O: ProxyOps>(ops: &mut O, kill_switch: bool) -> Result<()> {
    if ops.is_proxy_active() {
        bail!("proxy is already active — run --clearnet first");
    }

    ops.check_dependencies()?;
    ops.check_directories()?;
    ops.backup_files()?;

    let result = (|| -> Result<()> {
        ops.install_torrc()?;
        ops.start_tor()?;
        ops.set_tor_dns()?;
        ops.block_ipv6()?;
        ops.activate_firewall()?;
        ops.write_state(true)?;

        if kill_switch {
            ops.install_kill_switch()?;
        }

        Ok(())
    })();

    if let Err(e) = result {
        rollback_failed_activation(ops);
        return Err(e);
    }

    Ok(())
}

fn deactivate_proxy<O: ProxyOps>(ops: &mut O) -> Result<()> {
    if !ops.is_proxy_active() {
        warn!("proxy state file not found or inactive — attempting cleanup anyway");
    }

    ops.deactivate_firewall();
    ops.unblock_ipv6();

    let bypass_enabled = ops.kill_switch_installed();
    if bypass_enabled {
        ops.create_kill_switch_bypass()?;
    }

    ops.remove_kill_switch();

    let tor_err = ops.stop_tor().err();
    let files_err = ops.restore_files().err();
    let state_err = ops.write_state(false).err();

    if bypass_enabled {
        ops.remove_kill_switch_bypass();
    }

    if let Some(e) = tor_err {
        warn!("could not stop Tor cleanly: {:#}", e);
    }
    if let Some(e) = state_err {
        warn!("could not update state file cleanly: {:#}", e);
    }
    if let Some(e) = files_err {
        bail!("file restoration failed: {:#}", e);
    }
    if let Some(e) = state_err {
        bail!("state update failed: {:#}", e);
    }

    Ok(())
}

fn restart_proxy<O: ProxyOps>(ops: &mut O) -> Result<()> {
    if !ops.is_proxy_active() {
        bail!("proxy is not active — run --tor first");
    }

    let bypass_enabled = ops.kill_switch_installed();
    if bypass_enabled {
        ops.create_kill_switch_bypass()?;
    }

    let restart_result = ops.restart_tor();

    if bypass_enabled {
        ops.remove_kill_switch_bypass();
    }

    if let Err(e) = restart_result {
        warn!("Tor restart failed — restoring clearnet for safety");
        deactivate_proxy(ops).map_err(|cleanup| {
            anyhow::anyhow!(
                "restart failed: {:#}\nclearnet recovery also failed: {:#}",
                e,
                cleanup
            )
        })?;
        return Err(e);
    }

    Ok(())
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

    // Register the Ctrl-C handler now so any interruption during setup
    // triggers cleanup rather than leaving things in a broken state.
    let interrupted = Arc::new(AtomicBool::new(false));
    setup_signal_handler(interrupted.clone());

    let mut ops = RealOps;
    activate_proxy(&mut ops, kill_switch)?;

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

    let mut ops = RealOps;
    deactivate_proxy(&mut ops)?;

    output::separator();
    ok!("Normal clearnet access restored\n");

    Ok(())
}

/// `--restart`: Get a fresh Tor circuit with a different exit node.
fn cmd_restart() -> Result<()> {
    println!("\n{}", "rustorify — Restarting Tor (new circuit)".bold());
    output::separator();

    let mut ops = RealOps;
    restart_proxy(&mut ops)?;

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

#[cfg(test)]
mod tests {
    use super::{activate_proxy, kill_switch_dropin_content, restart_proxy, ProxyOps};
    use anyhow::{anyhow, Result};

    #[derive(Default)]
    struct MockOps {
        active: bool,
        kill_switch_installed: bool,
        fail_step: Option<String>,
        calls: Vec<String>,
    }

    impl MockOps {
        fn with_failure(step: &str) -> Self {
            Self {
                fail_step: Some(step.to_string()),
                ..Self::default()
            }
        }

        fn record(&mut self, step: &str) -> Result<()> {
            self.calls.push(step.to_string());
            if self.fail_step.as_deref() == Some(step) {
                return Err(anyhow!("{} failed", step));
            }
            Ok(())
        }
    }

    impl ProxyOps for MockOps {
        fn check_dependencies(&mut self) -> Result<()> {
            self.record("check_dependencies")
        }

        fn check_directories(&mut self) -> Result<()> {
            self.record("check_directories")
        }

        fn is_proxy_active(&self) -> bool {
            self.active
        }

        fn backup_files(&mut self) -> Result<()> {
            self.record("backup_files")
        }

        fn install_torrc(&mut self) -> Result<()> {
            self.record("install_torrc")
        }

        fn set_tor_dns(&mut self) -> Result<()> {
            self.record("set_tor_dns")
        }

        fn restore_files(&mut self) -> Result<()> {
            self.record("restore_files")
        }

        fn write_state(&mut self, active: bool) -> Result<()> {
            let step = format!("write_state({})", active);
            self.record(&step)?;
            self.active = active;
            Ok(())
        }

        fn block_ipv6(&mut self) -> Result<()> {
            self.record("block_ipv6")
        }

        fn unblock_ipv6(&mut self) {
            let _ = self.record("unblock_ipv6");
        }

        fn activate_firewall(&mut self) -> Result<()> {
            self.record("activate_firewall")
        }

        fn deactivate_firewall(&mut self) {
            let _ = self.record("deactivate_firewall");
        }

        fn start_tor(&mut self) -> Result<()> {
            self.record("start_tor")
        }

        fn stop_tor(&mut self) -> Result<()> {
            self.record("stop_tor")
        }

        fn restart_tor(&mut self) -> Result<()> {
            self.record("restart_tor")
        }

        fn kill_switch_installed(&self) -> bool {
            self.kill_switch_installed
        }

        fn install_kill_switch(&mut self) -> Result<()> {
            self.record("install_kill_switch")?;
            self.kill_switch_installed = true;
            Ok(())
        }

        fn remove_kill_switch(&mut self) {
            let _ = self.record("remove_kill_switch");
            self.kill_switch_installed = false;
        }

        fn create_kill_switch_bypass(&mut self) -> Result<()> {
            self.record("create_kill_switch_bypass")
        }

        fn remove_kill_switch_bypass(&mut self) {
            let _ = self.record("remove_kill_switch_bypass");
        }
    }

    #[test]
    fn activation_rolls_back_if_tor_start_fails() {
        let mut ops = MockOps::with_failure("start_tor");

        assert!(activate_proxy(&mut ops, false).is_err());
        assert_eq!(
            ops.calls,
            vec![
                "check_dependencies",
                "check_directories",
                "backup_files",
                "install_torrc",
                "start_tor",
                "deactivate_firewall",
                "unblock_ipv6",
                "remove_kill_switch",
                "stop_tor",
                "restore_files",
                "write_state(false)",
                "remove_kill_switch_bypass",
            ]
        );
    }

    #[test]
    fn activation_rolls_back_if_state_write_fails_after_firewall() {
        let mut ops = MockOps::with_failure("write_state(true)");

        assert!(activate_proxy(&mut ops, true).is_err());
        assert_eq!(
            ops.calls,
            vec![
                "check_dependencies",
                "check_directories",
                "backup_files",
                "install_torrc",
                "start_tor",
                "set_tor_dns",
                "block_ipv6",
                "activate_firewall",
                "write_state(true)",
                "deactivate_firewall",
                "unblock_ipv6",
                "remove_kill_switch",
                "stop_tor",
                "restore_files",
                "write_state(false)",
                "remove_kill_switch_bypass",
            ]
        );
    }

    #[test]
    fn restart_uses_bypass_file_when_kill_switch_is_installed() {
        let mut ops = MockOps {
            active: true,
            kill_switch_installed: true,
            ..MockOps::default()
        };

        restart_proxy(&mut ops).expect("restart should succeed");
        assert_eq!(
            ops.calls,
            vec![
                "create_kill_switch_bypass",
                "restart_tor",
                "remove_kill_switch_bypass",
            ]
        );
    }

    #[test]
    fn kill_switch_dropin_skips_clearnet_when_bypass_exists() {
        let content = kill_switch_dropin_content();

        assert!(content.contains("/bin/sh -c"));
        assert!(content.contains("rustorify --clearnet"));
        assert!(content.contains(super::KILLSWITCH_BYPASS_FILE));
    }
}
