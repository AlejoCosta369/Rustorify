//! Controls the Tor service via systemctl.
//!
//! The main thing this module adds on top of "just run systemctl" is the
//! readiness check: after starting or restarting Tor, we poll its SOCKS5
//! port until it responds. That way the caller knows Tor is actually ready
//! to accept connections before we apply firewall rules.

use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};
use anyhow::{bail, Context, Result};

use crate::config::{SOCKS_PORT, TOR_READY_TIMEOUT_SECS};
use crate::{info, ok};

// ─── Internal helper ─────────────────────────────────────────────────────────

/// Run `systemctl <verb> tor` and return an error if it fails.
///
/// We always pass an explicit, minimal PATH to avoid issues where the
/// system PATH is unusual or has been modified.
fn systemctl(verb: &str) -> Result<()> {
    tracing::debug!("systemctl {} tor", verb);

    let status = Command::new("systemctl")
        .args(&[verb, "tor"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()
        .with_context(|| format!("failed to run systemctl {}", verb))?;

    if !status.success() {
        bail!("systemctl {} tor failed with {}", verb, status);
    }
    Ok(())
}

// ─── Readiness probe ─────────────────────────────────────────────────────────

/// Wait until Tor's SOCKS5 port starts accepting connections, or give up after a timeout.
///
/// We poll every 500 ms and print a dot every ~5 seconds so the user
/// can see progress. The SOCKS port is the right thing to check here —
/// it only opens once Tor has finished bootstrapping and is ready to route traffic.
pub fn wait_ready(timeout_secs: u64) -> Result<()> {
    let addr = format!("127.0.0.1:{}", SOCKS_PORT);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let poll = Duration::from_millis(500);

    info!("Waiting for Tor to be ready (SOCKS port {})…", SOCKS_PORT);

    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &addr.parse().expect("valid addr"),
            Duration::from_secs(1),
        )
        .is_ok()
        {
            ok!("Tor is ready");
            return Ok(());
        }
        std::thread::sleep(poll);

        // Print a dot every ~5 seconds so the user knows we're still waiting.
        let elapsed = deadline - Instant::now();
        let remaining = timeout_secs.saturating_sub(
            timeout_secs.saturating_sub(elapsed.as_secs()),
        );
        if remaining % 5 == 0 && remaining != timeout_secs {
            print!(".");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    }

    bail!(
        "Tor did not become ready within {} seconds — \
         check `journalctl -u tor` for errors",
        timeout_secs
    )
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Start the Tor service and wait for it to finish bootstrapping.
pub fn start() -> Result<()> {
    info!("Starting Tor service…");
    systemctl("start").context("could not start tor")?;
    wait_ready(TOR_READY_TIMEOUT_SECS)?;
    ok!("Tor service started");
    Ok(())
}

/// Stop the Tor service.
pub fn stop() -> Result<()> {
    info!("Stopping Tor service…");
    systemctl("stop").context("could not stop tor")?;
    ok!("Tor service stopped");
    Ok(())
}

/// Restart Tor to get a fresh circuit with a different exit node.
/// We wait for readiness again after the restart so the caller knows
/// when it's safe to start making connections.
pub fn restart() -> Result<()> {
    info!("Restarting Tor service (new circuit)…");
    systemctl("restart").context("could not restart tor")?;
    wait_ready(TOR_READY_TIMEOUT_SECS)?;
    ok!("Tor service restarted — new exit node assigned");
    Ok(())
}

/// Returns true if the Tor service is currently running.
pub fn is_running() -> bool {
    Command::new("systemctl")
        .args(&["is-active", "--quiet", "tor"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
