//! Pre-flight checks that run before doing anything else.
//!
//! These verify that the environment is ready:
//! - the process is running as root
//! - required tools (tor, curl, iptables) are installed
//! - the installation directories exist

use std::path::Path;
use std::process::Command;
use anyhow::{bail, Context, Result};

use crate::config::{BACKUP_DIR, DATA_DIR};

// ─── Root check ─────────────────────────────────────────────────────────────

/// Make sure we're running as root (UID 0).
///
/// We read `/proc/self/status` directly instead of running `id -u` as a
/// shell command. This avoids any risk from a tampered PATH and doesn't
/// spawn an extra process just to check a number.
pub fn check_root() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")
        .context("cannot read /proc/self/status")?;

    for line in status.lines() {
        if line.starts_with("Uid:") {
            // The line looks like: "Uid:  1000  1000  1000  1000"
            // The third field is the effective UID — that's the one that matters.
            let euid = line
                .split_whitespace()
                .nth(2)
                .context("malformed /proc/self/status Uid line")?;

            if euid == "0" {
                return Ok(());
            } else {
                bail!(
                    "this program must be run as root (effective UID: {})",
                    euid
                );
            }
        }
    }

    bail!("could not determine effective UID from /proc/self/status");
}

// ─── Dependency check ───────────────────────────────────────────────────────

/// Check that all required external tools are installed.
///
/// We need `tor` to route traffic, `curl` to verify the circuit,
/// and `iptables` to set up the firewall rules. If any of them are
/// missing, we bail early with a clear error message.
pub fn check_dependencies() -> Result<()> {
    for dep in &["tor", "curl", "iptables"] {
        if !binary_exists(dep) {
            bail!(
                "required dependency '{}' is not installed or not in PATH",
                dep
            );
        }
    }
    Ok(())
}

/// Check whether a binary exists by asking `which` for it.
///
/// We pass a fixed PATH so this can't be fooled by a weird environment.
fn binary_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── Directory check ─────────────────────────────────────────────────────────

/// Verify that the installation directories were created by `make install`.
///
/// If they don't exist, the user probably skipped the installation step.
/// We check for both the data dir (where our torrc lives) and the backup
/// dir (where we store copies of files before modifying them).
pub fn check_directories() -> Result<()> {
    for dir in &[DATA_DIR, BACKUP_DIR] {
        if !Path::new(dir).is_dir() {
            bail!(
                "directory '{}' does not exist — run 'sudo bash install.sh' first",
                dir
            );
        }
    }
    Ok(())
}
