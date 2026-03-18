//! Everything related to reading and writing files on disk.
//!
//! This module handles three main jobs:
//! 1. Backing up and restoring `/etc/tor/torrc` and `/etc/resolv.conf`
//!    before and after we modify them.
//! 2. Installing the Tor transparent-proxy config and pointing DNS at Tor.
//! 3. Keeping a small state file so the program knows whether the proxy
//!    is currently active or not.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use anyhow::{bail, Context, Result};

use crate::config::{
    DATA_DIR, RESOLV_BACKUP, RESOLV_PATH, STATE_FILE, TORRC_BACKUP, TORRC_PATH,
};
#[cfg(unix)]
use crate::config::RESOLV_LINK_BACKUP;
use crate::warn;

// ─── Atomic write ────────────────────────────────────────────────────────────

/// Write content to a file safely using a temp-file-then-rename pattern.
///
/// Two security properties here:
///
/// 1. **Atomicity**: a rename on the same filesystem is instant — the file
///    switches from old to new content in one step, never left half-written.
///    This matters for `/etc/resolv.conf`: a half-written file means broken DNS.
///
/// 2. **Permissions**: the temp file is created with mode `0600` (owner read/write only)
///    so no other user can read sensitive content (torrc config, DNS settings)
///    during the brief window before the rename completes.
pub fn atomic_write(path: &str, content: &str) -> Result<()> {
    // Same directory as the destination so the rename stays on one filesystem.
    // PID in the name avoids collisions between parallel runs.
    let tmp = format!("{}.tmp.{}", path, std::process::id());

    // Create the temp file with strict permissions from the start.
    // 0600 = only the owner (root) can read or write it.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("failed to create temp file '{}'", tmp))?;

    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write to temp file '{}'", tmp))?;

    // Flush to disk before renaming so the content is guaranteed to be there.
    file.sync_all()
        .with_context(|| format!("failed to sync temp file '{}'", tmp))?;

    drop(file);

    fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename '{}' → '{}'", tmp, path))?;

    Ok(())
}

// ─── Backup ──────────────────────────────────────────────────────────────────

/// Save copies of the original torrc and resolv.conf before we touch them.
///
/// The backups are stored with `0600` permissions so only root can read them.
/// We also verify they're non-empty after copying — an empty backup would be
/// useless for restoration and might indicate a filesystem problem.
pub fn backup_files() -> Result<()> {
    for (src, dst) in &[(TORRC_PATH, TORRC_BACKUP), (RESOLV_PATH, RESOLV_BACKUP)] {
        if !Path::new(src).exists() {
            bail!("'{}' does not exist — check Tor installation", src);
        }

        fs::copy(src, dst)
            .with_context(|| format!("failed to backup '{}' → '{}'", src, dst))?;

        // Lock down the backup file so only root can read it.
        set_permissions_600(dst)
            .with_context(|| format!("failed to set permissions on backup '{}'", dst))?;

        let len = fs::metadata(dst)
            .with_context(|| format!("cannot stat backup '{}'", dst))?
            .len();

        if len == 0 {
            bail!(
                "backup '{}' is empty after copy — aborting to protect original",
                dst
            );
        }
    }

    // On Unix, /etc/resolv.conf is often a symlink (e.g. managed by systemd-resolved).
    // atomic_write uses rename(), which replaces the symlink with a plain file.
    // Save the symlink target now so restore_files() can recreate the symlink instead
    // of leaving a plain file that may confuse the system's DNS manager.
    #[cfg(unix)]
    if let Ok(target) = fs::read_link(RESOLV_PATH) {
        let _ = atomic_write(RESOLV_LINK_BACKUP, &target.to_string_lossy());
    }

    println!("  Backups created: {} and {}", TORRC_BACKUP, RESOLV_BACKUP);
    Ok(())
}

// ─── Restore ─────────────────────────────────────────────────────────────────

/// Put the original torrc and resolv.conf back.
///
/// resolv.conf restoration is attempted in four stages (see `restore_resolv`).
/// torrc is always restored from the backup file directly.
pub fn restore_files() -> Result<()> {
    restore_resolv()?;
    println!("  DNS configuration restored");

    // torrc is always restored from our backup — no special tool needed.
    verify_backup_readable(TORRC_BACKUP)?;
    fs::copy(TORRC_BACKUP, TORRC_PATH)
        .with_context(|| format!("failed to restore '{}'", TORRC_PATH))?;
    println!("  /etc/tor/torrc restored");

    Ok(())
}

/// Restore /etc/resolv.conf using the best available method.
///
/// Tries four strategies in order, stopping at the first success:
///
/// 1. **Symlink restore** — if the original was a symlink (e.g. systemd-resolved
///    manages it), recreate the symlink. This is the most correct option on modern
///    Debian/Ubuntu/Kali systems, where resolv.conf → /run/systemd/resolve/stub-resolv.conf.
///
/// 2. **`resolvconf -u`** — on systems that ship the resolvconf tool, this is the
///    canonical way to regenerate /etc/resolv.conf from its managed sources.
///
/// 3. **Copy from backup** — plain copy of the backup we made before modifying the file.
///
/// 4. **Emergency fallback** — write a working DNS config (Quad9 + Cloudflare) so
///    the system has internet access even if all three methods above fail.
fn restore_resolv() -> Result<()> {
    // 1. Symlink restore.
    #[cfg(unix)]
    if let Ok(link_target) = fs::read_to_string(RESOLV_LINK_BACKUP) {
        let target = link_target.trim();
        if !target.is_empty() {
            let _ = fs::remove_file(RESOLV_PATH);
            std::os::unix::fs::symlink(target, RESOLV_PATH)
                .with_context(|| format!("failed to restore symlink {} -> {}", RESOLV_PATH, target))?;
            let _ = fs::remove_file(RESOLV_LINK_BACKUP);
            return Ok(());
        }
    }

    // 2. resolvconf tool.
    if resolvconf_restore().is_ok() {
        return Ok(());
    }

    // 3. Direct copy from backup.
    if verify_backup_readable(RESOLV_BACKUP).is_ok() {
        fs::copy(RESOLV_BACKUP, RESOLV_PATH)
            .with_context(|| format!("failed to restore '{}'", RESOLV_PATH))?;
        return Ok(());
    }

    // 4. Emergency fallback — write a safe, working DNS config.
    warn!("resolv.conf backup not found — writing fallback DNS (9.9.9.9 / 1.1.1.1)");
    atomic_write(
        RESOLV_PATH,
        "# restored by rustorify (original backup not found)\nnameserver 9.9.9.9\nnameserver 1.1.1.1\n",
    )
    .context("failed to write fallback DNS to /etc/resolv.conf")?;
    Ok(())
}

/// Try to restore resolv.conf using the `resolvconf` command.
/// Returns an error if the tool isn't installed or if it fails.
fn resolvconf_restore() -> Result<()> {
    let out = Command::new("resolvconf")
        .arg("-u")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .context("resolvconf not available")?;

    if !out.status.success() {
        bail!("resolvconf -u failed");
    }
    Ok(())
}

/// Make sure a backup file exists and isn't empty before we try to restore from it.
fn verify_backup_readable(path: &str) -> Result<()> {
    let meta = fs::metadata(path)
        .with_context(|| format!("backup file '{}' not found — was the proxy started cleanly?", path))?;

    if meta.len() == 0 {
        bail!("backup file '{}' is empty — manual restoration required", path);
    }
    Ok(())
}

// ─── Permissions helper ──────────────────────────────────────────────────────

/// Set a file to `0600` (owner read/write only, no access for anyone else).
/// Used for backup files and other sensitive data that only root should read.
#[cfg_attr(not(unix), allow(dead_code))]
fn set_permissions_600(path: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)
            .with_context(|| format!("failed to set permissions on '{}'", path))?;
    }
    let _ = path; // suppress unused warning on non-Unix
    Ok(())
}

// ─── Tor configuration ───────────────────────────────────────────────────────

/// Copy our bundled torrc (which sets up TransPort and DNSPort) into /etc/tor/.
///
/// This replaces whatever torrc was there before — that's why we back it up first.
pub fn install_torrc() -> Result<()> {
    let src = format!("{}/torrc", DATA_DIR);

    if !Path::new(&src).exists() {
        bail!(
            "rustorify torrc not found at '{}' — run 'sudo make install'",
            src
        );
    }

    fs::copy(&src, TORRC_PATH)
        .with_context(|| format!("failed to copy '{}' → '{}'", src, TORRC_PATH))?;

    println!("  Installed Tor transparent-proxy configuration");
    Ok(())
}

/// Point DNS at Tor's local DNS port (127.0.0.1) by rewriting /etc/resolv.conf.
///
/// This ensures name lookups go through Tor and don't leak to your ISP's DNS.
/// Only call this after Tor is confirmed ready — otherwise DNS queries will fail
/// because nothing is listening yet on the redirected port.
pub fn set_tor_dns() -> Result<()> {
    atomic_write(RESOLV_PATH, "nameserver 127.0.0.1\n")
        .context("failed to configure /etc/resolv.conf for Tor DNS")?;
    println!("  DNS redirected to Tor DNSPort");
    Ok(())
}

// ─── State file ──────────────────────────────────────────────────────────────

/// Write "active" or "inactive" to the state file.
///
/// This tiny file lets us detect if someone runs --tor twice (already active)
/// or --clearnet when nothing is running. Without it, those double-calls
/// could leave the system in a broken half-configured state.
pub fn write_state(active: bool) -> Result<()> {
    let dir = Path::new(STATE_FILE)
        .parent()
        .unwrap_or(Path::new("/var/lib/rustorify"));

    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("cannot create state directory '{}'", dir.display()))?;
    }

    atomic_write(STATE_FILE, if active { "active\n" } else { "inactive\n" })
}

/// Returns true if the state file says the proxy is currently active.
/// Returns false if the file is missing or unreadable (safe default).
pub fn is_proxy_active() -> bool {
    fs::read_to_string(STATE_FILE)
        .map(|s| s.trim() == "active")
        .unwrap_or(false)
}
