//! Prevents two instances of the program from running at the same time.
//!
//! We write our PID to a lock file when we start, and delete it when we exit.
//! If another instance finds that file with a live PID inside, it stops
//! immediately with an error. Stale locks (from a crashed previous run)
//! are detected and cleaned up automatically.

use std::fs;
use std::path::Path;
use anyhow::{bail, Context, Result};

use crate::config::LOCK_FILE;

/// Holds the lock for as long as it's alive.
/// When this value is dropped (end of scope or program exit), the lock
/// file is automatically deleted. This is the RAII pattern in Rust.
pub struct Lock;

impl Lock {
    /// Try to acquire the lock. Returns an error if another live instance
    /// already holds it.
    pub fn acquire() -> Result<Self> {
        if Path::new(LOCK_FILE).exists() {
            let pid_str = fs::read_to_string(LOCK_FILE).unwrap_or_default();
            let pid: u32 = pid_str.trim().parse().unwrap_or(0);

            if pid > 0 && process_alive(pid) {
                bail!(
                    "another instance of rustorify is running (PID {})\n  \
                     If this is wrong, delete {} and retry",
                    pid,
                    LOCK_FILE
                );
            }

            // The process is gone but left the file behind — clean it up.
            tracing::warn!("removing stale lock file (PID {} no longer exists)", pid);
            let _ = fs::remove_file(LOCK_FILE);
        }

        // Make sure the directory exists (e.g. /var/run may not have our subdir yet).
        if let Some(parent) = Path::new(LOCK_FILE).parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create lock directory '{}'", parent.display()))?;
        }

        // Write our own PID so the next instance can detect us.
        fs::write(LOCK_FILE, format!("{}\n", std::process::id()))
            .with_context(|| format!("cannot write lock file '{}'", LOCK_FILE))?;

        tracing::debug!("lock acquired ({})", LOCK_FILE);
        Ok(Lock)
    }
}

impl Drop for Lock {
    /// Clean up the lock file when we're done, no matter how the program exits.
    fn drop(&mut self) {
        let _ = fs::remove_file(LOCK_FILE);
        tracing::debug!("lock released");
    }
}

/// Check whether a process with the given PID is still running.
/// We do this by checking if its `/proc/<pid>` directory exists — a simple
/// and reliable trick that doesn't require any extra tools.
fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}
