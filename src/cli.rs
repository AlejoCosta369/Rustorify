//! Defines the command-line interface.
//!
//! We use `clap` with its derive macro, so the struct below becomes the
//! CLI automatically — flags, help text, conflict rules, and all.

use clap::Parser;

/// The main CLI struct. Each field is a flag the user can pass on the command line.
///
/// Only one "action" flag (--tor, --clearnet, --restart, --status, --ipinfo)
/// can be used at a time. Clap enforces this via `conflicts_with_all`.
///
/// Security note: routing traffic through Tor improves privacy but does not
/// guarantee anonymity. For stronger isolation, consider Whonix or Tails.
#[derive(Parser, Debug)]
#[command(
    name = "rustorify",
    version = "1.0.0",
    about = "Transparent proxy through Tor — memory-safe Rust rewrite",
    long_about = None
)]
pub struct Cli {
    /// Redirect all TCP traffic through Tor and block IPv6.
    /// Backs up your current torrc and resolv.conf before making any changes.
    #[arg(short = 't', long, conflicts_with_all = ["clearnet", "restart", "status", "ipinfo"])]
    pub tor: bool,

    /// Undo everything --tor did: remove firewall rules, restore DNS,
    /// stop Tor, and go back to normal internet access.
    #[arg(short = 'c', long, conflicts_with_all = ["tor", "restart", "status", "ipinfo"])]
    pub clearnet: bool,

    /// Restart the Tor service to get a fresh circuit and a different exit node.
    /// Useful if a site is blocking the current exit IP.
    #[arg(short = 'r', long, conflicts_with_all = ["tor", "clearnet", "status", "ipinfo"])]
    pub restart: bool,

    /// Show whether the proxy is currently active, whether Tor is running,
    /// your current public IP, and whether the kill switch is installed.
    #[arg(short = 's', long, conflicts_with_all = ["tor", "clearnet", "restart", "ipinfo"])]
    pub status: bool,

    /// Just show your current public IP address (goes through Tor if active).
    #[arg(short = 'i', long, conflicts_with_all = ["tor", "clearnet", "restart", "status"])]
    pub ipinfo: bool,

    /// Install a systemd drop-in so that if Tor crashes or stops unexpectedly,
    /// the system automatically runs --clearnet instead of leaking traffic
    /// through your real IP. Only does something when used with --tor.
    #[arg(short = 'k', long)]
    pub kill_switch: bool,

    /// How much logging output to show. Options: off, error, warn, info, debug, trace.
    /// You can also set the RUST_LOG environment variable to override this.
    #[arg(long, default_value = "warn", env = "RUST_LOG")]
    pub log_level: String,
}
