//! Colored terminal output macros.
//!
//! Four simple macros for consistent, colored status messages:
//!
//! - `ok!`   → green  `[+]`  — something succeeded
//! - `info!` → cyan   `[*]`  — general progress update
//! - `warn!` → yellow `[!]`  — something worth noting, but not fatal
//! - `err!`  → red    `[!]`  — an error (prints to stderr)
//! - `step!` → bold         — section header
//!
//! Usage is the same as `println!`:
//! ```
//! ok!("Connected to Tor — exit IP: {}", ip);
//! warn!("DNS check failed: {}", reason);
//! ```
//!
//! Each macro imports `Colorize` inside its own block so callers don't
//! need to import it themselves.

use colored::Colorize;

#[macro_export]
macro_rules! ok {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        println!("{} {}", "[+]".green().bold(), format!($($arg)*))
    }};
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        println!("{} {}", "[*]".cyan().bold(), format!($($arg)*))
    }};
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        println!("{} {}", "[!]".yellow().bold(), format!($($arg)*))
    }};
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        eprintln!("{} {}", "[!]".red().bold(), format!($($arg)*))
    }};
}

#[macro_export]
macro_rules! step {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        println!("\n{}", format!($($arg)*).bold())
    }};
}

/// Print a horizontal divider line to visually separate sections of output.
pub fn separator() {
    println!("{}", "─".repeat(60).dimmed());
}
