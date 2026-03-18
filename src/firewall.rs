//! Sets up and tears down the iptables rules that route traffic through Tor.
//!
//! When activated, we redirect all outgoing TCP to Tor's TransPort and all
//! DNS to Tor's DNSPort. We also set default DROP policies on the filter
//! table so nothing bypasses Tor accidentally.
//!
//! When deactivated, we delete those rules and restore the default
//! ACCEPT policies so normal internet access works again.
//!
//! IPv6 is handled separately by blocking it entirely (both ip6tables rules
//! and sysctl), since Tor doesn't support IPv6 transparent proxying.

use std::process::Command;
use anyhow::{bail, Context, Result};

use crate::config::{DNS_PORT, NON_TOR_NETS, SYSCTL_IPV6_KEYS, TOR_USER, TRANS_PORT, VIRTUAL_ADDR};
use crate::{info, ok, warn};

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Run an iptables command with the given arguments.
/// Each argument is a separate string — never passed through a shell —
/// so there's no risk of special characters causing unintended behavior.
fn ipt(args: &[&str]) -> Result<()> {
    tracing::debug!("iptables {}", args.join(" "));

    let status = Command::new("iptables")
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()
        .context("failed to execute iptables")?;

    if !status.success() {
        bail!("iptables {:?} exited with {}", args, status);
    }
    Ok(())
}

/// Run an ip6tables command. Errors are tolerated — if ip6tables isn't
/// installed, we just skip it (it's best-effort).
fn ipt6(args: &[&str]) -> Result<()> {
    tracing::debug!("ip6tables {}", args.join(" "));

    let status = Command::new("ip6tables")
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status()
        .context("failed to execute ip6tables")?;

    if !status.success() {
        bail!("ip6tables {:?} exited with {}", args, status);
    }
    Ok(())
}

/// Delete an iptables rule, silently ignoring errors.
/// Used during cleanup where a rule might not exist yet.
fn ipt_del(args: &[&str]) {
    let mut full = vec!["-D"];
    full.extend_from_slice(args);
    let _ = Command::new("iptables")
        .args(&full)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .status();
}

fn filter_rule_specs(trans: &str, dns: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        (
            "filter INPUT ESTABLISHED",
            vec![
                "-A".into(),
                "INPUT".into(),
                "-m".into(),
                "state".into(),
                "--state".into(),
                "ESTABLISHED,RELATED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ),
        (
            "filter OUTPUT ESTABLISHED",
            vec![
                "-A".into(),
                "OUTPUT".into(),
                "-m".into(),
                "state".into(),
                "--state".into(),
                "ESTABLISHED,RELATED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ),
        (
            "filter INPUT lo",
            vec!["-A".into(), "INPUT".into(), "-i".into(), "lo".into(), "-j".into(), "ACCEPT".into()],
        ),
        (
            "filter OUTPUT lo",
            vec!["-A".into(), "OUTPUT".into(), "-o".into(), "lo".into(), "-j".into(), "ACCEPT".into()],
        ),
        (
            "filter OUTPUT Tor user",
            vec![
                "-A".into(),
                "OUTPUT".into(),
                "-m".into(),
                "owner".into(),
                "--uid-owner".into(),
                TOR_USER.into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ),
        (
            "filter INPUT TransPort",
            vec![
                "-A".into(),
                "INPUT".into(),
                "-i".into(),
                "lo".into(),
                "-p".into(),
                "tcp".into(),
                "--dport".into(),
                trans.into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ),
        (
            "filter INPUT DNSPort",
            vec![
                "-A".into(),
                "INPUT".into(),
                "-i".into(),
                "lo".into(),
                "-p".into(),
                "udp".into(),
                "--dport".into(),
                dns.into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ),
    ]
}

// ─── IPv6 blocking (ip6tables) ───────────────────────────────────────────────

/// Drop all IPv6 traffic by setting the default policy to DROP on every chain.
fn block_ipv6_tables() {
    for chain in &["INPUT", "OUTPUT", "FORWARD"] {
        let _ = ipt6(&["-P", chain, "DROP"]);
    }
}

/// Restore the default IPv6 policy to ACCEPT on every chain.
fn unblock_ipv6_tables() {
    for chain in &["INPUT", "OUTPUT", "FORWARD"] {
        let _ = ipt6(&["-P", chain, "ACCEPT"]);
    }
}

// ─── IPv6 blocking (sysctl) ──────────────────────────────────────────────────

/// Disable the IPv6 network stack entirely via sysctl.
///
/// ip6tables only filters packets — the IPv6 stack is still active and
/// could potentially be exploited. Disabling it via sysctl is more thorough:
/// the kernel won't assign or respond to IPv6 addresses at all.
pub fn sysctl_disable_ipv6() {
    for key in SYSCTL_IPV6_KEYS {
        let val = format!("{}=1", key);
        let result = Command::new("sysctl")
            .args(&["-w", &val])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output();

        match result {
            Ok(out) if out.status.success() => tracing::debug!("sysctl {}", val),
            Ok(out) => tracing::warn!(
                "sysctl {} failed: {}",
                val,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => tracing::warn!("sysctl not available: {}", e),
        }
    }
}

/// Re-enable IPv6 by setting the sysctl keys back to 0 (enabled).
pub fn sysctl_restore_ipv6() {
    for key in SYSCTL_IPV6_KEYS {
        let val = format!("{}=0", key);
        let _ = Command::new("sysctl")
            .args(&["-w", &val])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output();
    }
}

// ─── Public IPv6 API ─────────────────────────────────────────────────────────

/// Block all IPv6 traffic using both ip6tables and sysctl.
/// The combination ensures no IPv6 traffic can sneak through even if
/// one of the two mechanisms has gaps.
pub fn block_ipv6() -> Result<()> {
    block_ipv6_tables();
    sysctl_disable_ipv6();
    ok!("IPv6 blocked (ip6tables + sysctl)");
    Ok(())
}

/// Restore IPv6 access by undoing both the ip6tables and sysctl changes.
pub fn unblock_ipv6() {
    unblock_ipv6_tables();
    sysctl_restore_ipv6();
    ok!("IPv6 restored");
}

// ─── Activate ────────────────────────────────────────────────────────────────

/// Install all the iptables rules needed to redirect traffic through Tor.
///
/// The rules work in two layers:
///
/// **nat table** — redirects traffic before routing decisions:
/// - .onion addresses → Tor's TransPort (so they can be resolved)
/// - Tor's own traffic → bypass (prevents Tor-from-routing-through-itself)
/// - Loopback and local networks → bypass (you still need your LAN)
/// - Everything else TCP → TransPort (the main redirect)
/// - DNS (UDP port 53) → Tor's DNS port (prevents DNS leaks)
///
/// **filter table** — strict allowlist, blocks everything else:
/// - Default policy: DROP
/// - Allow: established connections, loopback, Tor daemon outbound,
///   TransPort and DNSPort inbound from localhost
pub fn activate() -> Result<()> {
    info!("Applying iptables transparent-proxy rules…");

    let trans = TRANS_PORT.to_string();
    let dns   = DNS_PORT.to_string();

    // ── nat table ────────────────────────────────────────────────────────────

    // .onion addresses use a virtual IP range — redirect them so Tor can resolve them.
    ipt(&["-t", "nat", "-A", "OUTPUT",
          "-d", VIRTUAL_ADDR, "-p", "tcp", "--syn",
          "-j", "REDIRECT", "--to-ports", &trans])
        .context("nat OUTPUT .onion redirect")?;

    // Tor's own process must bypass the redirect — otherwise it would try
    // to send traffic through itself and nothing would work.
    ipt(&["-t", "nat", "-A", "OUTPUT",
          "-m", "owner", "--uid-owner", TOR_USER,
          "-j", "RETURN"])
        .context("nat OUTPUT Tor user bypass")?;

    // Loopback traffic (127.0.0.1) should never go through Tor.
    ipt(&["-t", "nat", "-A", "OUTPUT",
          "-o", "lo", "-j", "RETURN"])
        .context("nat OUTPUT loopback bypass")?;

    // Local network ranges (your LAN, etc.) bypass Tor too — you still
    // need to reach your router, printers, local services, etc.
    for net in NON_TOR_NETS {
        ipt(&["-t", "nat", "-A", "OUTPUT",
              "-d", net, "-j", "RETURN"])
            .with_context(|| format!("nat OUTPUT bypass {}", net))?;
    }

    // All remaining TCP traffic goes through Tor's transparent proxy port.
    ipt(&["-t", "nat", "-A", "OUTPUT",
          "-p", "tcp", "--syn",
          "-j", "REDIRECT", "--to-ports", &trans])
        .context("nat OUTPUT TCP redirect")?;

    // Redirect DNS queries to Tor's DNS port so hostname lookups go through Tor.
    ipt(&["-t", "nat", "-A", "OUTPUT",
          "-p", "udp", "--dport", "53",
          "-j", "REDIRECT", "--to-ports", &dns])
        .context("nat OUTPUT DNS redirect")?;

    // ── filter table ─────────────────────────────────────────────────────────

    // Default to blocking everything — only explicitly allowed traffic gets through.
    ipt(&["-P", "INPUT",   "DROP"]).context("filter INPUT DROP")?;
    ipt(&["-P", "FORWARD", "DROP"]).context("filter FORWARD DROP")?;
    ipt(&["-P", "OUTPUT",  "DROP"]).context("filter OUTPUT DROP")?;

    for (label, rule) in filter_rule_specs(&trans, &dns) {
        let refs: Vec<&str> = rule.iter().map(String::as_str).collect();
        ipt(&refs).with_context(|| label.to_string())?;
    }

    ok!("iptables rules applied");
    Ok(())
}

/// Activate with automatic rollback.
///
/// If any iptables command fails partway through, we clean up whatever
/// rules were already added before returning the error. This avoids leaving
/// the system in a half-configured state where some traffic goes through
/// Tor and some doesn't.
pub fn activate_with_rollback() -> Result<()> {
    activate().map_err(|e| {
        warn!("iptables setup failed — rolling back partial rules…");
        deactivate();
        unblock_ipv6();
        e
    })
}

// ─── Deactivate ──────────────────────────────────────────────────────────────

/// Remove all the iptables rules we added and restore open default policies.
///
/// We delete rules individually (rather than flushing all rules) so we
/// only remove what we added — leaving any other rules the user may have
/// in place untouched, then restore ACCEPT policies.
pub fn deactivate() {
    info!("Flushing iptables rules…");

    let trans = TRANS_PORT.to_string();
    let dns   = DNS_PORT.to_string();

    // Remove nat OUTPUT rules in the same order they were added.
    ipt_del(&["OUTPUT", "-t", "nat",
               "-d", VIRTUAL_ADDR, "-p", "tcp", "--syn",
               "-j", "REDIRECT", "--to-ports", &trans]);

    ipt_del(&["OUTPUT", "-t", "nat",
               "-m", "owner", "--uid-owner", TOR_USER,
               "-j", "RETURN"]);

    ipt_del(&["OUTPUT", "-t", "nat", "-o", "lo", "-j", "RETURN"]);

    for net in NON_TOR_NETS {
        ipt_del(&["OUTPUT", "-t", "nat", "-d", net, "-j", "RETURN"]);
    }

    ipt_del(&["OUTPUT", "-t", "nat",
               "-p", "tcp", "--syn",
               "-j", "REDIRECT", "--to-ports", &trans]);

    ipt_del(&["OUTPUT", "-t", "nat",
               "-p", "udp", "--dport", "53",
               "-j", "REDIRECT", "--to-ports", &dns]);

    for (_, rule) in filter_rule_specs(&trans, &dns) {
        let delete_rule: Vec<&str> = rule[1..].iter().map(String::as_str).collect();
        ipt_del(&delete_rule);
    }

    // Restore the filter table default policies back to ACCEPT.
    for policy in &[
        &["-P", "INPUT",   "ACCEPT"][..],
        &["-P", "FORWARD", "ACCEPT"],
        &["-P", "OUTPUT",  "ACCEPT"],
    ] {
        let _ = Command::new("iptables")
            .args(*policy)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .status();
    }

    ok!("iptables rules removed, policies restored to ACCEPT");
}

#[cfg(test)]
mod tests {
    use super::filter_rule_specs;

    #[test]
    fn filter_rules_cover_only_rustorify_rules() {
        let rules = filter_rule_specs("9040", "5353");

        assert_eq!(rules.len(), 7);
        assert!(rules.iter().any(|(_, rule)| rule == &vec![
            "-A", "OUTPUT", "-m", "owner", "--uid-owner", "debian-tor", "-j", "ACCEPT",
        ].into_iter().map(str::to_string).collect::<Vec<_>>()));
        assert!(rules.iter().any(|(_, rule)| rule == &vec![
            "-A", "INPUT", "-i", "lo", "-p", "tcp", "--dport", "9040", "-j", "ACCEPT",
        ].into_iter().map(str::to_string).collect::<Vec<_>>()));
        assert!(rules.iter().any(|(_, rule)| rule == &vec![
            "-A", "INPUT", "-i", "lo", "-p", "udp", "--dport", "5353", "-j", "ACCEPT",
        ].into_iter().map(str::to_string).collect::<Vec<_>>()));
    }
}
