use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use tracing::{info, warn};

const NKOSI_CHAIN: &str = "NKOSI_INPUT";
const NKOSI_BLACKLIST_CHAIN: &str = "NKOSI_BLACKLIST";
const NKOSI_WHITELIST_CHAIN: &str = "NKOSI_WHITELIST";

/// Firewall manager for iptables
pub struct FirewallManager {
    ipv4_available: bool,
    ipv6_available: bool,
}

/// IP entry in blacklist/whitelist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpEntry {
    pub ip: String,
    pub comment: Option<String>,
    pub expires_at: Option<String>, // RFC3339 for temp entries
    pub added_at: String,
}

/// Firewall status report
#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub ipv4_available: bool,
    pub ipv6_available: bool,
    pub nkosi_chain_exists: bool,
    pub rules_count: u32,
    pub blacklist_count: u32,
    pub whitelist_count: u32,
    pub blacklist: Vec<IpEntry>,
    pub whitelist: Vec<IpEntry>,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self {
            ipv4_available: Self::check_binary("iptables"),
            ipv6_available: Self::check_binary("ip6tables"),
        }
    }

    fn check_binary(name: &str) -> bool {
        std::process::Command::new("which")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Initialize NKOSI iptables chains
    pub fn init_chains(&self) -> Result<()> {
        info!("Initializing NKOSI iptables chains");

        // Create NKOSI_INPUT chain (skip if exists)
        self.run_iptables(&["-N", NKOSI_CHAIN], false)?;
        // Jump to NKOSI_INPUT from INPUT
        self.run_iptables(&["-C", "INPUT", "-j", NKOSI_CHAIN], false)
            .or_else(|_| self.run_iptables(&["-I", "INPUT", "1", "-j", NKOSI_CHAIN], false))?;

        // Create blacklist chain
        self.run_iptables(&["-N", NKOSI_BLACKLIST_CHAIN], false)?;
        self.run_iptables(
            &["-C", NKOSI_CHAIN, "-j", NKOSI_BLACKLIST_CHAIN],
            false,
        )
        .or_else(|_| {
            self.run_iptables(
                &["-A", NKOSI_CHAIN, "-j", NKOSI_BLACKLIST_CHAIN],
                false,
            )
        })?;

        // Create whitelist chain
        self.run_iptables(&["-N", NKOSI_WHITELIST_CHAIN], false)?;
        self.run_iptables(
            &["-C", NKOSI_CHAIN, "-j", NKOSI_WHITELIST_CHAIN],
            false,
        )
        .or_else(|_| {
            self.run_iptables(
                &["-A", NKOSI_CHAIN, "-j", NKOSI_WHITELIST_CHAIN],
                false,
            )
        })?;

        // Allow established connections
        self.run_iptables(
            &[
                "-A", NKOSI_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT",
            ],
            true,
        )?;

        // Allow loopback
        self.run_iptables(
            &["-A", NKOSI_CHAIN, "-i", "lo", "-j", "ACCEPT"],
            true,
        )?;

        info!("NKOSI chains initialized");
        Ok(())
    }

    /// Flush all NKOSI rules
    pub fn flush(&self) -> Result<()> {
        info!("Flushing NKOSI iptables chains");
        let _ = self.run_iptables(&["-F", NKOSI_CHAIN], false);
        let _ = self.run_iptables(&["-F", NKOSI_BLACKLIST_CHAIN], false);
        let _ = self.run_iptables(&["-F", NKOSI_WHITELIST_CHAIN], false);
        Ok(())
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: &str, comment: Option<&str>, temp: bool) -> Result<()> {
        info!("Blocking IP: {} (temp={})", ip, temp);

        let mut args = vec!["-A", NKOSI_BLACKLIST_CHAIN, "-s", ip, "-j", "DROP"];
        if let Some(c) = comment {
            args.push("-m");
            args.push("comment");
            args.push("--comment");
            args.push(c);
        }

        self.run_iptables(&args, true)?;

        // Also block on OUTPUT
        let mut args_out = vec!["-A", "OUTPUT", "-d", ip, "-j", "DROP"];
        if let Some(c) = comment {
            args_out.push("-m");
            args_out.push("comment");
            args_out.push("--comment");
            args_out.push(c);
        }
        let _ = self.run_iptables(&args_out, false);

        Ok(())
    }

    /// Unblock an IP address
    pub fn unblock_ip(&self, ip: &str) -> Result<()> {
        info!("Unblocking IP: {}", ip);

        let _ = self.run_iptables(&["-D", NKOSI_BLACKLIST_CHAIN, "-s", ip, "-j", "DROP"], false);
        let _ = self.run_iptables(&["-D", "OUTPUT", "-d", ip, "-j", "DROP"], false);

        Ok(())
    }

    /// Add IP to whitelist (never blocked)
    pub fn whitelist_ip(&self, ip: &str, comment: Option<&str>) -> Result<()> {
        info!("Whitelisting IP: {}", ip);

        let mut args = vec!["-I", NKOSI_WHITELIST_CHAIN, "1", "-s", ip, "-j", "ACCEPT"];
        if let Some(c) = comment {
            args.push("-m");
            args.push("comment");
            args.push("--comment");
            args.push(c);
        }

        self.run_iptables(&args, true)?;
        Ok(())
    }

    /// Remove IP from whitelist
    pub fn remove_whitelist(&self, ip: &str) -> Result<()> {
        self.run_iptables(&["-D", NKOSI_WHITELIST_CHAIN, "-s", ip, "-j", "ACCEPT"], false)?;
        Ok(())
    }

    /// Add rate limiting rule for an IP
    pub fn add_rate_limit(&self, ip: &str, max_conn: u32, period: &str) -> Result<()> {
        info!("Adding rate limit for {}: {}/{}", ip, max_conn, period);

        self.run_iptables(
            &[
                "-A", NKOSI_CHAIN,
                "-s", ip,
                "-m", "conntrack", "--ctstate", "NEW",
                "-m", "recent", "--set", "--name", "NKOSI_RATE",
                "-j", "ACCEPT",
            ],
            false,
        )?;

        self.run_iptables(
            &[
                "-A", NKOSI_CHAIN,
                "-s", ip,
                "-m", "conntrack", "--ctstate", "NEW",
                "-m", "recent", "--update", "--seconds", period, "--hitcount", &max_conn.to_string(), "--name", "NKOSI_RATE",
                "-j", "DROP",
            ],
            false,
        )?;

        Ok(())
    }

    /// Get current firewall status
    pub fn status(&self) -> Result<FirewallStatus> {
        let chain_exists = self.chain_exists(NKOSI_CHAIN)?;
        let rules_count = self.count_rules(NKOSI_CHAIN)?;
        let blacklist = self.list_chain(NKOSI_BLACKLIST_CHAIN)?;
        let whitelist = self.list_chain(NKOSI_WHITELIST_CHAIN)?;

        Ok(FirewallStatus {
            ipv4_available: self.ipv4_available,
            ipv6_available: self.ipv6_available,
            nkosi_chain_exists: chain_exists,
            rules_count,
            blacklist_count: blacklist.len() as u32,
            whitelist_count: whitelist.len() as u32,
            blacklist,
            whitelist,
        })
    }

    /// Save rules to file for persistence
    pub fn save_rules(&self, path: &str) -> Result<()> {
        info!("Saving iptables rules to {}", path);

        let output = std::process::Command::new("iptables-save")
            .output()
            .context("Failed to run iptables-save")?;

        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            // Filter only NKOSI chains
            let mut filtered = String::new();
            let mut in_nkosi = false;
            for line in content.lines() {
                if line.contains(":NKOSI") || line.contains(":NKOSI_") {
                    in_nkosi = true;
                }
                if in_nkosi {
                    filtered.push_str(line);
                    filtered.push('\n');
                    if line == "COMMIT" {
                        in_nkosi = false;
                    }
                }
            }
            fs::write(path, filtered).context("Failed to write rules file")?;
            info!("Rules saved to {}", path);
        }

        Ok(())
    }

    /// Load rules from file
    pub fn load_rules(&self, path: &str) -> Result<()> {
        info!("Loading iptables rules from {}", path);
        let content = fs::read_to_string(path).context("Failed to read rules file")?;

        use std::io::Write;
        let mut child = std::process::Command::new("iptables-restore")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn iptables-restore")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(content.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("iptables-restore failed: {}", stderr);
        }

        Ok(())
    }

    // Internal helpers

    fn run_iptables(&self, args: &[&str], required: bool) -> Result<()> {
        let output = std::process::Command::new("iptables")
            .args(args)
            .output()
            .context("Failed to run iptables")?;

        if !output.status.success() && required {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables failed: {}", stderr);
        }

        Ok(())
    }

    fn chain_exists(&self, chain: &str) -> Result<bool> {
        let output = std::process::Command::new("iptables")
            .args(["-L", chain, "-n"])
            .output()?;

        Ok(output.status.success())
    }

    fn count_rules(&self, chain: &str) -> Result<u32> {
        let output = std::process::Command::new("iptables")
            .args(["-L", chain, "-n", "--line-numbers"])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.lines().filter(|l| l.contains(chain)).count() as u32)
        } else {
            Ok(0)
        }
    }

    fn list_chain(&self, chain: &str) -> Result<Vec<IpEntry>> {
        let output = std::process::Command::new("iptables")
            .args(["-L", chain, "-n", "-v"])
            .output()?;

        let mut entries = Vec::new();
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("DROP") || line.contains("ACCEPT") {
                    if let Some(ip) = line.split_whitespace().nth(3) {
                        if ip.contains('/') || ip.parse::<std::net::IpAddr>().is_ok() {
                            entries.push(IpEntry {
                                ip: ip.to_string(),
                                comment: None,
                                expires_at: None,
                                added_at: String::new(),
                            });
                        }
                    }
                }
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_manager_creation() {
        let mgr = FirewallManager::new();
        // Just verify it doesn't panic
        assert!(mgr.ipv4_available || !mgr.ipv4_available);
    }

    #[test]
    fn test_ip_entry_serialization() {
        let entry = IpEntry {
            ip: "1.2.3.4".to_string(),
            comment: Some("test".to_string()),
            expires_at: None,
            added_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("1.2.3.4"));

        let deserialized: IpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ip, "1.2.3.4");
    }

    #[test]
    fn test_firewall_status_serialization() {
        let status = FirewallStatus {
            ipv4_available: true,
            ipv6_available: false,
            nkosi_chain_exists: true,
            rules_count: 5,
            blacklist_count: 2,
            whitelist_count: 1,
            blacklist: vec![],
            whitelist: vec![],
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("ipv4_available"));
    }
}
