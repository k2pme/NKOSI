use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

/// SSH brute-force scanner configuration
#[derive(Debug, Clone)]
pub struct SshBruteforceConfig {
    pub log_path: String,
    pub threshold: u32,        // Number of failed attempts to trigger alert
    pub block_threshold: u32,  // Number of failed attempts to trigger block
    pub time_window_secs: u64, // Time window for counting attempts
}

impl Default for SshBruteforceConfig {
    fn default() -> Self {
        Self {
            log_path: "/var/log/auth.log".to_string(),
            threshold: 5,
            block_threshold: 10,
            time_window_secs: 300, // 5 minutes
        }
    }
}

/// A parsed SSH login attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAttempt {
    pub timestamp: String,
    pub ip: String,
    pub user: String,
    pub success: bool,
    pub raw_line: String,
}

/// Brute-force attack detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteforceAttacker {
    pub ip: String,
    pub attempts: Vec<SshAttempt>,
    pub total_attempts: u32,
    pub failed_attempts: u32,
    pub usernames_targeted: Vec<String>,
    pub first_attempt: String,
    pub last_attempt: String,
    pub blocked: bool,
}

/// SSH brute-force scan report
#[derive(Debug, Serialize, Deserialize)]
pub struct SshReport {
    pub timestamp: String,
    pub log_path: String,
    pub log_lines_parsed: u64,
    pub total_failed: u64,
    pub total_success: u64,
    pub attackers: Vec<BruteforceAttacker>,
    pub score: u32,
    pub summary: String,
}

/// SSH brute-force scanner
pub struct SshBruteforceScanner {
    config: SshBruteforceConfig,
}

impl SshBruteforceScanner {
    pub fn new(config: SshBruteforceConfig) -> Self {
        Self { config }
    }

    /// Scan auth.log for SSH brute-force attempts
    pub fn scan(&self) -> Result<SshReport> {
        info!("Starting SSH brute-force scan on {}", self.config.log_path);

        let content = match std::fs::read_to_string(&self.config.log_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot read auth.log: {}", e);
                return Ok(SshReport {
                    timestamp: Utc::now().to_rfc3339(),
                    log_path: self.config.log_path.clone(),
                    log_lines_parsed: 0,
                    total_failed: 0,
                    total_success: 0,
                    attackers: Vec::new(),
                    score: 100,
                    summary: format!("Cannot read auth.log: {}", e),
                });
            }
        };

        let attempts = self.parse_auth_log(&content)?;
        let attackers = self.detect_attackers(&attempts);
        let total_failed = attempts.iter().filter(|a| !a.success).count() as u64;
        let total_success = attempts.iter().filter(|a| a.success).count() as u64;
        let score = self.calculate_score(&attackers, total_failed);
        let summary = self.generate_summary(&attackers, total_failed, total_success, score);

        info!(
            "SSH brute-force scan completed: {} attackers, score: {}",
            attackers.len(),
            score
        );

        Ok(SshReport {
            timestamp: Utc::now().to_rfc3339(),
            log_path: self.config.log_path.clone(),
            log_lines_parsed: content.lines().count() as u64,
            total_failed,
            total_success,
            attackers,
            score,
            summary,
        })
    }

    /// Parse auth.log and extract SSH attempts
    fn parse_auth_log(&self, content: &str) -> Result<Vec<SshAttempt>> {
        let re_failed = Regex::new(
            r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"
        )?;
        let re_accepted = Regex::new(
            r"Accepted password for (\S+) from (\S+) port \d+"
        )?;
        let re_timestamp = Regex::new(
            r"^(\w+\s+\d+\s+\d+:\d+:\d+)"
        )?;

        let mut attempts = Vec::new();
        let mut current_timestamp = String::new();

        for line in content.lines() {
            // Extract timestamp
            if let Some(ts) = re_timestamp.captures(line) {
                current_timestamp = ts[1].to_string();
            }

            // Failed password attempt
            if let Some(caps) = re_failed.captures(line) {
                let user = caps[1].to_string();
                let ip = caps[2].to_string();
                attempts.push(SshAttempt {
                    timestamp: current_timestamp.clone(),
                    ip,
                    user,
                    success: false,
                    raw_line: line.to_string(),
                });
            }
            // Accepted password attempt
            else if let Some(caps) = re_accepted.captures(line) {
                let user = caps[1].to_string();
                let ip = caps[2].to_string();
                attempts.push(SshAttempt {
                    timestamp: current_timestamp.clone(),
                    ip,
                    user,
                    success: true,
                    raw_line: line.to_string(),
                });
            }
        }

        Ok(attempts)
    }

    /// Group attempts by IP and detect brute-force patterns
    fn detect_attackers(&self, attempts: &[SshAttempt]) -> Vec<BruteforceAttacker> {
        let mut by_ip: HashMap<String, Vec<&SshAttempt>> = HashMap::new();

        for attempt in attempts {
            by_ip.entry(attempt.ip.clone()).or_default().push(attempt);
        }

        let mut attackers = Vec::new();

        for (ip, mut ip_attempts) in by_ip {
            // Sort by timestamp
            ip_attempts.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

            let failed_count = ip_attempts.iter().filter(|a| !a.success).count() as u32;
            let total = ip_attempts.len() as u32;

            if failed_count >= self.config.threshold {
                let usernames: Vec<String> = ip_attempts
                    .iter()
                    .filter(|a| !a.success)
                    .map(|a| a.user.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                attackers.push(BruteforceAttacker {
                    ip: ip.clone(),
                    attempts: ip_attempts.iter().map(|a| (*a).clone()).collect(),
                    total_attempts: total,
                    failed_attempts: failed_count,
                    usernames_targeted: usernames,
                    first_attempt: ip_attempts.first()
                        .map(|a| a.timestamp.clone())
                        .unwrap_or_default(),
                    last_attempt: ip_attempts.last()
                        .map(|a| a.timestamp.clone())
                        .unwrap_or_default(),
                    blocked: false,
                });
            }
        }

        // Sort by failed attempts descending
        attackers.sort_by(|a, b| b.failed_attempts.cmp(&a.failed_attempts));
        attackers
    }

    /// Calculate risk score (0-100, lower is worse)
    fn calculate_score(&self, attackers: &[BruteforceAttacker], total_failed: u64) -> u32 {
        if attackers.is_empty() && total_failed == 0 {
            return 100;
        }

        let attacker_penalty = (attackers.len() as u32).min(50);
        let failed_penalty = ((total_failed as f64 / 100.0) * 30.0) as u32;
        let max_penalty = attacker_penalty + failed_penalty;

        100u32.saturating_sub(max_penalty)
    }

    /// Generate summary string
    fn generate_summary(
        &self,
        attackers: &[BruteforceAttacker],
        total_failed: u64,
        total_success: u64,
        score: u32,
    ) -> String {
        if attackers.is_empty() {
            format!(
                "No brute-force detected. {} failed attempts, {} successful.",
                total_failed, total_success
            )
        } else {
            format!(
                "{} attacker(s) detected: {} total failed attempts. Risk score: {}/100",
                attackers.len(),
                total_failed,
                score
            )
        }
    }

    /// Block an IP address using iptables
    pub fn block_ip(&self, ip: &str) -> Result<bool> {
        info!("Attempting to block IP: {}", ip);

        let output = std::process::Command::new("iptables")
            .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output()?;

        if output.status.success() {
            info!("Successfully blocked IP: {}", ip);
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to block IP {}: {}", ip, stderr);
            Ok(false)
        }
    }

    /// Check if an IP is already blocked in iptables
    pub fn is_ip_blocked(&self, ip: &str) -> Result<bool> {
        let output = std::process::Command::new("iptables")
            .args(["-L", "INPUT", "-n"])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.contains(ip))
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_auth_log() {
        let config = SshBruteforceConfig::default();
        let scanner = SshBruteforceScanner::new(config);

        let log_content = r#"Aug 20 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Aug 20 10:00:02 server sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
Aug 20 10:00:03 server sshd[1236]: Accepted password for user1 from 192.168.1.101 port 22 ssh2
Aug 20 10:00:04 server sshd[1237]: Failed password for root from 10.0.0.50 port 22 ssh2
"#;

        let attempts = scanner.parse_auth_log(log_content).unwrap();

        assert_eq!(attempts.len(), 4);
        assert_eq!(attempts[0].ip, "192.168.1.100");
        assert!(!attempts[0].success);
        assert_eq!(attempts[1].ip, "192.168.1.100");
        assert!(!attempts[1].success);
        assert_eq!(attempts[2].ip, "192.168.1.101");
        assert!(attempts[2].success);
        assert_eq!(attempts[3].ip, "10.0.0.50");
        assert!(!attempts[3].success);
    }

    #[test]
    fn test_detect_attackers() {
        let config = SshBruteforceConfig {
            threshold: 3,
            ..Default::default()
        };
        let scanner = SshBruteforceScanner::new(config);

        let attempts = vec![
            SshAttempt {
                timestamp: "Aug 20 10:00:01".into(),
                ip: "192.168.1.100".into(),
                user: "root".into(),
                success: false,
                raw_line: "".into(),
            },
            SshAttempt {
                timestamp: "Aug 20 10:00:02".into(),
                ip: "192.168.1.100".into(),
                user: "admin".into(),
                success: false,
                raw_line: "".into(),
            },
            SshAttempt {
                timestamp: "Aug 20 10:00:03".into(),
                ip: "192.168.1.100".into(),
                user: "root".into(),
                success: false,
                raw_line: "".into(),
            },
            SshAttempt {
                timestamp: "Aug 20 10:00:04".into(),
                ip: "10.0.0.50".into(),
                user: "root".into(),
                success: false,
                raw_line: "".into(),
            },
        ];

        let attackers = scanner.detect_attackers(&attempts);
        assert_eq!(attackers.len(), 1);
        assert_eq!(attackers[0].ip, "192.168.1.100");
        assert_eq!(attackers[0].failed_attempts, 3);
    }

    #[test]
    fn test_calculate_score() {
        let config = SshBruteforceConfig::default();
        let scanner = SshBruteforceScanner::new(config);

        // No attacks = 100
        let score = scanner.calculate_score(&[], 0);
        assert_eq!(score, 100);

        // One attacker with 10 failures
        let attackers = vec![BruteforceAttacker {
            ip: "1.2.3.4".into(),
            attempts: vec![],
            total_attempts: 10,
            failed_attempts: 10,
            usernames_targeted: vec![],
            first_attempt: "".into(),
            last_attempt: "".into(),
            blocked: false,
        }];
        let score = scanner.calculate_score(&attackers, 10);
        assert!(score < 100);
    }

    #[test]
    fn test_score_perfect_clean_log() {
        let config = SshBruteforceConfig::default();
        let scanner = SshBruteforceScanner::new(config);

        let log_content = r#"Aug 20 10:00:03 server sshd[1236]: Accepted password for user1 from 192.168.1.101 port 22 ssh2
"#;

        let attempts = scanner.parse_auth_log(log_content).unwrap();
        let attackers = scanner.detect_attackers(&attempts);
        let score = scanner.calculate_score(&attackers, 0);
        assert_eq!(score, 100);
    }
}
