use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitFinding {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub path: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitReport {
    pub timestamp: String,
    pub findings: Vec<RootkitFinding>,
    pub score: u32,
    pub summary: String,
}

pub struct RootkitScanner {
    system_binaries: Vec<PathBuf>,
    hidden_file_paths: Vec<PathBuf>,
    _suspicious_paths: Vec<PathBuf>,
}

impl Default for RootkitScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl RootkitScanner {
    pub fn new() -> Self {
        Self {
            system_binaries: Self::get_system_binaries(),
            hidden_file_paths: Self::get_hidden_file_paths(),
            _suspicious_paths: Self::get_suspicious_paths(),
        }
    }

    fn get_system_binaries() -> Vec<PathBuf> {
        vec![
            "/bin/ls".into(),
            "/bin/ps".into(),
            "/bin/netstat".into(),
            "/bin/ss".into(),
            "/bin/find".into(),
            "/bin/top".into(),
            "/bin/du".into(),
            "/bin/df".into(),
            "/usr/bin/lsof".into(),
            "/usr/bin/strace".into(),
            "/usr/bin/readelf".into(),
            "/usr/bin/file".into(),
        ]
    }

    fn get_hidden_file_paths() -> Vec<PathBuf> {
        vec![
            "/etc/ld.so.preload".into(),
            "/etc/cron.d/.hidden".into(),
            "/tmp/.X11-unix/.hidden".into(),
            "/dev/shm/.hidden".into(),
        ]
    }

    fn get_suspicious_paths() -> Vec<PathBuf> {
        vec![
            "/dev/.udev/rules.d".into(),
            "/etc/init.d/.hidden".into(),
            "/usr/lib/.hidden".into(),
        ]
    }

    pub fn scan(&self) -> Result<RootkitReport> {
        info!("Starting rootkit scan");
        let mut findings = Vec::new();

        // Check system binaries
        findings.extend(self.check_system_binaries()?);

        // Check hidden files
        findings.extend(self.check_hidden_files());

        // Check /proc for anomalies
        findings.extend(self.check_proc_anomalies());

        // Check loaded modules
        findings.extend(self.check_kernel_modules());

        // Check network connections
        findings.extend(self.check_suspicious_connections());

        // Check cron jobs
        findings.extend(self.check_cron_jobs());

        // Check startup scripts
        findings.extend(self.check_startup_scripts());

        let score = self.calculate_score(&findings);
        let summary = self.generate_summary(&findings, score);

        info!("Rootkit scan completed: {} findings, score: {}", findings.len(), score);

        Ok(RootkitReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings,
            score,
            summary,
        })
    }

    fn check_system_binaries(&self) -> Result<Vec<RootkitFinding>> {
        let mut findings = Vec::new();

        for binary in &self.system_binaries {
            if !binary.exists() {
                continue;
            }

            // Check if binary is writable (suspicious)
            if let Ok(metadata) = std::fs::metadata(binary) {
                let permissions = metadata.permissions();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = permissions.mode();
                    if mode & 0o222 != 0 {
                        findings.push(RootkitFinding {
                            category: "Tainted Binary".to_string(),
                            severity: "Critical".to_string(),
                            description: format!("System binary {} is writable", binary.display()),
                            path: Some(binary.display().to_string()),
                            details: Some(format!("Mode: {:o}", mode)),
                        });
                    }
                }
            }

            // Check for LD_PRELOAD in binary
            if let Ok(content) = std::fs::read(binary) {
                let content_str = String::from_utf8_lossy(&content);
                if content_str.contains("LD_PRELOAD") || content_str.contains("/etc/ld.so.preload") {
                    findings.push(RootkitFinding {
                        category: "Tainted Binary".to_string(),
                        severity: "Critical".to_string(),
                        description: format!("Binary {} references LD_PRELOAD", binary.display()),
                        path: Some(binary.display().to_string()),
                        details: None,
                    });
                }
            }
        }

        Ok(findings)
    }

    fn check_hidden_files(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        for path in &self.hidden_file_paths {
            if path.exists() {
                findings.push(RootkitFinding {
                    category: "Hidden File".to_string(),
                    severity: "High".to_string(),
                    description: format!("Hidden file found: {}", path.display()),
                    path: Some(path.display().to_string()),
                    details: None,
                });
            }
        }

        // Check for hidden files in /tmp
        if let Ok(entries) = std::fs::read_dir("/tmp") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with('.')
                    && name.to_string_lossy() != "."
                    && name.to_string_lossy() != ".."
                    && entry.path().is_file()
                {
                    findings.push(RootkitFinding {
                        category: "Hidden File".to_string(),
                        severity: "Medium".to_string(),
                        description: format!("Hidden file in /tmp: {}", name.to_string_lossy()),
                        path: Some(entry.path().display().to_string()),
                        details: None,
                    });
                }
            }
        }

        findings
    }

    fn check_proc_anomalies(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        // Check /proc/modules for suspicious modules
        if let Ok(content) = std::fs::read_to_string("/proc/modules") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    let module_name = parts[0];
                    // Flag common rootkit module names
                    let suspicious = ["diamorphine", "reptile", "kovid", "suckit", "knark", "repit"];
                    for &s in &suspicious {
                        if module_name.to_lowercase().contains(s) {
                            findings.push(RootkitFinding {
                                category: "Kernel Module".to_string(),
                                severity: "Critical".to_string(),
                                description: format!("Suspicious kernel module loaded: {}", module_name),
                                path: Some("/proc/modules".to_string()),
                                details: Some(line.to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Check /proc/net for hidden connections
        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            let line_count = content.lines().count();
            if line_count < 2 {
                findings.push(RootkitFinding {
                    category: "Hidden Connections".to_string(),
                    severity: "High".to_string(),
                    description: "Suspiciously few network connections in /proc/net/tcp".to_string(),
                    path: Some("/proc/net/tcp".to_string()),
                    details: Some(format!("Lines: {}", line_count)),
                });
            }
        }

        findings
    }

    fn check_kernel_modules(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/modules") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let module_name = parts[0];
                    let ref_count: u32 = parts[1].parse().unwrap_or(0);

                    // Module loaded but not referenced (suspicious)
                    if ref_count == 0 && !Self::is_whitelisted_module(module_name) {
                        findings.push(RootkitFinding {
                            category: "Kernel Module".to_string(),
                            severity: "Medium".to_string(),
                            description: format!("Unreferenced kernel module: {}", module_name),
                            path: Some("/proc/modules".to_string()),
                            details: Some(line.to_string()),
                        });
                    }
                }
            }
        }

        findings
    }

    fn is_whitelisted_module(name: &str) -> bool {
        let whitelist = [
            "ext4", "xfs", "btrfs", "vfat", "ntfs",
            "nf_conntrack", "iptable_filter", "ip6table_filter",
            "bridge", "bonding", "8021q",
            "snd", "snd_hda_intel",
            "usbhid", "hid",
            "drm", "i915", "nouveau",
        ];
        whitelist.iter().any(|&w| name.starts_with(w))
    }

    fn check_suspicious_connections(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        // Check for connections on unusual ports
        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            for (i, line) in content.lines().enumerate() {
                if i == 0 { continue; } // Skip header

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let local_addr = parts[1];
                    let state = parts[3];

                    // STATE 0A = LISTEN
                    if state == "0A"
                        && let Some(port_hex) = local_addr.split(':').next_back()
                        && let Ok(port) = u32::from_str_radix(port_hex, 16)
                    {
                        // Flag high ports that could be backdoors
                        if port > 1024 && port < 65535 {
                            // Check if it's a known suspicious port
                            let suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337, 1234, 54321];
                            if suspicious_ports.contains(&port) {
                                findings.push(RootkitFinding {
                                    category: "Suspicious Port".to_string(),
                                    severity: "High".to_string(),
                                    description: format!("Listening on suspicious port: {}", port),
                                    path: Some("/proc/net/tcp".to_string()),
                                    details: Some(line.to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_cron_jobs(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        let cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/var/spool/cron/crontabs",
        ];

        for cron_path in &cron_paths {
            if let Ok(content) = std::fs::read_to_string(cron_path) {
                // Check for suspicious commands
                let suspicious = [
                    "wget", "curl", "nc ", "ncat", "bash -i",
                    "/dev/tcp", "python -c", "perl -e", "ruby -e",
                    "base64", "eval(", "chmod 777",
                ];

                for line in content.lines() {
                    for &s in &suspicious {
                        if line.contains(s) {
                            findings.push(RootkitFinding {
                                category: "Suspicious Cron".to_string(),
                                severity: "High".to_string(),
                                description: format!("Suspicious command in cron: {}", line.trim()),
                                path: Some(cron_path.to_string()),
                                details: None,
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_startup_scripts(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        let init_dirs = [
            "/etc/init.d",
            "/etc/rc.local",
            "/etc/systemd/system",
        ];

        for dir in &init_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if entry.path().is_file()
                        && let Ok(content) = std::fs::read_to_string(entry.path())
                    {
                        let suspicious = [
                            "wget", "curl", "nc ", "bash -i",
                            "/dev/tcp", "base64", "chmod 777",
                        ];

                        for line in content.lines() {
                            for &s in &suspicious {
                                if line.contains(s) {
                                    findings.push(RootkitFinding {
                                        category: "Suspicious Init Script".to_string(),
                                        severity: "High".to_string(),
                                        description: format!(
                                            "Suspicious command in {}: {}",
                                            entry.path().display(),
                                            line.trim()
                                        ),
                                        path: Some(entry.path().display().to_string()),
                                        details: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn calculate_score(&self, findings: &[RootkitFinding]) -> u32 {
        let mut score = 0;
        for finding in findings {
            match finding.severity.as_str() {
                "Critical" => score += 40,
                "High" => score += 25,
                "Medium" => score += 10,
                "Low" => score += 5,
                _ => {}
            }
        }
        score.min(100)
    }

    fn generate_summary(&self, findings: &[RootkitFinding], score: u32) -> String {
        let critical = findings.iter().filter(|f| f.severity == "Critical").count();
        let high = findings.iter().filter(|f| f.severity == "High").count();
        let medium = findings.iter().filter(|f| f.severity == "Medium").count();

        if findings.is_empty() {
            "No rootkit indicators found. System appears clean.".to_string()
        } else {
            format!(
                "Found {} indicators: {} critical, {} high, {} medium. Risk score: {}/100",
                findings.len(), critical, high, medium, score
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = RootkitScanner::new();
        assert!(!scanner.system_binaries.is_empty());
    }

    #[test]
    fn test_calculate_score_empty() {
        let scanner = RootkitScanner::new();
        let score = scanner.calculate_score(&[]);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_calculate_score_critical() {
        let scanner = RootkitScanner::new();
        let findings = vec![
            RootkitFinding {
                category: "test".to_string(),
                severity: "Critical".to_string(),
                description: "test".to_string(),
                path: None,
                details: None,
            },
        ];
        let score = scanner.calculate_score(&findings);
        assert_eq!(score, 40);
    }

    #[test]
    fn test_whitelist() {
        assert!(RootkitScanner::is_whitelisted_module("ext4"));
        assert!(RootkitScanner::is_whitelisted_module("nf_conntrack"));
        assert!(!RootkitScanner::is_whitelisted_module("diamorphine"));
    }
}
