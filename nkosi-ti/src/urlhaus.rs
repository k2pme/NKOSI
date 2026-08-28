use anyhow::Result;
use chrono::Utc;
use nkosi_common::types::*;
use tracing::{info, warn};

use crate::integrity_check;

#[derive(Clone)]
pub struct UrlhausClient {
    url: String,
}

impl Default for UrlhausClient {
    fn default() -> Self {
        Self::new()
    }
}

impl UrlhausClient {
    pub fn new() -> Self {
        Self {
            url: "https://urlhaus.abuse.ch/csv/recent/".to_string(),
        }
    }

    pub fn with_url(url: String) -> Self {
        Self { url }
    }

    pub async fn fetch_recent_urls(&self) -> Result<Vec<ThreatIndicator>> {
        info!("Fetching recent URLs from URLhaus");

        match reqwest::get(&self.url).await {
            Ok(response) => {
                if response.status().is_success() {
                    let text = response.text().await?;

                    if !integrity_check::validate_min_size(
                        &text,
                        integrity_check::DEFAULT_MIN_FEED_BYTES,
                        "URLhaus",
                    ) {
                        return Ok(Vec::new());
                    }

                    let first_data_line = text
                        .lines()
                        .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'));
                    match first_data_line {
                        Some(line) if line.contains(',') => {}
                        _ => {
                            warn!(
                                "URLhaus response format unexpected (no CSV data lines), possible tampering"
                            );
                            return Ok(Vec::new());
                        }
                    }

                    let audit_hash = integrity_check::compute_audit_hash(&text);
                    info!("URLhaus response audit hash: {}", audit_hash);

                    let indicators = self.parse_csv(&text);
                    info!(
                        "Fetched {} URLs from URLhaus (content hash: {})",
                        indicators.len(),
                        audit_hash
                    );
                    Ok(indicators)
                } else {
                    warn!("URLhaus returned status: {}", response.status());
                    Ok(Vec::new())
                }
            }
            Err(e) => {
                warn!("Failed to fetch from URLhaus: {}", e);
                Ok(Vec::new())
            }
        }
    }

    pub fn parse_csv(&self, text: &str) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();

        for line in text.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 5 {
                // CSV format: id, dateadded, url, status, threat, tags, last_online
                let url = parts[2].trim().trim_matches('"');
                let threat = parts[4].trim().trim_matches('"');

                if url.starts_with("http://") || url.starts_with("https://") {
                    indicators.push(ThreatIndicator {
                        id: uuid::Uuid::new_v4(),
                        indicator_type: IndicatorType::Url,
                        value: url.to_string(),
                        malware_family: if threat.is_empty() {
                            None
                        } else {
                            Some(threat.to_string())
                        },
                        confidence: 0.7,
                        severity: Severity::Medium,
                        source: "URLhaus".to_string(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        tags: vec!["url".to_string(), "malware".to_string()],
                        enabled: true,
                    });
                }
            }
        }

        indicators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> UrlhausClient {
        UrlhausClient::new()
    }

    #[test]
    fn parse_valid_csv() {
        let csv = "12345,2024-01-01 12:00:00,http://evil.com/payload,offline,malware_download,,2024-01-02\n12346,2024-01-01 13:00:00,https://malware.org/steal,online,trojan,,2024-01-02";
        let indicators = client().parse_csv(csv);
        assert_eq!(indicators.len(), 2);
        assert_eq!(indicators[0].indicator_type, IndicatorType::Url);
        assert_eq!(indicators[0].value, "http://evil.com/payload");
        assert_eq!(
            indicators[0].malware_family.as_deref(),
            Some("malware_download")
        );
        assert_eq!(indicators[1].value, "https://malware.org/steal");
        assert_eq!(indicators[1].malware_family.as_deref(), Some("trojan"));
    }

    #[test]
    fn parse_csv_with_comments() {
        let csv =
            "# This is a comment\n12345,2024-01-01,http://evil.com/mal,ok,malware,,2024-01-01\n";
        let indicators = client().parse_csv(csv);
        assert_eq!(indicators.len(), 1);
    }

    #[test]
    fn parse_csv_empty() {
        let indicators = client().parse_csv("");
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_csv_invalid_url_skipped() {
        let csv = "12345,2024-01-01,not-a-url,ok,malware,,2024-01-01";
        let indicators = client().parse_csv(csv);
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_csv_too_few_columns_skipped() {
        let csv = "id,url";
        let indicators = client().parse_csv(csv);
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_csv_ftp_url_skipped() {
        let csv = "12345,2024-01-01,ftp://evil.com/payload,ok,malware,,2024-01-01";
        let indicators = client().parse_csv(csv);
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_csv_empty_threat_field() {
        let csv = "12345,2024-01-01,http://evil.com/payload,online,,,2024-01-01";
        let indicators = client().parse_csv(csv);
        assert_eq!(indicators.len(), 1);
        assert!(indicators[0].malware_family.is_none());
    }
}
