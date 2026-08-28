use anyhow::Result;
use chrono::Utc;
use nkosi_common::types::*;
use tracing::{info, warn};

use crate::integrity_check;

pub struct ThreatFoxClient {
    base_url: String,
}

impl Default for ThreatFoxClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatFoxClient {
    pub fn new() -> Self {
        Self {
            base_url: "https://threatfox.abuse.ch".to_string(),
        }
    }

    pub async fn fetch_recent_iocs(&self) -> Result<Vec<ThreatIndicator>> {
        info!("Fetching recent IOCs from ThreatFox");

        let url = format!("{}/api/v1/", self.base_url);

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .json(&serde_json::json!({
                "query": "get_iocs",
                "days": 1
            }))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    let text = resp.text().await?;

                    // RG-008: minimum size check
                    if !integrity_check::validate_min_size(&text, integrity_check::DEFAULT_MIN_FEED_BYTES, "ThreatFox") {
                        return Ok(Vec::new());
                    }

                    // RG-008: compute audit hash
                    let audit_hash = integrity_check::compute_audit_hash(&text);
                    info!("ThreatFox response audit hash: {}", audit_hash);

                    let indicators = self.parse_json_response(&text);
                    info!("Fetched {} IOCs from ThreatFox (content hash: {})", indicators.len(), audit_hash);
                    Ok(indicators)
                } else {
                    warn!("ThreatFox returned status: {}", resp.status());
                    Ok(Vec::new())
                }
            }
            Err(e) => {
                warn!("Failed to fetch from ThreatFox: {}", e);
                Ok(Vec::new())
            }
        }
    }

    pub fn parse_json_response(&self, text: &str) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();

        let json = match serde_json::from_str::<serde_json::Value>(text) {
            Ok(j) => j,
            Err(e) => {
                warn!("ThreatFox JSON parse error: {}", e);
                return indicators;
            }
        };

        // RG-008: validate API-level query_status
        if let Some(status) = json.get("query_status").and_then(|s| s.as_str())
            && status != "ok"
        {
            warn!("ThreatFox query_status is '{}', expected 'ok'", status);
            return indicators;
        }

        if let Some(data) = json.get("data")
            && let Some(iocs) = data.as_array()
        {
            for ioc in iocs {
                if let Some(indicator) = self.parse_ioc(ioc) {
                    indicators.push(indicator);
                }
            }
        }

        indicators
    }

    fn parse_ioc(&self, ioc: &serde_json::Value) -> Option<ThreatIndicator> {
        let ioc_type_str = ioc.get("ioc_type")?.as_str()?;
        let ioc_value = ioc.get("ioc")?.as_str()?;
        let malware = ioc.get("malware")?.as_str();
        let confidence = ioc.get("confidence_level")?.as_f64().unwrap_or(50.0) as f32 / 100.0;

        let indicator_type = match ioc_type_str {
            "ip:port" => IndicatorType::Ip,
            "domain" => IndicatorType::Domain,
            "url" => IndicatorType::Url,
            "md5" => IndicatorType::Md5,
            "sha1" => IndicatorType::Sha1,
            "sha256" => IndicatorType::Sha256,
            _ => {
                warn!("ThreatFox unknown ioc_type: '{}', skipping", ioc_type_str);
                return None;
            }
        };

        // RG-008: validate value format per indicator type
        if !integrity_check::validate_indicator_value(&indicator_type, ioc_value) {
            warn!(
                "ThreatFox value validation failed for type='{}', value='{}', skipping",
                ioc_type_str, ioc_value
            );
            return None;
        }

        Some(ThreatIndicator {
            id: uuid::Uuid::new_v4(),
            indicator_type,
            value: ioc_value.to_string(),
            malware_family: malware.map(|s| s.to_string()),
            confidence,
            severity: Severity::High,
            source: "ThreatFox".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            tags: vec!["ioc".to_string()],
            enabled: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> ThreatFoxClient {
        ThreatFoxClient::new()
    }

    #[test]
    fn parse_valid_json_response() {
        let json = serde_json::json!({
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "ip:port",
                    "ioc": "1.2.3.4:443",
                    "malware": "Emotet",
                    "confidence_level": 80
                },
                {
                    "ioc_type": "domain",
                    "ioc": "evil.example.com",
                    "malware": "TrickBot",
                    "confidence_level": 90
                },
                {
                    "ioc_type": "sha256",
                    "ioc": "a".repeat(64),
                    "malware": "Ransomware",
                    "confidence_level": 100
                }
            ]
        });

        let indicators = client().parse_json_response(&json.to_string());
        assert_eq!(indicators.len(), 3);
        assert_eq!(indicators[0].indicator_type, IndicatorType::Ip);
        assert_eq!(indicators[0].value, "1.2.3.4:443");
        assert_eq!(indicators[0].malware_family.as_deref(), Some("Emotet"));
        assert_eq!(indicators[1].indicator_type, IndicatorType::Domain);
        assert_eq!(indicators[2].indicator_type, IndicatorType::Sha256);
    }

    #[test]
    fn parse_empty_data() {
        let json = serde_json::json!({
            "query_status": "ok",
            "data": []
        });
        let indicators = client().parse_json_response(&json.to_string());
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_invalid_json() {
        let indicators = client().parse_json_response("not json at all");
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_query_status_error() {
        let json = serde_json::json!({
            "query_status": "error",
            "data": []
        });
        let indicators = client().parse_json_response(&json.to_string());
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_unknown_ioc_type_skipped() {
        let json = serde_json::json!({
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "unknown_type",
                    "ioc": "some_value",
                    "malware": "Malware",
                    "confidence_level": 50
                }
            ]
        });
        let indicators = client().parse_json_response(&json.to_string());
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_invalid_value_format_skipped() {
        let json = serde_json::json!({
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "sha256",
                    "ioc": "not-a-valid-hash",
                    "malware": "Malware",
                    "confidence_level": 50
                }
            ]
        });
        let indicators = client().parse_json_response(&json.to_string());
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_invalid_ip_skipped() {
        let json = serde_json::json!({
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "ip:port",
                    "ioc": "not-an-ip",
                    "malware": "Malware",
                    "confidence_level": 50
                }
            ]
        });
        let indicators = client().parse_json_response(&json.to_string());
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_invalid_url_skipped() {
        let json = serde_json::json!({
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "url",
                    "ioc": "ftp://malware.com/payload",
                    "malware": "Malware",
                    "confidence_level": 50
                }
            ]
        });
        let indicators = client().parse_json_response(&json.to_string());
        assert!(indicators.is_empty());
    }

    #[test]
    fn parse_missing_fields_skipped() {
        let json = serde_json::json!({
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "ip:port"
                }
            ]
        });
        let indicators = client().parse_json_response(&json.to_string());
        assert!(indicators.is_empty());
    }
}
