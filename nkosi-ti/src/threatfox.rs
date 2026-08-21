use anyhow::Result;
use chrono::Utc;
use nkosi_common::types::*;
use tracing::{info, warn};

pub struct ThreatFoxClient {
    base_url: String,
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
                    let indicators = self.parse_json_response(&text);
                    info!("Fetched {} IOCs from ThreatFox", indicators.len());
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

    fn parse_json_response(&self, text: &str) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();
        
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(data) = json.get("data") {
                if let Some(iocs) = data.as_array() {
                    for ioc in iocs {
                        if let Some(indicator) = self.parse_ioc(ioc) {
                            indicators.push(indicator);
                        }
                    }
                }
            }
        }
        
        indicators
    }

    fn parse_ioc(&self, ioc: &serde_json::Value) -> Option<ThreatIndicator> {
        let ioc_type = ioc.get("ioc_type")?.as_str()?;
        let ioc_value = ioc.get("ioc")?.as_str()?;
        let malware = ioc.get("malware")?.as_str();
        let confidence = ioc.get("confidence_level")?.as_f64().unwrap_or(50.0) as f32 / 100.0;
        
        let indicator_type = match ioc_type {
            "ip:port" => {
                IndicatorType::Ip
            }
            "domain" => IndicatorType::Domain,
            "url" => IndicatorType::Url,
            "md5" => IndicatorType::Md5,
            "sha1" => IndicatorType::Sha1,
            "sha256" => IndicatorType::Sha256,
            _ => return None,
        };

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
