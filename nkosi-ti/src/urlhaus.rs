use anyhow::Result;
use chrono::Utc;
use nkosi_common::types::*;
use tracing::{info, warn};

pub struct UrlhausClient {
    base_url: String,
}

impl UrlhausClient {
    pub fn new() -> Self {
        Self {
            base_url: "https://urlhaus.abuse.ch".to_string(),
        }
    }

    pub async fn fetch_recent_urls(&self) -> Result<Vec<ThreatIndicator>> {
        info!("Fetching recent URLs from URLhaus");
        
        let url = format!("{}/csv/recent/", self.base_url);
        
        match reqwest::get(&url).await {
            Ok(response) => {
                if response.status().is_success() {
                    let text = response.text().await?;
                    let indicators = self.parse_csv(&text);
                    info!("Fetched {} URLs from URLhaus", indicators.len());
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

    fn parse_csv(&self, text: &str) -> Vec<ThreatIndicator> {
        let mut indicators = Vec::new();
        
        for line in text.lines() {
            let line = line.trim();
            
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                // CSV format: id, url, status, threat, date_added, ...
                let url = parts[1].trim().trim_matches('"');
                let threat = parts[3].trim().trim_matches('"');
                
                if !url.is_empty() && url.starts_with("http") {
                    indicators.push(ThreatIndicator {
                        id: uuid::Uuid::new_v4(),
                        indicator_type: IndicatorType::Url,
                        value: url.to_string(),
                        malware_family: if threat.is_empty() { None } else { Some(threat.to_string()) },
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
