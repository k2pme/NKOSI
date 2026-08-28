use anyhow::Result;
use nkosi_common::config::ThreatIntelConfig;
use nkosi_common::types::*;
use nkosi_db::Database;
use tracing::{debug, info, warn};

use crate::malwarebazaar::MalwareBazaarClient;
use crate::threatfox::ThreatFoxClient;
use crate::urlhaus::UrlhausClient;

#[derive(Clone)]
pub struct UpdateService {
    db: Database,
    malwarebazaar: MalwareBazaarClient,
    threatfox: ThreatFoxClient,
    urlhaus: UrlhausClient,
    update_interval_hours: u32,
    malwarebazaar_enabled: bool,
    threatfox_enabled: bool,
    urlhaus_enabled: bool,
}

impl UpdateService {
    pub fn new(db: Database, update_interval_hours: u32) -> Self {
        Self::from_config(
            db,
            &ThreatIntelConfig {
                update_interval_hours,
                ..ThreatIntelConfig::default()
            },
        )
    }

    pub fn from_config(db: Database, config: &ThreatIntelConfig) -> Self {
        let source = |name: &str| {
            config
                .sources
                .iter()
                .find(|source| source.name.eq_ignore_ascii_case(name))
        };
        let malwarebazaar = source("MalwareBazaar");
        let threatfox = source("ThreatFox");
        let urlhaus = source("URLhaus");
        Self {
            db,
            malwarebazaar: malwarebazaar
                .map(|s| MalwareBazaarClient::with_url(s.url.clone()))
                .unwrap_or_default(),
            threatfox: threatfox
                .map(|s| ThreatFoxClient::with_url(s.url.clone()))
                .unwrap_or_default(),
            urlhaus: urlhaus
                .map(|s| UrlhausClient::with_url(s.url.clone()))
                .unwrap_or_default(),
            update_interval_hours: config.update_interval_hours.max(1),
            malwarebazaar_enabled: malwarebazaar.map(|s| s.enabled).unwrap_or(false),
            threatfox_enabled: threatfox.map(|s| s.enabled).unwrap_or(false),
            urlhaus_enabled: urlhaus.map(|s| s.enabled).unwrap_or(false),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting Threat Intelligence Update Service");

        // Initial update in background so monitors are not delayed
        let service = self.clone();
        tokio::spawn(async move {
            if let Err(e) = service.update_all().await {
                warn!("Initial TI update failed: {}", e);
            }
        });

        // Schedule periodic updates
        let interval = std::time::Duration::from_secs(self.update_interval_hours as u64 * 3600);
        let service = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                info!("Running scheduled TI update");
                if let Err(e) = service.update_all().await {
                    warn!("Scheduled TI update failed: {}", e);
                }
            }
        });

        Ok(())
    }

    pub async fn update_all(&self) -> Result<()> {
        info!("Starting TI update from all sources");

        let mut total_indicators = 0;

        // Update from MalwareBazaar
        if self.malwarebazaar_enabled {
            match self.malwarebazaar.fetch_recent_hashes().await {
                Ok(indicators) => {
                    let count = self.insert_indicators(&indicators).await;
                    total_indicators += count;
                    info!("MalwareBazaar: {} new indicators", count);
                }
                Err(e) => {
                    warn!("Failed to update from MalwareBazaar: {}", e);
                }
            }
        }

        // Update from ThreatFox
        if self.threatfox_enabled {
            match self.threatfox.fetch_recent_iocs().await {
                Ok(indicators) => {
                    let count = self.insert_indicators(&indicators).await;
                    total_indicators += count;
                    info!("ThreatFox: {} new indicators", count);
                }
                Err(e) => {
                    warn!("Failed to update from ThreatFox: {}", e);
                }
            }
        }

        // Update from URLhaus
        if self.urlhaus_enabled {
            match self.urlhaus.fetch_recent_urls().await {
                Ok(indicators) => {
                    let count = self.insert_indicators(&indicators).await;
                    total_indicators += count;
                    info!("URLhaus: {} new indicators", count);
                }
                Err(e) => {
                    warn!("Failed to update from URLhaus: {}", e);
                }
            }
        }

        info!(
            "TI update completed: {} total new indicators",
            total_indicators
        );

        Ok(())
    }

    async fn insert_indicators(&self, indicators: &[ThreatIndicator]) -> u32 {
        let repo = nkosi_db::ThreatIndicatorRepository::new(&self.db);
        let mut inserted = 0;

        for indicator in indicators {
            // Check if already exists
            if let Ok(existing) = repo.find_by_value(&indicator.value)
                && existing.is_some()
            {
                debug!("Indicator already exists: {}", indicator.value);
                continue;
            }

            if let Err(e) = repo.insert(indicator) {
                warn!("Failed to insert indicator {}: {}", indicator.value, e);
            } else {
                inserted += 1;
            }
        }

        inserted
    }

    pub fn get_stats(&self) -> Result<TiStats> {
        let repo = nkosi_db::ThreatIndicatorRepository::new(&self.db);
        let total = repo.count()?;

        Ok(TiStats {
            total_indicators: total as u32,
            last_update: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TiStats {
    pub total_indicators: u32,
    pub last_update: Option<String>,
}
