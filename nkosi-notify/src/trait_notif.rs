use async_trait::async_trait;
use crate::types::{Alert, AlertLevel};
use anyhow::Result;

#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send(&self, alert: &Alert) -> Result<()>;
    fn name(&self) -> &str;
    fn min_level(&self) -> AlertLevel;
}
