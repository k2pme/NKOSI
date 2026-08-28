use anyhow::Result;
use std::path::Path;

use nkosi_common::config::NkosiConfig;
use nkosi_db::Database;

pub fn load_config() -> Result<NkosiConfig> {
    let config_path = "/etc/nkosi/nkosi.toml";
    if Path::new(config_path).exists() {
        Ok(NkosiConfig::load(config_path)?)
    } else {
        let local_config = "config/nkosi.toml";
        if Path::new(local_config).exists() {
            Ok(NkosiConfig::load(local_config)?)
        } else {
            Ok(NkosiConfig::default())
        }
    }
}

pub fn init_database(config: &NkosiConfig) -> Result<Database> {
    let db_path = &config.agent.db_path;

    if let Some(parent) = db_path.parent()
        && parent.exists()
        && std::fs::create_dir_all(parent).is_ok()
        && let Ok(db) = Database::new(db_path)
    {
        return Ok(db);
    }

    let local_path = std::env::current_dir()?.join("data").join("nkosi.db");
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(Database::new(&local_path)?)
}
