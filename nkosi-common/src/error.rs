use thiserror::Error;

#[derive(Error, Debug)]
pub enum NkosiError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Component not available: {0}")]
    ComponentUnavailable(String),

    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Response error: {0}")]
    Response(String),

    #[error("Threat intelligence error: {0}")]
    ThreatIntel(String),
}

impl From<rusqlite::Error> for NkosiError {
    fn from(err: rusqlite::Error) -> Self {
        NkosiError::Database(err.to_string())
    }
}

impl From<serde_json::Error> for NkosiError {
    fn from(err: serde_json::Error) -> Self {
        NkosiError::Serialization(err.to_string())
    }
}

impl From<toml::de::Error> for NkosiError {
    fn from(err: toml::de::Error) -> Self {
        NkosiError::Config(err.to_string())
    }
}

impl From<toml::ser::Error> for NkosiError {
    fn from(err: toml::ser::Error) -> Self {
        NkosiError::Config(err.to_string())
    }
}
