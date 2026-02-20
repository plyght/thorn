use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThornError {
    #[error("detection error: {0}")]
    Detection(String),

    #[error("chain error: {0}")]
    Chain(String),

    #[error("honeypot error: {0}")]
    Honeypot(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("archive error: {0}")]
    Archive(String),

    #[error("notify error: {0}")]
    Notify(String),

    #[error("capture error: {0}")]
    Capture(String),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type ThornResult<T> = Result<T, ThornError>;
