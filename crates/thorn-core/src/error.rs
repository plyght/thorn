use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThornError {
    #[error("detection error: {0}")]
    Detection(String),

    #[error("chain error: {0}")]
    Chain(String),

    #[error("honeypot error: {0}")]
    Honeypot(String),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type ThornResult<T> = Result<T, ThornError>;
