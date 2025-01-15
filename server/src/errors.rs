use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("No token has been detected")]
    NoToken,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonError {
    pub message: String,
}
