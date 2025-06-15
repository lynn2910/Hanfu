use rocket::serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// The root of the files directory
    pub root: PathBuf,
    pub auth: AuthConfig,
    pub upload: UploadConfig
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadConfig {
    /// The timeout, in hours
    pub upload_sessions_timeout: i64,
    pub encryption_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub(crate) secret_key: String,
}
