use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(
    type_name = "ENUM('pending', 'completed', 'failed', 'cancelled')",
    rename_all = "snake_case"
)]
pub enum UploadStatus {
    Pending,
    Completed,
    Failed,
    Cancelled,
}

impl FromStr for UploadStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(UploadStatus::Pending),
            "completed" => Ok(UploadStatus::Completed),
            "failed" => Ok(UploadStatus::Failed),
            "cancelled" => Ok(UploadStatus::Cancelled),
            _ => Err(format!("'{}' is not a valid UploadStatus", s)),
        }
    }
}

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct UploadSession {
    pub id: String,
    pub user_id: String,
    pub file_name: String,
    pub total_size: i64,
    /// The IV in hexadecimal format
    pub iv: String,
    pub uploaded_bytes: i64,
    pub status: UploadStatus,
    pub file_id: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
}