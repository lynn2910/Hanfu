use crate::config::AppConfig;
use chrono::NaiveDateTime;
use rocket::log::private::{error, warn};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, MySqlConnection, Row};
use std::fmt::Display;
use std::str::FromStr;
use std::{fs, io};

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

impl Display for UploadStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            UploadStatus::Pending => "pending",
            UploadStatus::Completed => "completed",
            UploadStatus::Failed => "failed",
            UploadStatus::Cancelled => "cancelled",
        };
        write!(f, "{}", str)
    }
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
impl From<String> for UploadStatus {
    fn from(s: String) -> Self {
        UploadStatus::from_str(&s).unwrap()
    }
}

#[derive(Debug, FromRow, Clone, Serialize, Deserialize)]
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

impl UploadSession {
    pub async fn create(
        conn: &mut MySqlConnection,
        session_id: String,
        user_id: String,
        file_name: String,
        total_size: i64,
        iv: String,
        file_id: String,
        now_utc: NaiveDateTime,
        expires_at: Option<NaiveDateTime>,
    ) -> anyhow::Result<Self> {
        sqlx::query_as!(
            Self,
            r#"
INSERT INTO upload_sessions (id, user_id, file_name, total_size, iv, uploaded_bytes, status, file_id, created_at, updated_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        "#,
            session_id,
            user_id,
            file_name,
            total_size,
            iv,
            0i64,
            UploadStatus::Pending.to_string(),
            file_id,
            now_utc,
            now_utc,
            expires_at
        )
            .execute(&mut *conn)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        sqlx::query_as!(Self, "SELECT * FROM upload_sessions WHERE id = ?", session_id)
            .fetch_one(conn)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }
}

pub async fn clear_old_upload_data(conn: &mut MySqlConnection, config: AppConfig) -> anyhow::Result<()> {
    let old_upload = sqlx::query!("CALL clear_old_upload_data();")
        .fetch_all(conn)
        .await?
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect::<Vec<String>>();

    if old_upload.is_empty() {
        return Ok(());
    }

    let temp_path = config.root.join("temp");


    old_upload.iter()
        .map(|session_id| temp_path.clone().join(format!("hanfu_upload_{}.tmp", session_id)))
        .for_each(|temp_path| {
            if let Err(e) = fs::remove_file(&temp_path) {
                match e.kind() {
                    io::ErrorKind::PermissionDenied => {
                        error!("Cannot clear temp files: {}", temp_path.as_path().to_string_lossy());
                    },
                    io::ErrorKind::IsADirectory => {
                        warn!("Folder in the temp file. The folder '{}' will be removed.", temp_path.as_path().to_string_lossy());
                        let _ = fs::remove_dir_all(&temp_path);
                    }
                    _ => {}
                }
            };
        });

    Ok(())
}