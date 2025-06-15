use crate::config::AppConfig;
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::{FromRow, MySqlConnection};
use tokio::fs;

#[derive(Debug, FromRow, Clone, Serialize, Deserialize)]
pub struct File {
    pub file_id: String,
    pub owner_id: String,
    pub creation_date: NaiveDateTime,
    pub signature: String,
    pub path: String,

    pub upload_finished: bool,
    pub upload_finished_at: Option<NaiveDateTime>,
}

impl File {
    pub async fn create(conn: &mut MySqlConnection, file_id: String, path: String, user_id: String, now_utc: NaiveDateTime) -> anyhow::Result<Self> {
        sqlx::query_as!(
            Self,
            r#"
INSERT INTO files (file_id, owner_id, creation_date, signature, path, upload_finished, upload_finished_at)
VALUES (?, ?, ?, ?, ?, ? , ?);
"#,
            file_id,
            user_id,
            now_utc,
            "",
            path,
            false,
            None as Option<NaiveDateTime>
        )
            .execute(&mut *conn)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        Self::get_from_id(conn, &file_id).await
    }

    pub async fn get_from_id(conn: &mut MySqlConnection, file_id: &str) -> anyhow::Result<Self> {
        sqlx::query_as!(Self, r#"
SELECT
    file_id, owner_id, creation_date,
    signature, path,
    upload_finished as "upload_finished!: _", upload_finished_at
FROM files
WHERE file_id = ?"#,
            file_id
        ).fetch_one(conn)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn finish_upload(
        &self,
        conn: &mut MySqlConnection,
        user_id: String,
        config: &AppConfig,
        encrypted_final_data: &[u8],
        server_file_hash: &Vec<u8>,
    ) -> anyhow::Result<()> {
        let full_storage_path = config.root.join("user_files").join(&user_id).join(&self.path);

        if let Some(parent) = full_storage_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| anyhow::anyhow!(format!("Failed to create parent directories for file storage: {}", e)))?;
        }

        fs::write(&full_storage_path, &encrypted_final_data)
            .await
            .map_err(|e| anyhow::anyhow!(format!("Failed to write encrypted file to final storage: {}", e)))?;

        let updated_at = Utc::now().naive_utc();

        sqlx::query!(
            r#"UPDATE files SET signature = ?, upload_finished = ?, upload_finished_at = ?, creation_date = ? WHERE file_id = ?"#,
            hex::encode(server_file_hash),
            true,
            updated_at,
            updated_at,
            self.file_id
        )
            .execute(conn)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(())
    }
}