use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, MySqlConnection};

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
    pub async fn create(conn: &mut MySqlConnection, file_id: String, user_id: String, now_utc: NaiveDateTime) -> anyhow::Result<Self> {
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
            "",
            false,
            None as Option<NaiveDateTime>
        )
            .execute(&mut *conn)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        sqlx::query_as!(Self, r#"
SELECT
    file_id, owner_id, creation_date,
    signature, path,
    upload_finished as "upload_finished!: _", upload_finished_at
FROM files
WHERE file_id = ?"#,
            file_id
        )
            .fetch_one(conn)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }
}