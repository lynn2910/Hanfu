use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

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