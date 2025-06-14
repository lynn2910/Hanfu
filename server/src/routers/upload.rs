use crate::config::AppConfig;
use crate::models::file::File;
use crate::models::upload_sessions::UploadSession;
use crate::routers::authorization::Authorization;
use crate::{create_error_response, ApiResponse, ApiResponseCode, Db};
use chrono::Utc;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::tokio::fs;
use rocket::{error, post, routes, State};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
// ===================================
//
//  UPLOAD INITIATION
//
// ===================================


#[derive(Debug, Deserialize)]
pub struct InitiateUploadRequest {
    pub file_name: String,
    pub total_size: i64,
    pub iv: String,
}

#[post("/initiate", data = "<body>")]
pub async fn initiate_upload(
    auth_user: Authorization,
    body: Json<InitiateUploadRequest>,
    mut pool: Connection<Db>,
    config: &State<AppConfig>,
) -> Result<Json<InitiateUploadResponse>, (Status, Json<ApiResponse>)> {
    let session_id = Uuid::new_v4().to_string();
    let file_id = Uuid::new_v4().to_string();

    let temp_file_path = config.root.clone().join("temp");
    let now_utc = Utc::now().naive_utc();
    let expires_at = now_utc + chrono::Duration::hours(config.upload.upload_sessions_timeout);

    let iv_bytes_len = hex::decode(&body.iv)
        .map_err(|_| (Status::BadRequest, create_error_response(ApiResponseCode::UploadInvalidIVFormat, "Invalid IV format (not hex)")))?
        .len();

    if iv_bytes_len != 16 {
        return Err((Status::BadRequest, create_error_response(ApiResponseCode::UploadInvalidIVLength, "IV must be 16 bytes (32 hex characters)")));
    }

    // Create file in database
    let _ = File::create(&mut **pool, file_id.clone(), auth_user.user.id.clone(), now_utc)
        .await
        .map_err(|e| {
            error!("Failed to create file in database: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    // Create upload session
    let _ = UploadSession::create(
        &mut **pool,
        session_id.clone(),
        auth_user.user.id.clone(),
        body.file_name.clone(),
        body.total_size,
        body.iv.clone(),
        file_id.clone(),
        now_utc,
        Some(expires_at),
    )
        .await
        .map_err(|e| {
            error!("Failed to create upload session: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    fs::create_dir_all(&temp_file_path)
        .await
        .map_err(|e| {
            error!("Failed to create temporary directory: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    fs::File::create(temp_file_path.join(format!("hanfu_upload_{}.tmp", session_id)))
        .await
        .map_err(|e| {
            error!("Failed to create temporary file: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    Ok(Json(InitiateUploadResponse { session_id, file_id }))
}


// ===================================
//
//  UPLOAD INITIATION
//
// ===================================


#[derive(Debug, Serialize)]
pub struct InitiateUploadResponse {
    pub session_id: String,
    pub file_id: String,
}

#[derive(Debug, Deserialize)]
pub struct FinalizeUploadRequest {
    pub hmac_tag: String,
}


pub fn get_routes() -> Vec<rocket::Route> {
    routes![initiate_upload]
}
