use crate::config::AppConfig;
use crate::models::file;
use crate::models::file::File;
use crate::models::upload_sessions::{fail_upload_session, get_temp_file, UploadSession, UploadStatus};
use crate::routers::authorization::Authorization;
use crate::services::encryption;
use crate::{create_error_response, ApiResponse, ApiResponseCode, Db};
use chrono::Utc;
use cipher::KeyIvInit;
use cipher::StreamCipherSeek;
use rocket::data::{ByteUnit, ToByteUnit};
use rocket::futures::TryFutureExt;
use rocket::http::{Header, Status};
use rocket::log::private::{info, warn};
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::serde::json::Json;
use rocket::tokio::fs;
use rocket::{error, post, put, request, routes, Data, Request, Shutdown, State};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::io::{SeekFrom, Write};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

// ===================================
//
//  UPLOAD INITIATION
//
// ===================================


#[derive(Debug, Deserialize)]
pub struct InitiateUploadRequest {
    pub path: String,
    pub total_size: i64,
    pub iv: String,
}

#[derive(Debug, Serialize)]
pub struct InitiateUploadResponse {
    pub session_id: String,
    pub file_id: String,
}

#[post("/initiate", data = "<body>")]
pub async fn initiate_upload(
    auth_user: Authorization,
    body: Json<InitiateUploadRequest>,
    mut pool: Connection<Db>,
    config: &State<AppConfig>,
) -> Result<Json<InitiateUploadResponse>, (Status, Json<ApiResponse>)> {

    // Check the path
    if !file::is_path_valid(&body.path, &auth_user.user) {
        return Err((
            Status::NotAcceptable,
            create_error_response(ApiResponseCode::HackTry, "You really thought that you can hack the system? This path will not take you anywhere.")
        ));
    }


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
    let _ = File::create(&mut **pool, file_id.clone(), body.path.clone(), auth_user.user.id.clone(), now_utc)
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
        body.path.clone(),
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

    // fs::File::create(get_temp_file(&config.root, &session_id))
    //     .await
    //     .map_err(|e| {
    //         error!("Failed to create temporary file: {}", e);
    //         (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
    //     })?;

    let new_file_upload_path = get_temp_file(&config.root, &session_id);

    let mut temp_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&new_file_upload_path)
        .await
        .map_err(|e| {
            error!("Failed to create temporary file for upload: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Failed to create temporary file for upload"))
        })?;

    temp_file.set_len(body.total_size as u64)
        .await
        .map_err(|e| {
            error!("Failed to pre-allocate temporary file size: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Failed to pre-allocate temporary file size"))
        })?;

    Ok(Json(InitiateUploadResponse { session_id, file_id }))
}


// ===================================
//
//  UPLOAD CHUNK
//
// ===================================

#[derive(Debug)]
pub struct ContentRangeHeader {
    pub total: u64,
    pub start: u64,
    pub end: u64,
}

fn parse_range_header(range_header_value: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = range_header_value.splitn(2, '/').collect();

    if parts.len() == 2 {
        let range_part = parts[0];
        let total_part = parts[1];

        let start_end_parts: Vec<&str> = range_part.splitn(2, '-').collect();

        if start_end_parts.len() == 2 {
            let start_str = start_end_parts[0];
            let end_str = start_end_parts[1];

            if let (Ok(start), Ok(end), Ok(total)) = (
                start_str.parse::<u64>(),
                end_str.parse::<u64>(),
                total_part.parse::<u64>(),
            ) {
                return Some((start, end, total));
            }
        }
    }
    None
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ContentRangeHeader {
    type Error = Json<ApiResponse>;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        if let Some(range_header_value) = request.headers().get_one("Content-Range") {
            let v = range_header_value.to_string();
            let parts = parse_range_header(&v);
            if parts.is_none() {
                return Outcome::Error((
                    Status::BadRequest,
                    create_error_response(ApiResponseCode::InvalidHeader, "Invalid format for the header 'Content-Range'.")
                ));
            }

            let (start, end, total) = parts.unwrap();

            Outcome::Success(Self {
                total,
                start,
                end,
            })
        } else {
            Outcome::Error((Status::BadRequest, create_error_response(ApiResponseCode::MissingHeader, "The header 'Content-Range' is required")))
        }
    }
}

#[put("/session/<session_id>/chunk", data = "<chunk_stream>")]
pub async fn upload_chunk(
    auth_user: Authorization,
    session_id: &'_ str,
    content_range: ContentRangeHeader,
    chunk_stream: Data<'_>,
    mut conn: Connection<Db>,
    config: &State<AppConfig>,
) -> Result<Json<ApiResponse>, (Status, Json<ApiResponse>)> {
    let mut session = match UploadSession::get_by_session_id(&mut **conn, session_id).await {
        Ok(session) => session,
        Err(e) => {
            return if let Some(sqlx_err) = e.downcast_ref::<sqlx::Error>() {
                match sqlx_err {
                    sqlx::Error::RowNotFound => {
                        Err((Status::NotFound, create_error_response(ApiResponseCode::NotFound, "Session not found")))
                    }
                    _ => {
                        error!("Failed to get upload session (SQLx error): {}", e);
                        Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred")))
                    }
                }
            } else {
                error!("Failed to get upload session (unknown error type): {}", e);
                Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred")))
            }
        }
    };

    // Do some checks

    if session.user_id != auth_user.user.id {
        return Err((
            Status::Forbidden,
            create_error_response(ApiResponseCode::Unauthorized, "Access denied to this upload session.")
        ));
    }

    if !matches!(session.status, UploadStatus::Pending) {
        return Err((
            Status::BadRequest,
            create_error_response(ApiResponseCode::InvalidHeader, format!("Upload session is not in pending status. Current status: {:?}", session.status))
        ));
    }

    if let Some(expires_at) = session.expires_at {
        if Utc::now().naive_utc() > expires_at {
            let _ = fail_upload_session(&session, &config, &mut **conn).await;
            return Err((
                Status::Gone,
                create_error_response(ApiResponseCode::UploadSessionExpired, "Upload session has expired.")
            ))
        }
    }

    if !(content_range.total as i64).eq(&session.total_size) {
        return Err((
            Status::BadRequest,
            create_error_response(ApiResponseCode::InvalidHeader, "Upload session has invalid size.")
        ));
    }

    // Read the incoming chunk data into a buffer

    let chunk_size = (content_range.end - content_range.start + 1) as usize;
    let mut buffer = vec![0u8; chunk_size];

    let bytes_read = chunk_stream
        .open(ByteUnit::from(chunk_size).bytes())
        .read_exact(&mut buffer)
        .await
        .map_err(|e| {
            error!("Failed to read chunk data from temporary file: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred while reading chunk data"))
        })?;

    if bytes_read != chunk_size {
        warn!(
            "Warning: Bytes read ({}) mismatch with Content-Range expected length ({}) for session {}",
            bytes_read, chunk_size, session.id
        );
        return Err((
            Status::InternalServerError,
            create_error_response(ApiResponseCode::UploadFailed, "The upload failed: incomplete chunk read")
        ));
    }

    // --- ENCRYPTION OF THE CHUNK ---
    let encryption_key = config.upload.encryption_key.as_bytes();
    let iv_bytes = hex::decode(&session.iv)
        .map_err(|e| {
            error!("Failed to decode IV from hex: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Invalid IV stored for session"))
        })?;

    let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| {
        error!("Stored IV has incorrect length: {}", session.iv);
        (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Stored IV has incorrect length"))
    })?;

    let block_size: u64 = 16;
    let start_byte_offset = content_range.start;
    let start_block_offset = start_byte_offset / block_size;

    let mut cipher = encryption::Aes256Ctr::new(encryption_key.into(), &iv_array.into());

    let _ = cipher.seek(start_byte_offset);

    encryption::encrypt_chunk_in_stream(&mut cipher, &mut buffer);

    // --- Write the ENCRYPTED chunk to the temporary file ---
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(false)
        .open(get_temp_file(&config.root, &session.id))
        .await
        .map_err(|e| {
            error!("Failed to open temporary file at chunk upload: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    file.seek(SeekFrom::Start(content_range.start))
        .await
        .map_err(|e| {
            error!("Failed to seek temporary file at chunk upload: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;


    let _ = tokio::io::AsyncWriteExt::write_all(&mut file, &buffer)
        .await
        .map_err(|e| {
            error!("Failed to write encrypted chunk to temporary file: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    if bytes_read != chunk_size {
        warn!(
            "Warning: Bytes written ({}) mismatch with Content-Range expected length ({}) for session {}",
            bytes_read, chunk_size, session.id
        );
        return Err((
            Status::InternalServerError,
            create_error_response(ApiResponseCode::UploadFailed, "The upload failed: incomplete chunk write")
        ));
    }


    // Update "uploaded_bytes"

    let updated_at = Utc::now().naive_utc();

    // Use `bytes_read` (which is equal to `chunk_size` if successful) as the amount written
    let _ = UploadSession::update_uploaded_bytes(&mut **conn, &session.id, bytes_read as i64, updated_at).await;

    Ok(Json(ApiResponse {
        code: ApiResponseCode::ChunkUploadOK,
        message: format!("Chunk for session {:?} processed. Bytes written: {}", session.id, bytes_read),
    }))
}

// ===================================
//
//  UPLOAD FINALIZATION
//
// ===================================


#[derive(Debug, Deserialize)]
pub struct FinalizeUploadRequest {
    pub file_hash: String,
}

#[post("/session/<session_id>/finalize", data = "<body>")]
pub async fn finalize_upload(
    auth_user: Authorization,
    session_id: &str,
    body: Json<FinalizeUploadRequest>,
    mut conn: Connection<Db>,
    app_config: &State<AppConfig>,
    _shutdown: Shutdown,
) -> Result<Json<ApiResponse>, (Status, Json<ApiResponse>)> {
    let mut session = match UploadSession::get_by_session_id(&mut **conn, session_id).await {
        Ok(session) => session,
        Err(e) => {
            return if let Some(sqlx_err) = e.downcast_ref::<sqlx::Error>() {
                match sqlx_err {
                    sqlx::Error::RowNotFound => {
                        Err((Status::NotFound, create_error_response(ApiResponseCode::NotFound, "Session not found")))
                    }
                    _ => {
                        error!("Failed to get upload session (SQLx error): {}", e);
                        Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred")))
                    }
                }
            } else {
                error!("Failed to get upload session (unknown error type): {}", e);
                Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred")))
            }
        }
    };

    // Do some checkups (these remain the same)
    if session.user_id != auth_user.user.id {
        return Err((
            Status::Unauthorized,
            create_error_response(ApiResponseCode::Unauthorized, "Access denied to this upload session.")
        ));
    }

    if !matches!(session.status, UploadStatus::Pending) {
        return Err((
            Status::BadRequest,
            create_error_response(ApiResponseCode::UploadSessionExpired, "Upload session has failed or finished.")
        ));
    }

    if let Some(expires_at) = session.expires_at {
        if Utc::now().naive_utc() > expires_at {
            let _ = fail_upload_session(&session, &app_config, &mut **conn).await;
            return Err((
                Status::Gone,
                create_error_response(ApiResponseCode::UploadSessionExpired, "Upload session has expired.")
            ))
        }
    }

    let temp_path = get_temp_file(&app_config.root, session_id);


    let mut file = fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(&temp_path)
        .await
        .map_err(|e| {
            error!("Failed to open temporary file for finalization: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    file.set_len(session.total_size as u64)
        .await
        .map_err(|e| {
            error!("Failed to set temporary file length: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred during file finalization"))
        })?;


    let temp_file_metadata = fs::metadata(&temp_path)
        .await
        .map_err(|_| {
            error!("Failed to get metadata of temporary file: {}", temp_path.as_path().to_string_lossy());
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    if temp_file_metadata.len() as i64 != session.total_size {
        let _ = fail_upload_session(&session, &app_config, &mut **conn).await;
        return Err((Status::BadRequest, create_error_response(ApiResponseCode::UploadFailed, "Incomplete upload. File size mismatch.")));
    }

    // Read the ENCRYPTED data from the temporary file
    let mut encrypted_data = fs::read(&temp_path)
        .await
        .map_err(|e| {
            error!("Failed to read temporary file: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    let key = &app_config.upload.encryption_key;
    let iv_bytes = hex::decode(&session.iv.as_bytes())
        .map_err(|e| {
            error!("Failed to decode IV from hex for decryption: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Invalid IV stored for session for decryption"))
        })?;

    let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| {
        error!("Stored IV has incorrect length for decryption: {}", session.iv);
        (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Stored IV has incorrect length for decryption"))
    })?;


    // --- DECRYPT THE DATA FOR HASH CALCULATION ---
    let mut decrypted_data = encrypted_data.clone();
    if let Err(e) = encryption::decrypt_data(&mut decrypted_data, key.as_bytes(), &iv_array) {
        eprintln!("Decryption error for session {}: {}", session_id, e);
        let _ = fail_upload_session(&session, &app_config, &mut **conn).await;
        return Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, format!("Failed to decrypt data for hash: {}", e))));
    }

    let server_file_hash = Sha256::digest(&decrypted_data).to_vec();
    let client_file_hash = hex::decode(&body.file_hash)
        .map_err(|_| (Status::BadRequest, create_error_response(ApiResponseCode::InvalidHMAC, "Invalid file hash format (not hex)")))?;

    if server_file_hash.len() != client_file_hash.len() || !server_file_hash.iter().zip(client_file_hash.iter()).all(|(a, b)| a == b) {
        eprintln!("File hash mismatch for session {}", session_id);
        let _ = fail_upload_session(&session, &app_config, &mut **conn).await;
        return Err((Status::Forbidden, create_error_response(ApiResponseCode::UploadFailed, "File hash verification failed. Data integrity compromised.")));
    }

    // Finally, upload the file
    let file = File::get_from_id(&mut **conn, &session.file_id)
        .await
        .map_err(|e| {
            (Status::NotFound, create_error_response(ApiResponseCode::NotFound, "File not found"))
        })?;

    if let Err(e) = file.finish_upload(&mut **conn, auth_user.user.id, app_config, &encrypted_data, &server_file_hash).await { // Pass encrypted_data and server_file_hash
        error!("Failed to finish upload: {}", e);
        return Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred")));
    };

    let _ = UploadSession::delete(&mut **conn, app_config, session_id).await;

    Ok(Json(ApiResponse {
        code: ApiResponseCode::UploadFinished,
        message: "Upload finished successfully.".to_string(),
    }))
}

pub fn get_routes() -> Vec<rocket::Route> {
    routes![initiate_upload, upload_chunk, finalize_upload]
}
