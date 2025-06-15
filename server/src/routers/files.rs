use crate::models::file;
use crate::models::file::File;
use crate::routers::authorization::Authorization;
use crate::services::encryption;
use crate::{create_error_response, ApiResponse, ApiResponseCode, AppConfig, Db};
use aes::Aes256;
use cipher::{KeyIvInit, StreamCipherCoreWrapper, StreamCipherSeek};
use ctr::{Ctr32BE, CtrCore};
use mime_guess::mime;
use rocket::http::{ContentType, Status};
use rocket::response::{Responder, Response};
use rocket::serde::json::Json;
use rocket::{get, routes, Request, State};
use rocket_db_pools::Connection;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncRead, ReadBuf};

struct DecryptingReader<R, C>
where
    R: AsyncRead + Unpin,
    C: KeyIvInit + StreamCipherSeek + Clone + Send + 'static,
{
    inner: R,
    cipher_template: C,
    current_offset: u64,
}

impl<R, C> DecryptingReader<R, C>
where
    R: AsyncRead + Unpin,
    C: KeyIvInit + StreamCipherSeek + Clone + Send + 'static,
{
    fn new(inner: R, cipher_template: C) -> Self {
        DecryptingReader {
            inner,
            cipher_template,
            current_offset: 0,
        }
    }
}

impl<R, C> AsyncRead for DecryptingReader<R, C>
where
    R: AsyncRead + Unpin,
    C: KeyIvInit + StreamCipherSeek + Clone + Send + 'static + Unpin,
    Ctr32BE<Aes256>: From<C>,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<Result<(), tokio::io::Error>> {
        let this = self.get_mut();

        let filled_before = buf.filled().len();
        let poll_result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        let filled_after = buf.filled().len();
        let bytes_read_this_call = (filled_after - filled_before) as u64;

        match poll_result {
            std::task::Poll::Ready(Ok(())) => {
                if bytes_read_this_call > 0 {
                    let mut cipher_for_chunk = this.cipher_template.clone();
                    cipher_for_chunk.seek(this.current_offset);

                    let start_idx = filled_after - bytes_read_this_call as usize;
                    encryption::decrypt_chunk_in_stream(&mut cipher_for_chunk.into(), &mut buf.filled_mut()[start_idx..filled_after]);

                    this.current_offset += bytes_read_this_call;
                }
                std::task::Poll::Ready(Ok(()))
            }
            _ => poll_result,
        }
    }
}

struct DecryptedFileResponse<R> {
    reader: R,
    content_type: ContentType,
    content_length: u64,
}

impl<R> DecryptedFileResponse<R> {
    fn new(reader: R, content_type: ContentType, content_length: u64) -> Self {
        Self {
            reader,
            content_type,
            content_length,
        }
    }
}

impl<'r, R> Responder<'r, 'static> for DecryptedFileResponse<R>
where
    R: AsyncRead + Send + 'static,
{
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .header(self.content_type)
            .header(rocket::http::Header::new("Content-Length", self.content_length.to_string()))
            .streamed_body(self.reader)
            .ok()
    }
}

fn get_stored_file_path(root_path: &Path, user_id: &str, path: &str) -> PathBuf {
    root_path.join("user_files").join(user_id).join(path)
}

#[get("/<path..>")]
pub async fn get_file(
    path: PathBuf,
    auth_user: Authorization,
    mut conn: Connection<Db>,
    config: &State<AppConfig>,
) -> Result<DecryptedFileResponse<DecryptingReader<fs::File, encryption::Aes256Ctr>>, (Status, Json<ApiResponse>)> {
    let file = match File::get_from_path(&mut **conn, path.to_str().unwrap_or_default(), &auth_user.user.id).await {
        Ok(f) => f,
        Err(e) => {
            // Handle database errors, specifically `RowNotFound` for file not found.
            return if let Some(sqlx_err) = e.downcast_ref::<sqlx::Error>() {
                match sqlx_err {
                    sqlx::Error::RowNotFound => {
                        Err((Status::NotFound, create_error_response(ApiResponseCode::NotFound, "File not found")))
                    },
                    _ => {
                        eprintln!("Failed to get file (SQLx error): {}", e);
                        Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred")))
                    }
                }
            } else {
                eprintln!("Failed to get file (unknown error type): {}", e);
                Err((Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred")))
            }
        }
    };

    if !file.upload_finished {
        return Err((
            Status::Forbidden,
            create_error_response(
                ApiResponseCode::FileNotReady,
                "File upload isn't finished",
            )
        ));
    }

    let encrypted_file_path = get_stored_file_path(&config.root, &auth_user.user.id, path.to_str().unwrap_or_default());

    let encrypted_file = fs::File::open(&encrypted_file_path)
        .await
        .map_err(|e| {
            eprintln!("Failed to open encrypted file for download: {}. Error: {}", encrypted_file_path.display(), e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Failed to open file for download"))
        })?;

    let encryption_key = config.upload.encryption_key.as_bytes();

    let iv_bytes = hex::decode(&file.iv)
        .map_err(|e| {
            eprintln!("Failed to decode IV from hex for decryption: {}", e);
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Invalid IV stored for session for decryption"))
        })?;

    let iv_array: [u8; 16] = iv_bytes.try_into().map_err(|_| {
        eprintln!("Stored IV has incorrect length for decryption: {}", file.iv);
        (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "Stored IV has incorrect length for decryption"))
    })?;

    let cipher_template = encryption::Aes256Ctr::new(encryption_key.into(), &iv_array.into());

    let decrypted_reader = DecryptingReader::new(encrypted_file, cipher_template);

    let mime_type = file::get_mime_type(path.to_str().unwrap_or_default())
        .unwrap_or(mime::APPLICATION_OCTET_STREAM.to_string());

    let content_type = ContentType::parse_flexible(&mime_type).unwrap_or(ContentType::Binary);

    Ok(DecryptedFileResponse::new(decrypted_reader, content_type, file.total_size as u64))
}

pub fn get_routes() -> Vec<rocket::Route> {
    routes![get_file]
}