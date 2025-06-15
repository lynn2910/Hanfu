mod config;
mod errors;
mod models;
mod routers;
mod scheduler;
mod services;

use crate::config::AppConfig;
use crate::models::upload_sessions::clear_old_upload_data;
use crate::routers::authorization::Authorization;
use crate::routers::{authorization, files, upload};
use crate::scheduler::create_jobs;
use clap::Parser;
use dotenv::dotenv;
use rocket::fairing::AdHoc;
use rocket::http::{ContentType, Status};
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::{catch, catchers, error, fairing, get, routes, Build, Request, Response, Rocket};
use rocket_db_pools::Database;
use serde::Serialize;
use serde_repr::Serialize_repr;
use std::env;
use std::io::Cursor;
use std::path::PathBuf;

#[derive(Database)]
#[database("core")]
pub struct Db(sqlx::MySqlPool);

#[derive(Parser)]
struct Cli {
    #[arg(long, short)]
    pub config: PathBuf,
}

async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    // run the migrations
    match Db::fetch(&rocket) {
        Some(db) => match sqlx::migrate!("db/migrations").run(&db.0).await {
            Ok(_) => Ok(rocket),
            Err(e) => {
                error!("Failed to run database migrations: {}", e);
                Err(rocket)
            }
        },
        None => Err(rocket),
    }
}

#[rocket::main]
async fn main() -> Result<(), anyhow::Error> {
    color_eyre::install().map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let cli = Cli::parse();
    dotenv().ok();

    let app_config: AppConfig = toml::from_str(
        std::fs::read_to_string(cli.config)
            .expect("Cannot read config.toml")
            .as_str(),
    )
    .expect("Cannot parse the config from config.toml");

    if let Err(e) = create_jobs(app_config.clone()).await {
        error!("Failed to create jobs scheduler: {}", e);
        std::process::exit(1);
    }

    let migrations_fairing = AdHoc::try_on_ignite("SQLx Migrations", run_migrations);

    // Create DB config for Rocket
    let figment = rocket::Config::figment().merge((
        "databases.core",
        rocket_db_pools::Config {
            url: env::var("DATABASE_URL").expect("DATABASE_URL not set"),
            min_connections: None,
            max_connections: 1024,
            connect_timeout: 3,
            idle_timeout: None,
            extensions: None,
        },
    ));

    let api = rocket::custom(figment)
        .manage(app_config)
        .attach(Db::init())
        .attach(migrations_fairing)
        .mount("/", routes![hello, test])
        .register("/", catchers![unauthorized, internal_error, not_found])
        .mount("/hub", authorization::get_routes())
        .mount("/upload", upload::get_routes())
        .mount("/files", files::get_routes());

    api.launch().await.expect("API launch failed");

    Ok(())
}

#[derive(Serialize_repr, Debug, PartialEq)]
#[repr(u32)]
pub enum ApiResponseCode {
    /// This specific code is used when someone is trying to hack the systems.
    HackTry = 0001,
    Unauthorized = 1001,
    InternalError = 1002,
    NotFound = 1003,
    MissingHeader = 1004,
    InvalidHeader = 1005,

    HubCannotSignup = 2001,
    UploadInvalidIVFormat = 3001,
    UploadInvalidIVLength = 3002,
    UploadSessionExpired = 3003,
    UploadFailed = 3004,
    InvalidHMAC = 3005,
    ChunkUploadOK = 3101,
    UploadFinished = 3102,
}

fn create_error_response(code: ApiResponseCode, message: impl ToString) -> Json<ApiResponse> {
    ApiResponse { code, message: message.to_string() }.into()
}

#[derive(Serialize, Debug)]
pub struct ApiResponse {
    code: ApiResponseCode,
    message: String,
}

impl<'r> Responder<'r, 'static> for ApiResponse {
    fn respond_to(self, _: &'r Request) -> rocket::response::Result<'static> {
        let json_string = serde_json::to_string(&self)
            .map_err(|e| {
                eprintln!("Error serializing ApiErrorResponse: {:?}", e);
                Status::InternalServerError
            })?;

        Response::build()
            .sized_body(json_string.len(), Cursor::new(json_string))
            .header(ContentType::new("application", "json"))
            .status(Status::BadRequest)
            .ok()
    }
}

#[catch(401)]
fn unauthorized() -> Json<ApiResponse> {
    create_error_response(ApiResponseCode::Unauthorized, "Access denied".to_string())
}

#[catch(500)]
fn internal_error() -> Json<ApiResponse> {
    create_error_response(ApiResponseCode::InternalError, "Internal server error".to_string())
}

#[catch(404)]
fn not_found(req: &Request) -> Json<ApiResponse> {
    create_error_response(ApiResponseCode::NotFound, format!("Not found: {}", req.uri()))
}

#[get("/")]
fn hello() -> &'static str {
    "hello world!"
}

#[get("/secured")]
fn test(auth: Authorization) -> String {
    format!("Hello user '{id}'", id = auth.user.first_name)
}
