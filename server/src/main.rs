mod authorization;
mod config;
mod errors;
mod models;

use crate::authorization::Authorization;
use crate::config::AppConfig;
use clap::Parser;
use dotenv::dotenv;
use rocket::fairing::AdHoc;
use rocket::{error, fairing, get, routes, Build, Rocket};
use rocket_db_pools::Database;
use std::env;
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
        .mount("/", routes![test])
        .mount("/hub", authorization::get_routes());

    api.launch().await.expect("API launch failed");

    Ok(())
}

#[get("/")]
fn test(auth: Authorization) -> String {
    format!("Hello user '{id}'", id = auth.user.first_name)
}
