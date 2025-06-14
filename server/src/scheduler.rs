use crate::config::AppConfig;
use crate::models::upload_sessions::clear_old_upload_data;
use rocket::error;
use rocket::log::private::trace;
use sqlx::mysql::MySqlPoolOptions;
use std::env;
use std::time::Duration;
use tokio_cron_scheduler::{Job, JobScheduler};

pub async fn create_jobs(config: AppConfig) -> anyhow::Result<()> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = MySqlPoolOptions::new()
        .max_connections(1024)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await?;


    clear_old_upload_data(&mut pool.acquire().await.unwrap(), config.clone()).await?;

    let sched = JobScheduler::new().await?;

    // Clean Upload Files
    let job_pool_clone_1 = pool.clone();
    let config_clone_1 = config.clone();
    sched.add(Job::new("0 0 * * * *", move |_uuid, _l| {
        let pool_clone = job_pool_clone_1.clone();
        let config_clone = config_clone_1.clone();
        tokio::spawn(async move {
            let mut conn = match pool_clone.acquire().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("[JOB] Failed to acquire database connection: {}", e);
                    return;
                }
            };

            if let Err(e) = clear_old_upload_data(&mut conn, config_clone).await {
                error!("[JOB] Failed to clear old upload data: {}", e);
            };
        });

        trace!("[JOB] Old upload session cleaner job triggered");
    })?).await?;

    Ok(())
}