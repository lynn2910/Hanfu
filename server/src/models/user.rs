use crate::authorization::Login;
use crate::Db;
use anyhow::bail;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rocket_db_pools::sqlx::Executor;
use rocket_db_pools::Connection;
use sqlx::{FromRow, MySqlConnection, Row};

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: String,

    pub email: String,
    pub first_name: String,
    pub last_name: Option<String>,

    pub password: String,
}

impl User {
    /// Get the email and hashed password, and check if the user login is valid.
    ///
    /// Will return either the user or None if the login is invalid
    pub(crate) async fn login(data: &Login, mut db: Connection<Db>) -> Option<User> {
        let query = sqlx::query_as!(User, "SELECT * FROM users WHERE email = ?;", data.email);

        match db.fetch_one(query).await {
            Ok(row) => {
                let user = User::from_row(&row).expect("Failed to convert row to user");

                let parsed_hash = PasswordHash::new(&user.password);
                if parsed_hash.is_err() {
                    eprintln!("Failed to parse password hash");
                    return None;
                }

                Argon2::default()
                    .verify_password(data.password.as_bytes(), &parsed_hash.unwrap())
                    .ok()
                    .map(|_| user)
            }
            Err(_) => None,
        }
    }

    pub(crate) async fn get_by_email(email: &str, conn: &mut MySqlConnection) -> anyhow::Result<Option<User>> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE email = ?;", email)
            .fetch_optional(conn)
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn get_by_id(id: &str, conn: &mut MySqlConnection) -> anyhow::Result<Option<User>> {
        sqlx::query_as!(User, "SELECT * FROM users WHERE id = ?;", id)
            .fetch_optional(conn)
            .await
            .map_err(|e| e.into())
    }

    pub(crate) async fn create(data: &User, mut db: Connection<Db>) -> Result<User, anyhow::Error> {
        let existing_user = Self::get_by_email(&data.email, &mut **db).await?;

        if existing_user.is_some() {
            bail!("User already exists");
        }

        let query = sqlx::query!(
            r#"
INSERT INTO users (email, first_name, last_name, password)
VALUES (?, ?, ?, ?)
            "#,
            data.email,
            data.first_name,
            data.last_name,
            data.password
        );

        match db.execute(query).await {
            Ok(_) => {
                let query = sqlx::query_as!(User, "SELECT * FROM users WHERE email = ?;", data.email);
                query.fetch_one(&mut **db)
                    .await
                    .map_err(|e| e.into())
            },
            Err(e) => Err(e.into()),
        }
    }
}
