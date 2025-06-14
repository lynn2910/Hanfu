use crate::config::AppConfig;
use crate::models::user::User;
use crate::{create_error_response, ApiResponse, ApiResponseCode, Db};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use rocket::http::hyper::body::HttpBody;
use rocket::http::Status;
use rocket::log::private::error;
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::Json;
use rocket::{post, routes, Request, State};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::ops::Add;
use std::str::FromStr;

pub(crate) fn generate_password_hash(password: &[u8]) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    Ok(argon2.hash_password(password, &salt)?.to_string())
}

fn generate_token(user: &User, password: &str, secret_key: impl ToString) -> Option<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret_key.to_string().as_bytes()).unwrap();
    let mut claims = std::collections::BTreeMap::new();
    claims.insert("creation", Utc::now().to_string());
    // Validity: 12h
    claims.insert(
        "valid_until",
        Utc::now().add(TimeDelta::hours(12)).to_string(),
    );
    claims.insert("validity_duration", "12".to_string());
    claims.insert("email", user.email.clone());
    // claims.insert("password", password.to_string());
    claims.insert("user_id", user.id.clone());

    match claims.sign_with_key(&key) {
        Ok(token) => Some(token),
        Err(e) => {
            error!("Failed to generate token: {}", e);
            None
        }
    }
}

#[derive(Deserialize, Debug)]
pub(crate) struct Login {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Debug)]
struct LoginOkResult {
    token: String,
}

#[post("/login", format = "application/json", data = "<login>")]
async fn login_route(
    login: Json<Login>,
    db: Connection<Db>,
    config: &State<AppConfig>,
) -> Result<Json<LoginOkResult>, Status> {
    match User::login(&login.0, db).await {
        Some(user) => {
            let token = generate_token(&user, &config.auth.secret_key, &config.auth.secret_key);
            if token.is_none() {
                return Err(Status::InternalServerError);
            }
            let token = token.unwrap();

            Ok(Json(LoginOkResult { token }))
        }
        None => Err(Status::Unauthorized),
    }
}

// ==================================
//
//      SIGNUP
//
// ==================================

#[derive(Deserialize, Debug)]
pub(crate) struct Signup {
    pub first_name: String,
    pub last_name: Option<String>,

    pub password: String,
    pub email: String,
}

#[derive(Serialize, Debug)]
struct SignupOkResult {
    token: String,
}


#[post("/signup", format = "application/json", data = "<signup>")]
async fn signup_route(
    signup: Json<Signup>,
    db: Connection<Db>,
    config: &State<AppConfig>,
) -> Result<Json<SignupOkResult>, (Status, Json<ApiResponse>)> {
    // We'll hash the password first
    let hashed_password =
        generate_password_hash(signup.password.as_bytes()).map_err(|e| { // Use signup.password
            error!(target: "Signup", "Failed to generate password hash: {}", e.to_string());
            (Status::InternalServerError, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))
        })?;

    let user = User {
        id: String::new(),
        first_name: signup.first_name.clone(),
        last_name: signup.last_name.clone(),

        password: hashed_password.clone(),
        email: signup.email.clone(),
    };

    // Register user
    let user = User::create(&user, db).await.map_err(|e| {
        error!(target: "Signup", "Failed to create user: {}", e.to_string());
        (Status::Unauthorized, create_error_response(ApiResponseCode::HubCannotSignup, "Cannot create an account"))
    })?;

    let token = generate_token(&user, config.auth.secret_key.as_str(), config.auth.secret_key.as_str());

    match token {
        Some(token) => Ok(Json(SignupOkResult { token })),
        None => Err((Status::Unauthorized, create_error_response(ApiResponseCode::InternalError, "An internal error occurred"))),
    }
}

#[derive(Debug)]
pub struct Authorization {
    pub user: User,
    pub creation: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// The duration of the validity, in hours
    pub validity_duration: u32,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorization {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = req.headers().get_one("Authorization");

        let auth_header = match auth_header {
            Some(header) => header,
            None => return Outcome::Forward(Status::Unauthorized),
        };

        let parts: Vec<&str> = auth_header.split(' ').collect();

        if parts.len() != 2 || parts[0] != "Bearer" {
            return Outcome::Forward(Status::Unauthorized);
        }

        let token = parts[1];

        let config = match req.guard::<&State<AppConfig>>().await.succeeded() {
            Some(c) => c,
            None => return Outcome::Forward(Status::InternalServerError),
        };

        let key: Hmac<Sha256> = match Hmac::new_from_slice(config.auth.secret_key.as_bytes()) {
            Ok(key) => key,
            Err(e) => {
                error!("Invalid secret key for HMAC: {}", e);
                return Outcome::Forward(Status::InternalServerError);
            }
        };

        let claims: std::collections::BTreeMap<String, String> = match token.verify_with_key(&key) {
            Ok(claims) => claims,
            Err(e) => {
                error!("Failed to verify token or decode claims: {}", e);
                return Outcome::Forward(Status::Unauthorized);
            }
        };

        let user_id = claims.get("user_id").cloned().unwrap_or("UNKNOWN".into());
        // let email = claims.get("email").cloned().unwrap_or("UNKNOWN".into());

        let validity_duration = u32::from_str(
            &claims
                .get("validity_duration")
                .cloned()
                .unwrap_or("UNKNOWN".into()),
        )
            .unwrap_or(0);
        let creation_str = claims.get("creation").cloned().unwrap_or("UNKNOWN".into());
        let creation =
            DateTime::<Utc>::from_str(&creation_str)
                .unwrap_or_else(|e| {
                    error!("Failed to parse creation timestamp from token: {}", e);
                    Utc::now()
                });


        let mut db = match req.guard::<Connection<Db>>().await.succeeded() {
            Some(db) => db,
            None => return Outcome::Forward(Status::InternalServerError),
        };

        let user_from_db = match User::get_by_id(&user_id, &mut **db).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Outcome::Forward(Status::Unauthorized);
            }
            Err(e) => {
                error!("Failed to fetch user from database: {}", e);
                return Outcome::Forward(Status::InternalServerError);
            }
        };

        let valid_until_calc = creation.add(TimeDelta::hours(validity_duration as i64));
        if valid_until_calc < Utc::now() {
            error!("Expired token for user: {}", user_from_db.email);
            return Outcome::Forward(Status::Unauthorized);
        }

        Outcome::Success(Authorization {
            user: user_from_db,
            validity_duration,
            creation,
            valid_until: valid_until_calc,
        })
    }
}

pub fn get_routes() -> Vec<rocket::Route> {
    routes![login_route, signup_route]
}
