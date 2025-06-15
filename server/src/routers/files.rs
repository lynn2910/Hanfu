use crate::routers::authorization::Authorization;
use rocket::{get, routes};

#[get("/<path..>")]
pub async fn get_file(
    path: &str,
    user: Authorization,
) {}

pub fn get_routes() -> Vec<rocket::Route> {
    routes![get_file]
}
