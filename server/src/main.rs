use rocket::{get, launch, routes};

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
}

#[get("/")]
fn index() -> &'static str {
    "Hello World!"
}