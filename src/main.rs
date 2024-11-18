#[macro_use]
extern crate diesel;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, Error};
use actix_web::http::StatusCode;
use log::error;
use env_logger;
use std::fmt;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use bcrypt::{hash, DEFAULT_COST};
use actix_web::web::Data;
use dotenv::dotenv;

mod models;
use crate::models::{User, UserInput};

mod schema;
use schema::users;

#[derive(Debug)]
struct CustomError {
    message: String,
    status_code: StatusCode,
}

impl CustomError {
    fn new(message: &str, status_code: StatusCode) -> CustomError {
        CustomError {
            message: message.to_string(),
            status_code
        }
    }
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl actix_web::ResponseError for CustomError {
    fn status_code(&self) -> StatusCode {
        self.status_code
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.message.clone())
    }
}

async fn hola() -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok().body("Hola :wave:"))
}


async fn all_hail(name: web::Path<String>) -> Result<impl Responder, Error> {
    if name.is_empty() {
        let err = CustomError::new("Name is required", StatusCode::BAD_REQUEST);
        error!("Error occured: {}", err);
        return Err(err.into());
    }

    let response = format!("All hail, {}!", name);
    Ok(HttpResponse::Ok().body(response))
}

async fn divide_numbers(params: web::Query<(i32, i32)>) -> Result<impl Responder, Error> {
    let (a, b) = *params;

    if b == 0 {
        let err = CustomError::new("Cannot divide by zero", StatusCode::BAD_REQUEST);
        error!("Error occured: {}", err);
        return Err(err.into());
    }

    let result = a / b;
    Ok(HttpResponse::Ok().body(format!("{} / {} = {}", a, b, result)))
}

// async fn error_demo() -> Result<impl Responder, Error> {
//     let err = CustomError::new("This is a demonstration of an intentional error", StatusCode::INTERNAL_SERVER_ERROR);
//     error!("Intentional error: {}", err);
//     Err::<T, actix_web::Error>(err.into())
// }

async fn hash_password(password: web::Json<String>) -> Result<impl Responder, Error> {
    match hash(&*password, DEFAULT_COST) {
        Ok(hashed_password) => Ok(HttpResponse::Ok().body(format!("Hashed password: {}", hashed_password))),
        Err(e) => {
            let err = CustomError::new(&format!("Failed to hash password: {}", e), StatusCode::INTERNAL_SERVER_ERROR);
            error!("Error occurred: {}", err);
            Err(err.into())
        }
    }
}

async fn create_user(pool: web::Data<r2d2::Pool<ConnectionManager<PgConnection>>>, user_data: web::Json<UserInput>) -> Result<impl Responder, Error> {
    let conn = pool.get().map_err(|_| CustomError::new("Failed to get database connection", StatusCode::INTERNAL_SERVER_ERROR))?;
    let user_data = user_data.into_inner();
    let hashed_password = hash(&user_data.password, DEFAULT_COST).map_err(|e| CustomError::new(&format!("Failed to hash password: {}", e), StatusCode::INTERNAL_SERVER_ERROR))?;

    let new_user = User {
        id: 0, // Will be handled by the database as an auto-increment value.
        password: hashed_password,
        created_at: Some(chrono::Local::now().naive_local()),
        name: user_data.name,
        email: user_data.email,
        username: user_data.username,
    };

    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&conn)
        .map_err(|e| CustomError::new(&format!("Failed to insert user: {}", e), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(HttpResponse::Ok().body("User created successfully"))
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder().build(manager).expect("Failed to create pool.");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .route("/", web::get().to(hola))
            .route("/all-hail/{name}", web::get().to(all_hail))
            .route("/divide", web::get().to(divide_numbers))
            // .route("/error-demo", web::get().to(error_demo))
            .route("/hash_password", web::post().to(hash_password))
            .route("/create_user", web::post().to(create_user))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
