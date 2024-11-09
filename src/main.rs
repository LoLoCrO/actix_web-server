use actix_web::{web, App, HttpResponse, HttpServer, Responder, Error};
use actix_web::http::StatusCode;
use log::error;
use env_logger;
use std::fmt;

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
    // explain datatypes in the next line
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(hola))
            .route("/all-hail/{name}", web::get().to(all_hail))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
