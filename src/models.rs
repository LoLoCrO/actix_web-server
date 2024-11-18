use crate::schema::users;

use diesel::Queryable;
use diesel::Insertable;

use serde_derive::{Deserialize, Serialize};

#[derive(Queryable, Insertable, Debug, Deserialize, Serialize)]
#[table_name = "users"]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub created_at: Option<chrono::NaiveDateTime>,
}

#[derive(Deserialize)]
pub struct UserInput {
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
}