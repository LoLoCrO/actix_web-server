// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Int4,
        name -> Varchar,
        email -> Varchar,
        username -> Varchar,
        password -> Varchar,
        created_at -> Nullable<Timestamp>,
    }
}
