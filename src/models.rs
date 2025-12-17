use serde::{Deserialize, Serialize};

// Struktur untuk data user yang diambil dari database
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
}

// Struktur untuk payload permintaan register/login
#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

// Struktur untuk claims JWT
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32, // User ID (Subject)
    pub username: String,
    pub exp: i64, // Expiration time
    // ... claims lainnya
}

// Struktur untuk respons sukses
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub message: String,
    pub token: Option<String>,
}