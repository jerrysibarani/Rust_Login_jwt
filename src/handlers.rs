use axum::{
    extract::{State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use sqlx::PgPool;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};
use crate::{
    models::{AuthPayload, AuthResponse, User},
    jwt,
};

// Handler untuk registrasi user baru
pub async fn register(
    State(pool): State<PgPool>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // 1. Hash Password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    // 2. Simpan ke Database
    let result = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
        payload.username,
        password_hash
    )
    .fetch_one(&pool)
    .await;

    match result {
        Ok(_) => Ok(Json(AuthResponse {
            message: "User registered successfully".to_string(),
            token: None,
        })),
        Err(sqlx::Error::Database(err)) if err.is_unique_violation() => {
            Err(StatusCode::CONFLICT) // Username sudah ada
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Handler untuk login
pub async fn login(
    State(pool): State<PgPool>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // 1. Ambil user dari database
    let user = sqlx::query_as!(
        User,
        "SELECT id, username, password_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?; // User tidak ditemukan

    // 2. Verifikasi Password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let argon2 = Argon2::default();
    
    // Verifikasi password
    if argon2.verify_password(payload.password.as_bytes(), &parsed_hash).is_err() {
        return Err(StatusCode::UNAUTHORIZED); // Password salah
    }

    // 3. Buat JWT
    let token = jwt::create_jwt(user.id, user.username)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 4. Kirim response
    Ok(Json(AuthResponse {
        message: "Login successful".to_string(),
        token: Some(token),
    }))
}

// Contoh handler yang dilindungi oleh JWT
pub async fn protected_route(
    // State, atau User yang sudah di-extract dari JWT, bisa ditambahkan di sini
) -> impl IntoResponse {
    (StatusCode::OK, "Anda telah mengakses rute yang dilindungi!")
}