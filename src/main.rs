mod models;
mod handlers;
mod jwt;

use crate::models::Claims; // Sesuaikan 'ax_auth_api' dengan nama package di Cargo.toml Anda
use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    routing::{get, post},
    RequestPartsExt, Router,
};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};

// --- MIDDLEWARE / EXTRACTOR JWT ---
// Ini berfungsi untuk melindungi rute. Jika header Authorization tidak valid,
// rute akan otomatis mengembalikan 401 Unauthorized.
struct AuthUser(Claims);

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Ekstrak token dari header "Authorization: Bearer <TOKEN>"
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // Validasi token
        let claims = jwt::validate_jwt(bearer.token())
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthUser(claims))
    }
}

// --- MAIN FUNCTION ---
#[tokio::main]
async fn main() {
    // 1. Muat variabel lingkungan dari .env
    dotenv().ok();

    // 2. Inisialisasi Database Pool
   // let database_url = std::env::var("DATABASE_URL")
      //  .expect("DATABASE_URL must be set in .env");

    let database_url = "postgres://postgres:P@ssw0rd@localhost:5432/FDS";

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Gagal terhubung ke database PostgreSQL");

    // 3. Bangun Router
    let app = Router::new()
        // Rute Publik
        .route("/register", post(handlers::register))
        .route("/login", post(handlers::login))
        // Rute Terproteksi (Hanya bisa diakses jika mengirim JWT valid)
        .route("/protected", get(protected_handler))
        .with_state(pool);

    // 4. Jalankan Server menggunakan TcpListener (Axum v0.7 style)
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    
    println!("🚀 Server berjalan di http://{}", addr);
    
    axum::serve(listener, app)
        .await
        .unwrap();
}

// --- HANDLER UNTUK RUTE TERPROTEKSI ---
async fn protected_handler(AuthUser(claims): AuthUser) -> String {
    format!(
        "Halo {}, ID Anda adalah {}. Anda berhasil mengakses rute rahasia!",
        claims.username, claims.sub
    )
}