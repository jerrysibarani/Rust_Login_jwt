use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use chrono::{Utc, Duration};
use crate::models::{Claims};
use std::env;

// Fungsi untuk membuat JWT
pub fn create_jwt(user_id: i32, username: String) -> Result<String, jsonwebtoken::errors::Error> {
    // Ambil secret dari env
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let key = EncodingKey::from_secret(secret.as_ref());

    // Atur waktu kedaluwarsa (misalnya 1 jam)
    let expiration = Utc::now() + Duration::hours(1);

    let claims = Claims {
        sub: user_id,
        username,
        exp: expiration.timestamp(),
    };

    encode(&Header::default(), &claims, &key)
}

// Fungsi untuk memvalidasi JWT
pub fn validate_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::default();

    decode::<Claims>(token, &key, &validation).map(|data| data.claims)
}