//! Postgres-backed persistent storage for OAuth2 tokens.
//!
//! This crate provides a secure, async token store using PostgreSQL via `sqlx`.
//! Tokens are **never stored in plaintext** — they're hashed with BLAKE3 before insertion.
//! Designed to work alongside the `oauth2` crate when building an OAuth2 authorization server
//! or token introspection endpoint.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicTokenType,
    AccessToken, EmptyExtraTokenFields, RefreshToken, Scope,
    StandardTokenResponse, TokenResponse,
};
use sqlx::{PgPool, FromRow};
use thiserror::Error;
use uuid::Uuid;

/// Main error type for this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("token not found")]
    NotFound,

    #[error("token expired or revoked")]
    InvalidToken,

    #[error("hashing error: {0}")]
    Hashing(String),

    #[error("other error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// A stored token record (what you get back when looking up by token).
#[derive(Debug, Clone, FromRow)]
pub struct StoredToken {
    pub id: Uuid,
    pub access_token_hash: String,
    pub refresh_token_hash: Option<String>,
    pub client_id: String,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// Abstract trait for token storage backends.
#[async_trait]
pub trait OAuth2TokenStore: Send + Sync + 'static {
    /// Store a newly issued token response.
    async fn store_token(
        &self,
        token: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        client_id: &str,
        user_id: Option<Uuid>,
        scopes: &[Scope],
    ) -> Result<(), Error>;

    /// Look up token metadata by access token value.
    async fn get_by_access_token(&self, token: &AccessToken) -> Result<Option<StoredToken>, Error>;

    /// Look up by refresh token (if present).
    async fn get_by_refresh_token(&self, token: &RefreshToken) -> Result<Option<StoredToken>, Error>;

    /// Mark a token as revoked by its access token value.
    async fn revoke_by_access_token(&self, token: &AccessToken) -> Result<(), Error>;

    /// Mark revoked by refresh token.
    async fn revoke_by_refresh_token(&self, token: &RefreshToken) -> Result<(), Error>;

    /// Remove expired/revoked tokens (run periodically via cron/job).
    async fn cleanup(&self) -> Result<usize, Error>;
}

/// Concrete Postgres implementation using `sqlx`.
#[derive(Clone)]
pub struct PgTokenStore {
    pool: PgPool,
}

impl PgTokenStore {
    /// Create a new store connected to the given Postgres pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Hash a token value before storing/lookup using BLAKE3 (deterministic, fast, cryptographically secure).
    fn hash_token(&self, token: &str) -> Result<String, Error> {
        use blake3;
        use hex;

        let hash = blake3::hash(token.as_bytes());
        Ok(hex::encode(hash.as_bytes()))
    }
}

#[async_trait]
impl OAuth2TokenStore for PgTokenStore {
    async fn store_token(
        &self,
        token: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        client_id: &str,
        user_id: Option<Uuid>,
        scopes: &[Scope],
    ) -> Result<(), Error> {
        let access_hash = self.hash_token(token.access_token().secret())?;

        let refresh_hash = token
            .refresh_token()
            .map(|r: &RefreshToken| self.hash_token(r.secret()))
            .transpose()?;

        let scopes_str: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();

        let expires_at = token
            .expires_in()
            .map(|d| Utc::now() + d);

        sqlx::query!(
            r#"
            INSERT INTO oauth2_tokens (
                access_token_hash,
                refresh_token_hash,
                client_id,
                user_id,
                scopes,
                issued_at,
                expires_at,
                revoked
            ) VALUES ($1, $2, $3, $4, $5, NOW(), $6, FALSE)
            "#,
            access_hash,
            refresh_hash,
            client_id,
            user_id,
            &scopes_str,
            expires_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_by_access_token(&self, token: &AccessToken) -> Result<Option<StoredToken>, Error> {
        let hash = self.hash_token(token.secret())?;

        let row = sqlx::query_as!(
            StoredToken,
            r#"
            SELECT * FROM oauth2_tokens
            WHERE access_token_hash = $1
              AND NOT revoked
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
            hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_refresh_token(&self, token: &RefreshToken) -> Result<Option<StoredToken>, Error> {
        let hash = self.hash_token(token.secret())?;

        let row = sqlx::query_as!(
            StoredToken,
            r#"
            SELECT * FROM oauth2_tokens
            WHERE refresh_token_hash = $1
              AND NOT revoked
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
            hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn revoke_by_access_token(&self, token: &AccessToken) -> Result<(), Error> {
        let hash = self.hash_token(token.secret())?;

        let res = sqlx::query!(
            r#"
            UPDATE oauth2_tokens
            SET revoked = TRUE
            WHERE access_token_hash = $1
            "#,
            hash
        )
        .execute(&self.pool)
        .await?;

        if res.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        Ok(())
    }

    async fn revoke_by_refresh_token(&self, token: &RefreshToken) -> Result<(), Error> {
        let hash = self.hash_token(token.secret())?;

        let res = sqlx::query!(
            r#"
            UPDATE oauth2_tokens
            SET revoked = TRUE
            WHERE refresh_token_hash = $1
            "#,
            hash
        )
        .execute(&self.pool)
        .await?;

        if res.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        Ok(())
    }

    async fn cleanup(&self) -> Result<usize, Error> {
        let res = sqlx::query!(
            r#"
            DELETE FROM oauth2_tokens
            WHERE revoked = TRUE
               OR (expires_at IS NOT NULL AND expires_at < NOW())
            "#
        )
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected() as usize)
    }
}
