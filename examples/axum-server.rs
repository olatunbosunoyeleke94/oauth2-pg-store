use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use oauth2_pg_store::{OAuth2TokenStore, PgTokenStore};
use oauth2::{
    AccessToken,
    basic::BasicTokenType,
    EmptyExtraTokenFields,
    RefreshToken,
    Scope,
    StandardTokenResponse,
};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: Arc<PgTokenStore>,
}

/* -----------------------------
   Response Types (Better than json! macros)
------------------------------*/

#[derive(Serialize)]
struct StoreTokenResponse {
    message: String,
    access_token: String,
    refresh_token: String,
    client_id: String,
    user_id: Option<Uuid>,
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct GetTokenResponse {
    client_id: String,
    user_id: Option<Uuid>,
    scopes: Vec<String>,
    issued_at: String,
    expires_at: Option<String>,
    revoked: bool,
}

/* -----------------------------
   Handlers
------------------------------*/

async fn store_token(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let access_token_str = Uuid::new_v4().to_string();
    let refresh_token_str = Uuid::new_v4().to_string();

    let mut token_response = StandardTokenResponse::new(
        AccessToken::new(access_token_str.clone()),
        BasicTokenType::Bearer,
        EmptyExtraTokenFields {},
    );

    token_response.set_expires_in(Some(&Duration::from_secs(7200)));
    token_response.set_refresh_token(Some(RefreshToken::new(refresh_token_str.clone())));

    let scopes = vec![
        Scope::new("read".to_string()),
        Scope::new("write".to_string()),
    ];

    let client_id = "example-client";
    let user_id = Some(Uuid::new_v4());

    if let Err(e) = state.store
        .store_token(&token_response, client_id, user_id, &scopes)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to store token: {}", e),
        ).into_response();
    }

    let response = StoreTokenResponse {
        message: "Token stored".into(),
        access_token: access_token_str,
        refresh_token: refresh_token_str,
        client_id: client_id.into(),
        user_id,
        scopes: scopes.iter().map(|s| s.as_str().to_string()).collect(),
    };

    Json(response).into_response()
}

async fn get_token(
    State(state): State<AppState>,
    Path(access_token): Path<String>,
) -> impl IntoResponse {
    let token = AccessToken::new(access_token);

    match state.store.get_by_access_token(&token).await {
        Ok(Some(found)) => {
            let response = GetTokenResponse {
                client_id: found.client_id,
                user_id: found.user_id,
                scopes: found.scopes,
                issued_at: found.issued_at.to_rfc3339(),
                expires_at: found.expires_at.map(|t| t.to_rfc3339()),
                revoked: found.revoked,
            };

            Json(response).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Token not found").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {}", e),
        ).into_response(),
    }
}

/* -----------------------------
   Main
------------------------------*/

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/testdb".into());

    let pool = PgPool::connect(&database_url).await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    let store = PgTokenStore::new(pool);
    let state = AppState {
        store: Arc::new(store),
    };

    let app = Router::new()
        .route("/tokens", post(store_token))
        .route("/tokens/:access_token", get(get_token))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server listening on http://0.0.0.0:3000");

    axum::serve(listener, app).await?;

    Ok(())
}
