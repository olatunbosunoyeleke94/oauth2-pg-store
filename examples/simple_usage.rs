use oauth2_pg_store::{PgTokenStore, OAuth2TokenStore};
use oauth2::{
    AccessToken, basic::BasicTokenType, EmptyExtraTokenFields, Scope, StandardTokenResponse,
};
use sqlx::PgPool;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (e.g. postgres://user:pass@localhost/db)");

    let pool = PgPool::connect(&database_url).await?;
    let store = PgTokenStore::new(pool);

    // Simulate storing a token
    let token = AccessToken::new("example_token_abc123".to_string());
    let scopes = vec![Scope::new("api:read".to_string())];

    let mut token_response = StandardTokenResponse::new(
        token.clone(),
        BasicTokenType::Bearer,
        EmptyExtraTokenFields {},
    );

    // Fixed: borrow the Duration with &
    token_response.set_expires_in(Some(&std::time::Duration::from_secs(7200)));

    store.store_token(&token_response, "my-app", None, &scopes).await?;

    // Lookup
    if let Some(found) = store.get_by_access_token(&token).await? {
        println!("Found token:");
        println!("  client_id: {}", found.client_id);
        println!("  scopes:    {:?}", found.scopes);
        println!("  expires_at: {:?}", found.expires_at);
        println!("  revoked:   {}", found.revoked);
    } else {
        println!("Token not found");
    }

    Ok(())
}
