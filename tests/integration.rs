#[cfg(test)]
mod tests {
    use oauth2_pg_store::{OAuth2TokenStore, PgTokenStore};
    use oauth2::{
        AccessToken,
        basic::BasicTokenType,
        EmptyExtraTokenFields,
        RefreshToken,
        Scope,
        StandardTokenResponse,
    };
    use sqlx::PgPool;
    use testcontainers::core::{ImageExt, IntoContainerPort};
    use testcontainers::{ContainerAsync, GenericImage};
    use testcontainers::runners::AsyncRunner;
    use uuid::Uuid;
    use std::time::Duration;
    use tokio::net::TcpStream;

    async fn setup_test_db() -> (PgPool, ContainerAsync<GenericImage>) {
        let container: ContainerAsync<GenericImage> = GenericImage::new("postgres", "16-alpine")
            .with_exposed_port(5432.tcp())
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_DB", "testdb")
            .start()
            .await
            .expect("Failed to start Postgres container");

        let host = "localhost".to_string();
        let port = container.get_host_port_ipv4(5432).await.expect("No port mapping");

        // Wait for TCP port open
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if TcpStream::connect(format!("{host}:{port}")).await.is_ok() {
                println!("TCP port {port} is open");
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("TCP port never opened after 60s");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Fixed delay for Postgres startup
        println!("Port open — waiting 15s for Postgres to be ready...");
        tokio::time::sleep(Duration::from_secs(15)).await;

        // Retry sqlx connect
        let database_url = format!("postgres://postgres:postgres@{host}:{port}?sslmode=disable");
        let mut pool: Option<PgPool> = None;
        for attempt in 1..=20 {
            match PgPool::connect(&database_url).await {
                Ok(p) => {
                    pool = Some(p);
                    println!("sqlx connected after attempt {}", attempt);
                    break;
                }
                Err(e) => {
                    println!("sqlx connect attempt {} failed: {}", attempt, e);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }

        let pool = pool.expect("Failed to connect sqlx pool after 20 attempts");

        println!("Running migrations...");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Migrations failed");

        println!("Setup complete — running test");

        (pool, container)
    }

    #[tokio::test]
    async fn test_store_and_retrieve_token() -> Result<(), Box<dyn std::error::Error>> {
        let (pool, _container) = setup_test_db().await;
        let store = PgTokenStore::new(pool);

        let access_token_str = Uuid::new_v4().to_string();
        let refresh_token_str = Uuid::new_v4().to_string();

        let mut token_response = StandardTokenResponse::new(
            AccessToken::new(access_token_str.clone()),
            BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );

        token_response.set_expires_in(Some(&Duration::from_secs(7200)));
        token_response.set_refresh_token(Some(RefreshToken::new(refresh_token_str)));

        let scopes = vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ];

        let user_id = Uuid::new_v4();

        store
            .store_token(&token_response, "test-app", Some(user_id), &scopes)
            .await?;

        let found = store
            .get_by_access_token(&AccessToken::new(access_token_str.clone()))
            .await?
            .expect("Token should be found");

        assert_eq!(found.client_id, "test-app");
        assert_eq!(found.user_id, Some(user_id));
        assert_eq!(found.scopes.len(), 2);
        assert!(!found.revoked);
        assert!(found.expires_at.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_revoke_by_access_token() -> Result<(), Box<dyn std::error::Error>> {
        let (pool, _container) = setup_test_db().await;
        let store = PgTokenStore::new(pool);

        let access_token_str = Uuid::new_v4().to_string();
        let token = AccessToken::new(access_token_str.clone());

        let mut token_response = StandardTokenResponse::new(
            token.clone(),
            BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );
        token_response.set_expires_in(Some(&Duration::from_secs(3600)));

        store
            .store_token(&token_response, "revoke-test", None, &[])
            .await?;

        store.revoke_by_access_token(&token).await?;

        let found = store.get_by_access_token(&token).await?;
        assert!(found.is_none(), "Revoked token should not be returned");

        Ok(())
    }

    #[tokio::test]
    async fn test_cleanup_removes_expired_tokens() -> Result<(), Box<dyn std::error::Error>> {
        let (pool, _container) = setup_test_db().await;
        let store = PgTokenStore::new(pool);

        let access_token_str = Uuid::new_v4().to_string();
        let token = AccessToken::new(access_token_str.clone());

        let mut token_response = StandardTokenResponse::new(
            token.clone(),
            BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );

        token_response.set_expires_in(Some(&Duration::from_millis(300)));

        store
            .store_token(&token_response, "cleanup-test", None, &[])
            .await?;

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let removed = store.cleanup().await?;
        assert!(removed >= 1, "Should have removed at least one expired token");

        let found = store.get_by_access_token(&token).await?;
        assert!(found.is_none(), "Expired token should be cleaned up");

        Ok(())
    }

    #[tokio::test]
    async fn test_revoke_by_refresh_token() -> Result<(), Box<dyn std::error::Error>> {
        let (pool, _container) = setup_test_db().await;
        let store = PgTokenStore::new(pool);

        let refresh_token_str = Uuid::new_v4().to_string();
        let refresh = RefreshToken::new(refresh_token_str.clone());

        let access_token_str = Uuid::new_v4().to_string();

        let mut token_response = StandardTokenResponse::new(
            AccessToken::new(access_token_str.clone()),
            BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );
        token_response.set_refresh_token(Some(refresh.clone()));

        store
            .store_token(&token_response, "refresh-test", None, &[])
            .await?;

        store.revoke_by_refresh_token(&refresh).await?;

        let found = store
            .get_by_access_token(&AccessToken::new(access_token_str))
            .await?;
        assert!(found.is_none(), "Token should be revoked via refresh token");

        Ok(())
    }

    #[tokio::test]
    async fn test_get_non_existent_token() -> Result<(), Box<dyn std::error::Error>> {
        let (pool, _container) = setup_test_db().await;
        let store = PgTokenStore::new(pool);

        let token = AccessToken::new(Uuid::new_v4().to_string());

        let found = store.get_by_access_token(&token).await?;

        assert!(found.is_none(), "Non-existent token should return None");

        Ok(())
    }
}
