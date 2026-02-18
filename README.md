# oauth2-pg-store

**PostgreSQL-backed persistent storage for OAuth2 tokens (async, secure, production-ready).**

`oauth2-pg-store` provides a database-backed implementation of an OAuth2 token store designed to work with the `oauth2` crate when building:

* Authorization Servers
* Resource Servers (token introspection / validation)
* API Gateways
* SaaS authentication layers
* Microservice identity systems

It is built with **Tokio + SQLx** and designed for **high-assurance environments** where tokens must never be stored in plaintext.

---

## ✨ Features

* ✅ Async-first (`tokio`)
* ✅ PostgreSQL-backed via `sqlx`
* ✅ No plaintext token storage
* ✅ Deterministic token hashing using **BLAKE3**
* ✅ Access + Refresh token support
* ✅ Revocation support
* ✅ Expiration enforcement at query level
* ✅ Cleanup of stale tokens
* ✅ Works directly with `oauth2::StandardTokenResponse`
* ✅ Horizontal-scale friendly (stateless services)
* ✅ No ORM — predictable SQL behavior

---

## 🔐 Security Model

**Tokens are NEVER stored directly.**

```
Issued Token → Hashed (BLAKE3) → Stored in Postgres
```

If your database is compromised:

* Attackers **cannot impersonate users**
* Tokens cannot be reconstructed
* Lookups remain fast and indexable

Why BLAKE3?

* Cryptographically secure
* Extremely fast (ideal for API validation paths)
* Fixed-length deterministic output (great for indexing)
* OAuth2 tokens already contain high entropy → no salt required

---

## 📦 Installation

Add to your `Cargo.toml`:

```toml
oauth2-pg-store = "0.1"

sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "uuid", "chrono", "migrate"] }
tokio = { version = "1", features = ["full"] }
```

---

## 🗄 Database Schema

Create the table using SQLx migrations:

```sql
CREATE TABLE oauth2_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT,

    client_id TEXT NOT NULL,
    user_id UUID,

    scopes TEXT[] NOT NULL,

    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_oauth2_access_hash ON oauth2_tokens(access_token_hash);
CREATE INDEX idx_oauth2_refresh_hash ON oauth2_tokens(refresh_token_hash);
CREATE INDEX idx_oauth2_expires_at ON oauth2_tokens(expires_at);
```

---

## 🚀 Quick Start

### Create the Store

```rust
use oauth2_pg_store::PgTokenStore;
use sqlx::PgPool;

let pool = PgPool::connect(&database_url).await?;
let store = PgTokenStore::new(pool);
```

---

### Store a Token

```rust
store.store_token(
    &token_response,
    "client-id",
    Some(user_id),
    &scopes
).await?;
```

---

### Validate an Access Token

```rust
if let Some(token) = store.get_by_access_token(&access_token).await? {
    println!("Token valid for client {}", token.client_id);
}
```

---

### Revoke a Token

```rust
store.revoke_by_access_token(&access_token).await?;
```

---

### Cleanup Expired / Revoked Tokens

```rust
let deleted = store.cleanup().await?;
println!("Removed {} expired tokens", deleted);
```

Run periodically using a background job or cron.

---

## ▶️ Running the Example Server (Axum Demo)

A full working example is included demonstrating how to integrate the store into a web service.

---

### 1️⃣ Set Your Database URL

Ensure PostgreSQL is running:

```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/yourdb"
```

---

### 2️⃣ Run Database Migrations

```bash
sqlx migrate run
```

---

### 3️⃣ Start the Example Server

```bash
cargo run --example axum-server
```

Server starts at:

```
http://localhost:3000
```

---

### 4️⃣ Issue a Token

```bash
curl -X POST http://localhost:3000/tokens
```

Example response:

```json
{
  "message": "Token stored",
  "access_token": "9f1c6f7e-...",
  "refresh_token": "52a8f8d1-...",
  "client_id": "example-client",
  "user_id": "d3c7...",
  "scopes": ["read", "write"]
}
```

---

### 5️⃣ Retrieve Token Metadata

```bash
curl http://localhost:3000/tokens/YOUR_ACCESS_TOKEN_HERE
```

Returns token metadata if valid and not revoked/expired.

---

## 🐳 Optional: Using Docker for Testing

**Docker is NOT required to run this crate.**

The library and example server work with any PostgreSQL instance (local, cloud, etc.).

However, the dev environment can optionally use `testcontainers`
to spin up an ephemeral PostgreSQL database during integration testing.

### Only Needed If You Want Reproducible Tests

Requirements:

* Docker installed
* Docker daemon running

Then tests can automatically provision Postgres:

```bash
cargo test
```

This is useful for CI pipelines and isolated environments,
but completely optional for normal development or production.

---

## 🔄 Intended OAuth2 Integration Model

This crate does **not issue tokens** — it stores and validates them.

```
OAuth2 protocol handled by `oauth2` crate
            ↓
Your server generates token response
            ↓
oauth2-pg-store persists hashed token
            ↓
APIs validate tokens using this store
```

This keeps protocol logic separate from persistence and scaling concerns.

---

## 🧰 Example Use Cases

* Self-hosted identity providers
* Fintech authentication layers
* Internal microservice authorization
* API gateway token validation
* Machine-to-machine OAuth2 systems

---

## ⚙️ Design Goals

| Goal               | Approach                  |
| ------------------ | ------------------------- |
| Stateless services | DB-backed validation      |
| Horizontal scaling | No in-memory sessions     |
| Security           | Hashed tokens only        |
| Performance        | BLAKE3 + indexed lookups  |
| Predictability     | Raw SQL via SQLx          |
| Interoperability   | Works with `oauth2` crate |

---

## 📌 Non-Goals

This crate intentionally does **NOT**:

* Implement OAuth2 flows
* Authenticate users
* Issue JWTs
* Act as a full identity provider

It is strictly a **secure persistence + validation layer**.

---

## 🛣 Roadmap

* RFC 7662 Token Introspection helper
* Optional Redis cache layer
* Partitioning strategies for large deployments
* Observability hooks
* Audit logging extensions

---

## 📄 License

MIT
