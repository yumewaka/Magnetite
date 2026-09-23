//! `magnetite-sso` — the embedded OpenID Connect issuer (Magnetite as the IdP).
//! Registered OAuth clients run the Authorization Code + PKCE flow against these
//! endpoints, mounted on the main HTTP server at `issuer` (= `server.base_url`):
//!
//! * `GET  /.well-known/openid-configuration` — discovery
//! * `GET  /oidc/jwks`      — JSON Web Key Set (RS256 public key)
//! * `GET  /oidc/authorize` — authenticates the end user via the portal session
//!   cookie and issues a single-use authorization code
//! * `POST /oidc/token`     — exchanges the code (client auth + PKCE) for a
//!   signed `id_token` + `access_token`, and records an `SsoSession`
//! * `GET  /oidc/userinfo`  — returns claims for a bearer access token
//!
//! The RS256 signing key is persisted in the DB (PKCS#8 PEM) and reloaded at
//! startup, so the JWKS stays stable across restarts. [`SsoState::rotate`]
//! installs a fresh signer while keeping the previous key published for a grace
//! window so its tokens keep verifying. Deferred: a consent screen, refresh
//! tokens, `login`-redirect round-trip for unauthenticated `/authorize`, and
//! dynamic client registration.

mod endpoints;
mod keys;

use axum::routing::{get, post};
use axum::Router;
use keys::{Keyring, SigningKey};
use magnetite_db::Db;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// Lifetime of an authorization code before it expires (RFC 6749 §4.1.2 advises
/// a short window; codes are single-use).
const CODE_TTL_SECS: i64 = 60;
/// Issued token lifetime.
pub(crate) const TOKEN_TTL_SECS: i64 = 3600;
/// How long a retired key stays published after rotation. Comfortably longer
/// than [`TOKEN_TTL_SECS`], so every token it signed has expired before it is
/// pruned from the JWKS.
const RETIRED_KEY_GRACE_SECS: i64 = 24 * 3600;

/// Mint a fresh, unique key id for a signing key.
fn new_kid() -> String {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("magnetite-oidc-{}", hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// A pending authorization code awaiting exchange at the token endpoint.
#[derive(Clone)]
pub(crate) struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub scope: String,
    pub nonce: Option<String>,
    /// PKCE `code_challenge` (S256).
    pub code_challenge: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Shared state for the OIDC endpoints.
#[derive(Clone)]
pub struct SsoState {
    pub(crate) db: Db,
    pub(crate) issuer: String,
    /// The active signer plus retired verifiers. Guarded so [`Self::rotate`] can
    /// swap in a new signer live; read guards are never held across an `.await`.
    pub(crate) keyring: Arc<RwLock<Keyring>>,
    pub(crate) codes: Arc<Mutex<HashMap<String, AuthCode>>>,
}

impl SsoState {
    /// Build the issuer state, loading the persisted RS256 keyring (and, on the
    /// very first run, generating and persisting a signing key). `issuer` is the
    /// public base URL (no trailing slash), used as the token `iss` and to derive
    /// the endpoint URLs in discovery. Keys survive restarts, so the JWKS a
    /// client cached stays valid.
    pub async fn new(db: Db, issuer: impl Into<String>) -> Result<Self, String> {
        let keyring = load_or_init_keyring(&db).await?;
        Ok(Self {
            db,
            issuer: issuer.into().trim_end_matches('/').to_string(),
            keyring: Arc::new(RwLock::new(keyring)),
            codes: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Rotate the signing key: generate a fresh active key, retire the current
    /// one (kept in the JWKS for [`RETIRED_KEY_GRACE_SECS`] so its tokens keep
    /// verifying), persist the change, and drop keys retired past the grace
    /// window. Returns the new active key id.
    pub async fn rotate(&self) -> Result<String, String> {
        let kid = new_kid();
        let (_key, pem) = SigningKey::generate_with_kid(kid.clone())?;
        self.db
            .rotate_signing_key(&kid, &pem)
            .await
            .map_err(|e| e.to_string())?;
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(RETIRED_KEY_GRACE_SECS);
        let _ = self.db.prune_retired_signing_keys(cutoff).await;
        let keyring = load_or_init_keyring(&self.db).await?;
        *self.keyring.write().map_err(|_| "keyring lock poisoned")? = keyring;
        Ok(kid)
    }

    /// Store a fresh authorization code, returning its value.
    pub(crate) fn put_code(&self, code: String, entry: AuthCode) {
        self.codes.lock().unwrap().insert(code, entry);
    }

    /// Remove and return a code (single-use), if present and unexpired.
    pub(crate) fn take_code(&self, code: &str) -> Option<AuthCode> {
        let mut codes = self.codes.lock().unwrap();
        let entry = codes.remove(code)?;
        if entry.expires_at < chrono::Utc::now() {
            return None;
        }
        Some(entry)
    }
}

/// Load the persisted keyring, pruning keys retired past the grace window and
/// generating+persisting an active key on first run.
async fn load_or_init_keyring(db: &Db) -> Result<Keyring, String> {
    // Startup housekeeping: drop keys retired past the grace window.
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(RETIRED_KEY_GRACE_SECS);
    let _ = db.prune_retired_signing_keys(cutoff).await;

    let stored = db
        .load_sso_signing_keys()
        .await
        .map_err(|e| e.to_string())?;
    let mut active: Option<SigningKey> = None;
    let mut retired: Vec<SigningKey> = Vec::new();
    for sk in &stored {
        let key = SigningKey::from_pkcs8_pem(sk.kid.clone(), &sk.private_pem)?;
        if sk.active && active.is_none() {
            active = Some(key);
        } else {
            retired.push(key);
        }
    }
    let active = match active {
        Some(key) => key,
        None => {
            // First run (or a store somehow left without an active key):
            // generate one and persist it as the signer.
            let kid = new_kid();
            let (key, pem) = SigningKey::generate_with_kid(kid.clone())?;
            db.insert_active_signing_key(&kid, &pem)
                .await
                .map_err(|e| e.to_string())?;
            key
        }
    };
    Ok(Keyring::new(active, retired))
}

/// Build the OIDC issuer router (fully stated — ready to merge into the app).
pub fn oidc_router(state: SsoState) -> Router {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(endpoints::discovery),
        )
        .route("/oidc/jwks", get(endpoints::jwks))
        .route("/oidc/authorize", get(endpoints::authorize))
        .route("/oidc/token", post(endpoints::token))
        .route("/oidc/userinfo", get(endpoints::userinfo))
        .route("/oidc/rotate-key", post(endpoints::rotate_key))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Claims {
        sub: String,
        exp: i64,
        iat: i64,
    }

    #[tokio::test]
    async fn keys_persist_and_rotation_keeps_old_tokens_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();

        // First startup mints and persists an active key.
        let st = SsoState::new(db.clone(), "https://idp.test").await.unwrap();
        let kid1 = st.keyring.read().unwrap().active_kid().to_string();
        let claims = Claims {
            sub: "alice".into(),
            exp: 9_999_999_999,
            iat: 0,
        };
        let old_token = st.keyring.read().unwrap().sign(&claims).unwrap();

        // Rotation swaps the active key but keeps the old one published.
        let kid2 = st.rotate().await.unwrap();
        assert_ne!(kid1, kid2);
        assert_eq!(st.keyring.read().unwrap().active_kid(), kid2);
        assert_eq!(
            st.keyring.read().unwrap().jwks()["keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        // A token signed by the now-retired key still verifies.
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        v.validate_aud = false;
        let decoded = st
            .keyring
            .read()
            .unwrap()
            .decode::<Claims>(&old_token, &v)
            .unwrap();
        assert_eq!(decoded.claims.sub, "alice");

        // Persistence: a fresh state on the same DB reloads kid2 as the signer
        // and still publishes both keys (no fresh keygen on restart).
        let st2 = SsoState::new(db.clone(), "https://idp.test").await.unwrap();
        assert_eq!(st2.keyring.read().unwrap().active_kid(), kid2);
        assert_eq!(
            st2.keyring.read().unwrap().jwks()["keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
