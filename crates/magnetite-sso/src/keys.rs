//! The issuer's RS256 signing keys. A single *active* key signs new tokens while
//! any recently *retired* keys stay published in the JWKS so tokens they signed
//! keep verifying across a rotation. Keys are persisted (PKCS#8 PEM) in the DB by
//! the caller, so they survive restarts — clients see a stable JWKS.

use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

/// One RS256 key: the private half (for signing/verifying) plus its public JWK
/// coordinates (for publication).
pub(crate) struct SigningKey {
    encoding: EncodingKey,
    decoding: DecodingKey,
    kid: String,
    /// Public modulus / exponent, base64url (JWK form).
    jwk_n: String,
    jwk_e: String,
}

impl SigningKey {
    /// Build a key from an RSA private key and a key id, returning the key and
    /// its PKCS#8 PEM so the caller can persist it.
    fn build(kid: String, private: RsaPrivateKey) -> Result<(Self, String), String> {
        let pem = private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| e.to_string())?
            .to_string();
        let key = Self::from_pkcs8_pem(kid, &pem)?;
        Ok((key, pem))
    }

    /// Generate a fresh 2048-bit RSA key with the given key id, returning the key
    /// and its PKCS#8 PEM for persistence.
    pub fn generate_with_kid(kid: String) -> Result<(Self, String), String> {
        let mut rng = rand::rngs::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| e.to_string())?;
        Self::build(kid, private)
    }

    /// Reconstruct a key from a stored PKCS#8 PEM (as produced by [`Self::build`]).
    pub fn from_pkcs8_pem(kid: String, pem: &str) -> Result<Self, String> {
        let private = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| e.to_string())?;
        let public = RsaPublicKey::from(&private);
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| e.to_string())?;

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwk_n = b64.encode(public.n().to_bytes_be());
        let jwk_e = b64.encode(public.e().to_bytes_be());
        let decoding =
            DecodingKey::from_rsa_components(&jwk_n, &jwk_e).map_err(|e| e.to_string())?;

        Ok(Self {
            encoding,
            decoding,
            kid,
            jwk_n,
            jwk_e,
        })
    }

    /// This key as one JWK Set entry (public half only).
    fn jwk_entry(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": self.jwk_n,
            "e": self.jwk_e,
        })
    }
}

/// The set of issuer keys: `keys[0]` is the active signer; the rest are retired
/// keys kept for verification until their tokens expire.
pub(crate) struct Keyring {
    keys: Vec<SigningKey>,
}

impl Keyring {
    /// Build from an active key plus any retired verifiers (order preserved: the
    /// active key must be first).
    pub fn new(active: SigningKey, retired: Vec<SigningKey>) -> Self {
        let mut keys = Vec::with_capacity(1 + retired.len());
        keys.push(active);
        keys.extend(retired);
        Self { keys }
    }

    /// The active signer's key id.
    #[cfg(test)]
    pub fn active_kid(&self) -> &str {
        &self.keys[0].kid
    }

    /// Sign a claims set with the active key, stamping its `kid` into the header.
    pub fn sign<T: serde::Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let active = &self.keys[0];
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(active.kid.clone());
        jsonwebtoken::encode(&header, claims, &active.encoding)
    }

    /// Verify a token against the key named by its `kid` header (falling back to
    /// the active key when no `kid` is present).
    pub fn decode<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        validation: &jsonwebtoken::Validation,
    ) -> Result<jsonwebtoken::TokenData<T>, jsonwebtoken::errors::Error> {
        let kid = jsonwebtoken::decode_header(token).ok().and_then(|h| h.kid);
        let key = match kid {
            Some(ref want) => self.keys.iter().find(|k| &k.kid == want),
            None => self.keys.first(),
        }
        .ok_or_else(|| {
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
        })?;
        jsonwebtoken::decode::<T>(token, &key.decoding, validation)
    }

    /// The JWK Set: every key (active and retired) so a client verifying an older
    /// token still finds its key.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({ "keys": self.keys.iter().map(SigningKey::jwk_entry).collect::<Vec<_>>() })
    }
}
