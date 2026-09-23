//! DKIM outbound signing (RFC 6376, RSA-SHA256, `simple/simple`
//! canonicalization). Relayed outbound mail is signed with the sending domain's
//! private key so receivers can verify it against the public key published at
//! `<selector>._domainkey.<domain>` in DNS. Inbound DKIM verification is not
//! included.

use base64::Engine;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// Headers included in the DKIM signature (simple canonicalization).
const SIGNED_HEADERS: &[&str] = &["from", "to", "subject", "date", "message-id"];

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Sign `message` with DKIM when `selector` + `private_key_pem` are present,
/// returning the message with a `DKIM-Signature` header prepended. Returns the
/// message unchanged when unconfigured or signing fails.
pub(crate) fn maybe_sign(
    message: &[u8],
    domain: &str,
    selector: Option<&str>,
    private_key_pem: Option<&str>,
) -> Vec<u8> {
    match (selector, private_key_pem) {
        (Some(sel), Some(key)) if !sel.is_empty() && !key.is_empty() => {
            sign(message, domain, sel, key).unwrap_or_else(|| message.to_vec())
        }
        _ => message.to_vec(),
    }
}

fn sign(message: &[u8], domain: &str, selector: &str, key_pem: &str) -> Option<Vec<u8>> {
    let private = RsaPrivateKey::from_pkcs8_pem(key_pem).ok()?;
    let raw = String::from_utf8_lossy(message);
    let (headers_part, body_part) = split_headers_body(&raw);

    let body_hash = B64.encode(Sha256::digest(canon_body(body_part).as_bytes()));
    let signed = signed_headers(headers_part);
    let names = signed
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(":");
    let mut header_canon = String::new();
    for (name, value) in &signed {
        header_canon.push_str(&format!("{name}: {value}\r\n"));
    }

    // The signature covers the canonical headers + the DKIM-Signature header
    // itself with an empty `b=` value.
    let unsigned = dkim_header(domain, selector, &names, &body_hash, "");
    let hash = Sha256::digest(format!("{header_canon}{unsigned}").as_bytes());
    let signature = private.sign(Pkcs1v15Sign::new::<Sha256>(), &hash).ok()?;

    let full = dkim_header(domain, selector, &names, &body_hash, &B64.encode(signature));
    let mut out = Vec::with_capacity(full.len() + message.len() + 2);
    out.extend_from_slice(full.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(message);
    Some(out)
}

fn dkim_header(domain: &str, selector: &str, headers: &str, body_hash: &str, b: &str) -> String {
    format!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d={domain}; s={selector};\r\n\
         \th={headers}; bh={body_hash};\r\n\tb={b}"
    )
}

/// Generate a fresh RSA-2048 DKIM key, returning `(private PKCS#8 PEM,
/// base64 SubjectPublicKeyInfo)` — the latter is the `p=` value for the DNS
/// TXT record. RSA keygen is slow in debug builds; do it once per domain.
pub(crate) fn generate_key() -> Option<(String, String)> {
    let mut rng = rand::rngs::OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).ok()?;
    let pem = private
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .ok()?
        .to_string();
    let public = RsaPublicKey::from(&private);
    let spki = public.to_public_key_der().ok()?;
    Some((pem, B64.encode(spki.as_bytes())))
}

/// The DNS TXT record value to publish at `<selector>._domainkey.<domain>`.
pub(crate) fn dns_txt_record(public_key_b64: &str) -> String {
    format!("v=DKIM1; k=rsa; p={public_key_b64}")
}

/// Freshly generated DKIM key material for the management UI.
pub struct DkimKeyMaterial {
    /// PKCS#8 PEM private key — stored server-side, never shown to end users.
    pub private_key_pem: String,
    /// DNS TXT value the operator publishes at `<selector>._domainkey.<domain>`.
    pub txt_record: String,
}

/// Generate a fresh 2048-bit RSA DKIM key pair. Returns `None` if key
/// generation fails. RSA keygen is CPU-heavy — call it once per domain.
pub fn generate_dkim_key() -> Option<DkimKeyMaterial> {
    let (private_key_pem, public_key_b64) = generate_key()?;
    Some(DkimKeyMaterial {
        private_key_pem,
        txt_record: dns_txt_record(&public_key_b64),
    })
}

/// Re-derive the public DNS TXT record value from a stored PKCS#8 PEM private
/// key. Used to show the record an operator must publish for an existing key.
pub fn dkim_txt_from_private_pem(pem: &str) -> Option<String> {
    let private = RsaPrivateKey::from_pkcs8_pem(pem).ok()?;
    let public = RsaPublicKey::from(&private);
    let spki = public.to_public_key_der().ok()?;
    Some(dns_txt_record(&B64.encode(spki.as_bytes())))
}

/// Split a message into `(headers, body)` at the first blank line.
fn split_headers_body(raw: &str) -> (&str, &str) {
    if let Some(pos) = raw.find("\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.find("\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (raw, "")
    }
}

/// Simple body canonicalization (RFC 6376 §3.4.3): strip trailing empty lines,
/// end with a single CRLF.
fn canon_body(body: &str) -> String {
    let trimmed = body.trim_end_matches("\r\n").trim_end_matches('\n');
    if trimmed.is_empty() {
        "\r\n".to_string()
    } else {
        format!("{trimmed}\r\n")
    }
}

/// The signed headers present in the message, in order, as `(name, value)`.
fn signed_headers(headers: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if SIGNED_HEADERS.contains(&name.trim().to_ascii_lowercase().as_str()) {
                out.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// Shared key (RSA keygen is slow in debug).
    fn test_key() -> &'static (String, String) {
        static KEY: OnceLock<(String, String)> = OnceLock::new();
        KEY.get_or_init(|| generate_key().unwrap())
    }

    #[test]
    fn signs_with_dkim_signature_header() {
        let (pem, pubkey) = test_key();
        let msg = b"From: a@example.com\r\nTo: b@remote.test\r\nSubject: hi\r\n\r\nhello\r\n";
        let signed = maybe_sign(msg, "example.com", Some("mail"), Some(pem));

        let text = String::from_utf8_lossy(&signed);
        assert!(text.starts_with("DKIM-Signature: v=1;"), "{text}");
        assert!(text.contains("d=example.com"));
        assert!(text.contains("s=mail"));
        assert!(text.contains("a=rsa-sha256"));
        assert!(text.contains("bh="));
        assert!(text.contains("b="));
        // Original message is preserved after the signature.
        assert!(text.contains("Subject: hi"));
        assert!(text.contains("hello"));
        // The DNS record embeds the same key material.
        assert!(dns_txt_record(pubkey).starts_with("v=DKIM1; k=rsa; p="));
    }

    #[test]
    fn unconfigured_is_passthrough() {
        let msg = b"From: a@x\r\n\r\nbody\r\n";
        assert_eq!(maybe_sign(msg, "x", None, None), msg.to_vec());
        assert_eq!(maybe_sign(msg, "x", Some(""), Some("k")), msg.to_vec());
    }
}
