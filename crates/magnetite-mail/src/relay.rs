//! Outbound mail relay (T5). Sends accepted messages for non-hosted recipients
//! to an external SMTP server: through the configured smarthost when set, else
//! by direct delivery to each recipient's domain (port 25, opportunistic). Uses
//! lettre's async SMTP transport with `send_raw`, so the original message
//! (headers + body) is relayed verbatim.
//!
//! Only authenticated submissions reach here (the SMTP dialog accepts foreign
//! recipients only for an authed session), so this is not an open relay.
//!
//! Transport uses **opportunistic STARTTLS** ([`opportunistic_tls`]): the session
//! is encrypted when the peer offers STARTTLS, else it falls back to plaintext.
//! Peer certs are not verified (port-25 delivery reaches arbitrary MTAs). Direct
//! delivery resolves the recipient domain's **MX records** ([`mail_exchangers`])
//! and tries each host most-preferred first, falling back to the domain itself
//! (implicit MX). The durable retry queue and DSN bounces live in the service
//! layer.

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use magnetite_core::RelayConfig;

/// Opportunistic STARTTLS for outbound SMTP: if the peer advertises STARTTLS the
/// session is encrypted, otherwise it falls back to plaintext (RFC 7435). Peer
/// certificates are not verified — port-25 delivery reaches arbitrary MTAs whose
/// certs are commonly self-signed or name-mismatched, so this buys encryption
/// against passive eavesdropping without breaking interoperability. Returns
/// [`Tls::None`] if the TLS parameters cannot be built (plaintext fallback).
fn opportunistic_tls(domain: &str) -> Tls {
    match TlsParameters::builder(domain.to_string())
        .dangerous_accept_invalid_certs(true)
        .dangerous_accept_invalid_hostnames(true)
        .build()
    {
        Ok(params) => Tls::Opportunistic(params),
        Err(e) => {
            tracing::warn!("TLS setup for {domain} failed ({e}); sending in plaintext");
            Tls::None
        }
    }
}

/// Build a plain-text email (lettre encodes the headers, so a non-ASCII subject or
/// body is handled correctly) and relay it from `from` to `to`. Returns the number
/// of recipients the remote side accepted, or `0` if the message could not be built
/// (e.g. an unparseable address). This is the public send path for notifications.
pub async fn send_mail(
    relay: Option<&RelayConfig>,
    from: &str,
    to: &[String],
    subject: &str,
    body: &str,
) -> usize {
    use lettre::message::{header::ContentType, Message};

    let Ok(from_mbox) = from.parse() else {
        tracing::warn!("send_mail: unparseable from address '{from}'");
        return 0;
    };
    let mut builder = Message::builder().from(from_mbox).subject(subject);
    let mut valid: Vec<String> = Vec::new();
    for addr in to {
        match addr.parse() {
            Ok(mbox) => {
                builder = builder.to(mbox);
                valid.push(addr.clone());
            }
            Err(_) => tracing::warn!("send_mail: skipping unparseable recipient '{addr}'"),
        }
    }
    if valid.is_empty() {
        return 0;
    }
    let msg = match builder
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
    {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("send_mail: building message failed: {e}");
            return 0;
        }
    };
    relay_message(relay, from, &valid, &msg.formatted()).await
}

/// Relay `data` (a complete RFC 5322 message) from `sender` to the remote
/// `recipients`, returning how many were accepted by the remote side. `sender`
/// may be empty (a null return-path).
pub(crate) async fn relay_message(
    relay: Option<&RelayConfig>,
    sender: &str,
    recipients: &[String],
    data: &[u8],
) -> usize {
    match relay {
        // Smarthost: a single connection carries every recipient.
        Some(cfg) => {
            let Some(envelope) = build_envelope(sender, recipients) else {
                tracing::warn!("relay: no valid recipient addresses");
                return 0;
            };
            match smarthost_transport(cfg).send_raw(&envelope, data).await {
                Ok(_) => recipients.len(),
                Err(e) => {
                    tracing::warn!("relay via smarthost {} failed: {e}", cfg.host);
                    0
                }
            }
        }
        // Direct delivery: look up the recipient domain's MX hosts and try each
        // (most-preferred first) until one accepts.
        None => {
            let mut delivered = 0;
            for rcpt in recipients {
                let domain = rcpt.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                if domain.is_empty() {
                    tracing::warn!("relay: skipping malformed recipient '{rcpt}'");
                    continue;
                }
                let Some(envelope) = build_envelope(sender, std::slice::from_ref(rcpt)) else {
                    continue;
                };
                let mut sent = false;
                for host in mail_exchangers(domain).await {
                    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                        .port(25)
                        .tls(opportunistic_tls(&host))
                        .build();
                    match transport.send_raw(&envelope, data).await {
                        Ok(_) => {
                            delivered += 1;
                            sent = true;
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("direct relay to {rcpt} via MX {host} failed: {e}")
                        }
                    }
                }
                if !sent {
                    tracing::warn!("direct relay to {rcpt}: all mail exchangers failed");
                }
            }
            delivered
        }
    }
}

/// Forward a raw message to a specific `host:port` over plaintext SMTP. Used by
/// the backup-MX queue to reach a domain's primary directly (not via smarthost
/// or MX lookup). Returns the number of recipients the remote accepted, or 0 on
/// any failure (the caller reschedules).
pub(crate) async fn forward_to_host(
    host: &str,
    port: u16,
    sender: &str,
    recipients: &[String],
    data: &[u8],
) -> usize {
    let Some(envelope) = build_envelope(sender, recipients) else {
        tracing::warn!("backup MX forward: no valid recipient addresses");
        return 0;
    };
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        .port(port)
        .tls(opportunistic_tls(host))
        .build();
    match transport.send_raw(&envelope, data).await {
        Ok(_) => recipients.len(),
        Err(e) => {
            tracing::warn!("backup MX forward to {host}:{port} failed: {e}");
            0
        }
    }
}

/// Build a plaintext (unencrypted) transport to the configured smarthost.
fn smarthost_transport(cfg: &RelayConfig) -> AsyncSmtpTransport<Tokio1Executor> {
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
        .port(cfg.port)
        .tls(opportunistic_tls(&cfg.host));
    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
    }
    builder.build()
}

/// The process-wide resolver for MX lookups (built once from system config).
async fn mx_resolver() -> Option<&'static hickory_resolver::TokioResolver> {
    use tokio::sync::OnceCell;
    static RESOLVER: OnceCell<Option<hickory_resolver::TokioResolver>> = OnceCell::const_new();
    RESOLVER
        .get_or_init(|| async {
            hickory_resolver::TokioResolver::builder_tokio()
                .ok()
                .map(|b| b.build())
        })
        .await
        .as_ref()
}

/// Order MX hosts by ascending preference (lowest = most preferred). With no MX
/// records the domain itself is used as an implicit MX (RFC 5321 §5.1).
fn order_exchangers(mut mxs: Vec<(u16, String)>, domain: &str) -> Vec<String> {
    mxs.retain(|(_, host)| !host.is_empty());
    if mxs.is_empty() {
        return vec![domain.to_string()];
    }
    mxs.sort_by_key(|(pref, _)| *pref);
    mxs.into_iter().map(|(_, host)| host).collect()
}

/// Resolve `domain`'s mail exchangers, most-preferred first. Falls back to the
/// domain itself when it has no MX records or the lookup fails.
async fn mail_exchangers(domain: &str) -> Vec<String> {
    let Some(resolver) = mx_resolver().await else {
        return vec![domain.to_string()];
    };
    match resolver.mx_lookup(format!("{domain}.")).await {
        Ok(lookup) => {
            let mxs = lookup
                .iter()
                .map(|mx| {
                    (
                        mx.preference(),
                        mx.exchange().to_utf8().trim_end_matches('.').to_string(),
                    )
                })
                .collect();
            order_exchangers(mxs, domain)
        }
        Err(_) => vec![domain.to_string()],
    }
}

/// Construct an SMTP envelope, dropping any addresses that fail to parse.
/// Returns `None` if no recipient address is usable.
fn build_envelope(sender: &str, recipients: &[String]) -> Option<Envelope> {
    let from = if sender.trim().is_empty() {
        None
    } else {
        sender.parse().ok()
    };
    let to: Vec<_> = recipients.iter().filter_map(|r| r.parse().ok()).collect();
    if to.is_empty() {
        return None;
    }
    Envelope::new(from, to).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchangers_sorted_by_preference() {
        let mxs = vec![
            (20, "mx2.example.com".to_string()),
            (10, "mx1.example.com".to_string()),
            (30, "mx3.example.com".to_string()),
        ];
        assert_eq!(
            order_exchangers(mxs, "example.com"),
            vec!["mx1.example.com", "mx2.example.com", "mx3.example.com"]
        );
    }

    #[test]
    fn no_mx_falls_back_to_domain() {
        assert_eq!(order_exchangers(vec![], "example.com"), vec!["example.com"]);
        // Empty hostnames are dropped, then the fallback applies.
        assert_eq!(
            order_exchangers(vec![(10, String::new())], "example.com"),
            vec!["example.com"]
        );
    }
}
