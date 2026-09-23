//! The embedded SMTP receiving server (E4). Binds a listen port and runs a
//! minimal ESMTP dialog (HELO/EHLO, MAIL, RCPT, DATA, RSET, NOOP, QUIT),
//! validating recipients against the mail model and storing accepted messages
//! in the shared DB. Registered as an [`EmbeddedService`] so `magnetite-server`
//! runs it in-process (09b §-1).
//!
//! Scope: SMTP receipt for locally-hosted domains, alias & mailing-list
//! expansion to local mailboxes, quota enforcement, per-recipient storage.
//! Implicit TLS (T3) and STARTTLS + SMTP AUTH (T4): with a `tls_cert_name` the
//! SMTPS/IMAPS/POP3S ports and the STARTTLS upgrade serve the dialogs over TLS,
//! and authenticated (AUTH LOGIN/PLAIN) sessions may submit to remote domains.
//! Outbound submission is relayed (T5) via the configured smarthost, or by
//! direct delivery to the recipient domain, over opportunistic STARTTLS. The
//! backup-MX queue (durable retry) and DSN bounces are handled here; MX lookup
//! remains deferred.

use crate::resolver::{resolve_recipient, Recipient, Snapshot};
use crate::tls::Flow;
use chrono::Utc;
use magnetite_core::domain::DomainKey;
use magnetite_core::models::common::{LogKind, LogLevel};
use magnetite_core::RelayConfig;
use magnetite_db::{Db, EmbeddedService, NewLogEntry, ServiceHealth};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

const H_STARTING: u8 = 0;
const H_HEALTHY: u8 = 1;
const H_ERROR: u8 = 2;

/// Embedded SMTP server bound to `addr` (usually `0.0.0.0:25`).
pub struct MailService {
    addr: SocketAddr,
    log_events: bool,
    relay: Option<RelayConfig>,
    health: Arc<AtomicU8>,
}

impl MailService {
    /// `log_events` ⇒ write an operation LogEntry per accepted message. `relay`
    /// is the outbound smarthost for authenticated submissions (T5); `None`
    /// falls back to direct delivery to the recipient domain.
    pub fn new(addr: SocketAddr, log_events: bool, relay: Option<RelayConfig>) -> Self {
        Self {
            addr,
            log_events,
            relay,
            health: Arc::new(AtomicU8::new(H_STARTING)),
        }
    }
}

impl EmbeddedService for MailService {
    fn domain(&self) -> DomainKey {
        DomainKey::Mail
    }

    fn health(&self) -> ServiceHealth {
        match self.health.load(Ordering::Relaxed) {
            H_HEALTHY => ServiceHealth::Healthy,
            H_ERROR => ServiceHealth::Error,
            _ => ServiceHealth::Unknown,
        }
    }

    fn start(&self, db: Db, shutdown: watch::Receiver<bool>) {
        let addr = self.addr;
        let health = self.health.clone();
        let log_events = self.log_events;
        let relay = self.relay.clone();

        // Seed the DB-backed relay settings from the file config on first run, so the
        // Web UI shows (and can edit) the current smarthost. The DB wins thereafter.
        let seed_db = db.clone();
        let seed_relay = self.relay.clone();
        tokio::spawn(async move {
            let seed = seed_relay.map(|r| magnetite_core::domains::mail::model::MailRelayConfig {
                enabled: true,
                host: r.host,
                port: r.port,
                username: r.username,
                password: r.password,
            });
            if let Err(e) = seed_db.ensure_mail_relay(seed).await {
                tracing::warn!("mail relay: could not seed relay settings: {e}");
            }
        });

        // POP3 / IMAP retrieval — and the implicit-TLS ports (SMTPS/IMAPS/POP3S)
        // — on the ports from the mail config's protocol entries. All are bound
        // at startup; restart to change, like the SMTP listen port.
        let retrieval_db = db.clone();
        let retrieval_shutdown = shutdown.clone();
        let retrieval_ip = addr.ip();
        let retrieval_relay = relay.clone();
        tokio::spawn(async move {
            let config = retrieval_db.get_mail_config().await.ok();
            let port = |name: &str| {
                config
                    .as_ref()
                    .and_then(|c| c.protocols.get(name).cloned())
                    .filter(|p| p.enabled && p.port > 0)
                    .map(|p| p.port)
            };
            let addr_for = |p: u16| SocketAddr::new(retrieval_ip, p);

            if let Some(pop3_port) = port("pop3") {
                let a = addr_for(pop3_port);
                let db = retrieval_db.clone();
                let sd = retrieval_shutdown.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::pop3::serve(a, db, sd).await {
                        tracing::error!("POP3 server on {a} failed: {e}");
                    }
                });
            }
            if let Some(imap_port) = port("imap") {
                let a = addr_for(imap_port);
                let db = retrieval_db.clone();
                let sd = retrieval_shutdown.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::imap::serve(a, db, sd).await {
                        tracing::error!("IMAP server on {a} failed: {e}");
                    }
                });
            }

            // Implicit TLS: only when the mail config names a certificate that
            // has a private key and parses. Each S-port that is enabled gets a
            // listener that TLS-wraps every connection before the dialog.
            let tls_config = match config.as_ref().and_then(|c| c.tls_cert_name.as_deref()) {
                Some(name) => crate::tls::build_server_config(&retrieval_db, name).await,
                None => None,
            };
            if let Some(server_config) = tls_config {
                let acceptor = TlsAcceptor::from(server_config);
                spawn_tls_smtp(
                    port("smtps"),
                    &acceptor,
                    &retrieval_db,
                    &retrieval_shutdown,
                    retrieval_ip,
                    log_events,
                    retrieval_relay.clone(),
                );
                spawn_tls_imap(
                    port("imaps"),
                    &acceptor,
                    &retrieval_db,
                    &retrieval_shutdown,
                    retrieval_ip,
                );
                spawn_tls_pop3(
                    port("pop3s"),
                    &acceptor,
                    &retrieval_db,
                    &retrieval_shutdown,
                    retrieval_ip,
                );
            } else if config
                .as_ref()
                .and_then(|c| c.tls_cert_name.as_deref())
                .is_some()
            {
                tracing::warn!(
                    "mail TLS: configured tls_cert_name has no usable key/PEM; S-ports disabled"
                );
            }
        });

        // Backup-MX forwarding queue worker (durable retry to each primary; DSN
        // bounce on final give-up).
        let queue_db = db.clone();
        let queue_relay = relay.clone();
        let queue_shutdown = shutdown.clone();
        tokio::spawn(queue_task(queue_db, queue_relay, queue_shutdown));

        // SMTP DORA loop (health source for the domain).
        magnetite_db::spawn_health_guarded("mail", health.clone(), H_ERROR, async move {
            if let Err(e) = run(addr, db, shutdown, health.clone(), log_events, relay).await {
                tracing::error!("SMTP server on {addr} failed: {e}");
                health.store(H_ERROR, Ordering::Relaxed);
            }
        });
    }
}

async fn load_snapshot(db: &Db) -> Snapshot {
    Snapshot {
        domains: db.list_mail_domains().await.unwrap_or_default(),
        users: db.list_mail_users().await.unwrap_or_default(),
        aliases: db.list_aliases().await.unwrap_or_default(),
        lists: db.list_mailing_lists().await.unwrap_or_default(),
        backups: db.list_backup_mx().await.unwrap_or_default(),
    }
}

/// Extract the address from a `MAIL FROM:<a@b>` / `RCPT TO:<a@b>` command.
fn extract_address(line: &str, keyword: &str) -> String {
    let upper = line.to_ascii_uppercase();
    let Some(pos) = upper.find(keyword) else {
        return String::new();
    };
    line[pos + keyword.len()..]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

/// DKIM-sign `data` with the sender domain's configured key, or pass it through
/// unchanged when the domain has no DKIM signing configured.
async fn dkim_sign(db: &Db, sender: &str, data: &[u8]) -> Vec<u8> {
    let Some((_, domain)) = sender.rsplit_once('@') else {
        return data.to_vec();
    };
    if domain.is_empty() {
        return data.to_vec();
    }
    match db.get_mail_dkim(domain).await {
        Ok(Some((selector, pem))) => {
            crate::dkim::maybe_sign(data, domain, Some(&selector), Some(&pem))
        }
        _ => data.to_vec(),
    }
}

/// The live outbound-relay settings: the DB-backed smarthost (Web-UI editable) when
/// enabled, else the startup file-config `fallback`. Loaded at the point of use so
/// edits apply without a restart. An explicitly *disabled* DB row means "direct MX"
/// and overrides the file fallback.
async fn effective_relay(db: &Db, fallback: Option<RelayConfig>) -> Option<RelayConfig> {
    match db.get_mail_relay().await {
        Ok(Some(r)) if r.enabled && !r.host.trim().is_empty() => Some(RelayConfig {
            host: r.host,
            port: r.port,
            username: r.username.filter(|u| !u.trim().is_empty()),
            password: r.password.filter(|p| !p.is_empty()),
        }),
        Ok(Some(_)) => None,
        _ => fallback,
    }
}

async fn handle_connection<S>(
    stream: S,
    db: Db,
    log_events: bool,
    starttls: Option<TlsAcceptor>,
    secure: bool,
    relay: Option<RelayConfig>,
    spf_ip: Option<IpAddr>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Source the relay live from the DB (Web-UI editable), falling back to the file config.
    let relay = effective_relay(&db, relay).await;
    let config = db.get_mail_config().await.ok();
    let hostname = config
        .as_ref()
        .map(|c| c.hostname.clone())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "magnetite".to_string());
    let max_size = config
        .as_ref()
        .map(|c| c.max_message_size_bytes)
        .unwrap_or(0);
    let snapshot = load_snapshot(&db).await;

    // One buffered handle used for both directions; the dialog is strictly
    // request/response so no split is needed. Keeping ownership of the whole
    // stream lets us swap it for a TLS stream on STARTTLS.
    let mut io = BufReader::new(stream);
    io.write_all(format!("220 {hostname} ESMTP Magnetite\r\n").as_bytes())
        .await?;

    let offer_tls = starttls.is_some() && !secure;
    let flow = smtp_dialog(
        &mut io,
        &db,
        &hostname,
        max_size,
        &snapshot,
        log_events,
        secure,
        offer_tls,
        relay.as_ref(),
        spf_ip,
    )
    .await?;

    // STARTTLS: reunite the stream, TLS-wrap it, and resume the dialog on the
    // encrypted channel. `into_inner` drops any buffered bytes — a defense
    // against plaintext command injection ahead of the handshake (RFC 3207 §4).
    if let Flow::StartTls = flow {
        let acceptor = starttls.expect("STARTTLS only offered when acceptor present");
        let tls = acceptor.accept(io.into_inner()).await?;
        let mut io = BufReader::new(tls);
        smtp_dialog(
            &mut io,
            &db,
            &hostname,
            max_size,
            &snapshot,
            log_events,
            true,
            false,
            relay.as_ref(),
            spf_ip,
        )
        .await?;
    }
    Ok(())
}

/// The ESMTP command loop. Returns [`Flow::StartTls`] when the client issued
/// `STARTTLS` (and it was offered) so the caller can upgrade the connection;
/// otherwise [`Flow::Done`]. `secure` marks a session already on TLS (AUTH is
/// only offered/accepted there); `offer_tls` advertises STARTTLS in EHLO.
#[allow(clippy::too_many_arguments)]
async fn smtp_dialog<S>(
    io: &mut BufReader<S>,
    db: &Db,
    hostname: &str,
    max_size: u64,
    snapshot: &Snapshot,
    log_events: bool,
    secure: bool,
    offer_tls: bool,
    relay: Option<&RelayConfig>,
    spf_ip: Option<IpAddr>,
) -> std::io::Result<Flow>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut sender = String::new();
    let mut deliver: Vec<String> = Vec::new();
    // Foreign recipients accepted for outbound relay (authenticated sessions).
    let mut relay_to: Vec<String> = Vec::new();
    // Backup-MX recipients accepted for queued forwarding, keyed to the primary
    // `(host, port)` they must be forwarded to.
    let mut queue: Vec<(String, String, u16)> = Vec::new();
    // SPF result header for the sender domain (inbound plaintext sessions).
    let mut spf_header: Option<String> = None;
    let mut authed = false;
    let mut line = String::new();

    loop {
        line.clear();
        if crate::line::read_line_capped_timeout(io, &mut line, crate::line::MAX_COMMAND_LINE)
            .await?
            == 0
        {
            return Ok(Flow::Done); // client disconnected
        }
        let trimmed = line.trim_end();
        let command = trimmed
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();

        match command.as_str() {
            "EHLO" => {
                sender.clear();
                deliver.clear();
                let mut lines = vec![hostname.to_string()];
                if offer_tls {
                    lines.push("STARTTLS".into());
                }
                if secure {
                    lines.push("AUTH LOGIN PLAIN".into());
                }
                let mut resp = String::new();
                for (i, l) in lines.iter().enumerate() {
                    let sep = if i + 1 == lines.len() { ' ' } else { '-' };
                    resp.push_str(&format!("250{sep}{l}\r\n"));
                }
                io.write_all(resp.as_bytes()).await?;
            }
            "HELO" => {
                sender.clear();
                deliver.clear();
                io.write_all(format!("250 {hostname}\r\n").as_bytes())
                    .await?;
            }
            "STARTTLS" => {
                if offer_tls {
                    io.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                    io.flush().await?;
                    return Ok(Flow::StartTls);
                }
                io.write_all(b"503 5.5.1 STARTTLS not available\r\n")
                    .await?;
            }
            "AUTH" => {
                if !secure {
                    io.write_all(b"530 5.7.0 Must issue a STARTTLS command first\r\n")
                        .await?;
                } else if authed {
                    io.write_all(b"503 5.5.1 Already authenticated\r\n").await?;
                } else {
                    let rest = trimmed.split_once(' ').map(|x| x.1).unwrap_or("");
                    match smtp_auth(io, db, rest).await? {
                        Some(true) => {
                            authed = true;
                            io.write_all(b"235 2.7.0 Authentication successful\r\n")
                                .await?;
                        }
                        Some(false) => {
                            io.write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                                .await?;
                        }
                        None => {
                            io.write_all(b"504 5.5.4 Unsupported authentication mechanism\r\n")
                                .await?;
                        }
                    }
                }
            }
            "MAIL" => {
                sender = extract_address(trimmed, "FROM:");
                deliver.clear();
                relay_to.clear();
                // SPF: evaluate the sender domain against the connecting IP
                // (inbound plaintext only; record-only, never rejects). Loopback
                // senders have no meaningful SPF, so they are skipped.
                spf_header = None;
                if let Some(ip) = spf_ip.filter(|ip| !ip.is_loopback()) {
                    if let Some((_, domain)) = sender.rsplit_once('@') {
                        if !domain.is_empty() {
                            let (_, header) = crate::spf::evaluate(domain, ip).await;
                            spf_header = Some(header);
                        }
                    }
                }
                io.write_all(b"250 2.1.0 Ok\r\n").await?;
            }
            "RCPT" => {
                let rcpt = extract_address(trimmed, "TO:");
                match resolve_recipient(snapshot, &rcpt) {
                    Recipient::Deliver(locals) => {
                        for local in locals {
                            if !deliver.contains(&local) {
                                deliver.push(local);
                            }
                        }
                        io.write_all(b"250 2.1.5 Ok\r\n").await?;
                    }
                    Recipient::Backup { rcpt, host, port } => {
                        // We are this domain's backup MX: accept and queue for
                        // forwarding to the primary (no auth required — this is
                        // legitimate inbound MX traffic, not open relaying).
                        if !queue.iter().any(|(r, _, _)| r == &rcpt) {
                            queue.push((rcpt, host, port));
                        }
                        io.write_all(b"250 2.1.5 Ok\r\n").await?;
                    }
                    Recipient::RelayDenied => {
                        // Foreign domain: relay only for an authenticated
                        // submission (never an open relay).
                        if authed {
                            if !relay_to.contains(&rcpt) {
                                relay_to.push(rcpt);
                            }
                            io.write_all(b"250 2.1.5 Ok\r\n").await?;
                        } else {
                            io.write_all(b"550 5.7.1 Relaying denied\r\n").await?;
                        }
                    }
                    Recipient::Unknown => {
                        io.write_all(b"550 5.1.1 No such user here\r\n").await?;
                    }
                }
            }
            "DATA" => {
                if deliver.is_empty() && relay_to.is_empty() && queue.is_empty() {
                    io.write_all(b"503 5.5.1 No valid recipients\r\n").await?;
                    continue;
                }
                io.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    .await?;
                // Cap buffering during the read so an oversized/unterminated body cannot
                // exhaust memory before the size is checked.
                let Some(data) = read_data(io, max_size).await? else {
                    io.write_all(b"552 5.3.4 Message too large\r\n").await?;
                    continue;
                };
                {
                    // Locally-stored copy carries the Received-SPF trace header.
                    let received = match &spf_header {
                        Some(h) => format!("{h}\r\n{data}"),
                        None => data.clone(),
                    };
                    let mut stored = 0usize;
                    // Distinguish "mailbox full" (Ok(false)) from a transient store error
                    // (Err) so the reply code is accurate (452 vs 451) below.
                    let mut deliver_error = false;
                    for rcpt in &deliver {
                        match db.deliver_to_mailbox(rcpt, &sender, &received).await {
                            Ok(true) => stored += 1,
                            Ok(false) => {}
                            Err(_) => deliver_error = true,
                        }
                    }
                    let relayed = if relay_to.is_empty() {
                        0
                    } else {
                        // DKIM-sign the outbound copy with the sender domain's key.
                        let signed = dkim_sign(db, &sender, data.as_bytes()).await;
                        crate::relay::relay_message(relay, &sender, &relay_to, &signed).await
                    };
                    // Backup MX: park queued recipients for durable forwarding to
                    // the primary. Grouped by target so one queue row carries all
                    // recipients bound for the same primary.
                    let queued = enqueue_backup(db, &sender, &queue, &data).await;
                    log_event(
                        db,
                        log_events,
                        format!(
                            "received from={} local={} stored={} relay={} relayed={} queued={} size={} tls={} auth={}",
                            if sender.is_empty() { "<>" } else { &sender },
                            deliver.len(),
                            stored,
                            relay_to.len(),
                            relayed,
                            queued,
                            data.len(),
                            secure,
                            authed
                        ),
                    )
                    .await;
                    if stored + relayed + queued > 0 {
                        io.write_all(b"250 2.0.0 Message accepted\r\n").await?;
                    } else if deliver_error {
                        // A store error (not a full mailbox): ask the client to retry.
                        io.write_all(b"451 4.3.0 Temporary delivery failure\r\n")
                            .await?;
                    } else if !deliver.is_empty() {
                        // Every local mailbox was full.
                        io.write_all(b"452 4.2.2 Mailbox full\r\n").await?;
                    } else {
                        // Relay-only message and every relay attempt failed.
                        io.write_all(b"451 4.4.0 Unable to relay message\r\n")
                            .await?;
                    }
                }
                sender.clear();
                deliver.clear();
                relay_to.clear();
                queue.clear();
            }
            "RSET" => {
                sender.clear();
                deliver.clear();
                relay_to.clear();
                queue.clear();
                io.write_all(b"250 2.0.0 Ok\r\n").await?;
            }
            "NOOP" => io.write_all(b"250 2.0.0 Ok\r\n").await?,
            "QUIT" => {
                io.write_all(b"221 2.0.0 Bye\r\n").await?;
                return Ok(Flow::Done);
            }
            "" => {}
            _ => {
                io.write_all(b"502 5.5.2 Command not implemented\r\n")
                    .await?;
            }
        }
    }
}

/// Run a SASL exchange for `AUTH <mechanism> [initial-response]`. Returns
/// `Some(true)`/`Some(false)` on a completed LOGIN/PLAIN attempt (valid /
/// invalid credentials), or `None` for an unsupported mechanism.
async fn smtp_auth<S>(io: &mut BufReader<S>, db: &Db, rest: &str) -> std::io::Result<Option<bool>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut parts = rest.splitn(2, ' ');
    let mechanism = parts.next().unwrap_or("").to_ascii_uppercase();
    let initial = parts.next().unwrap_or("").trim();

    match mechanism.as_str() {
        "PLAIN" => {
            let token = if initial.is_empty() {
                io.write_all(b"334 \r\n").await?;
                io.flush().await?;
                read_auth_line(io).await?
            } else {
                initial.to_string()
            };
            // authzid \0 authcid \0 passwd
            let Some(decoded) = decode_b64(&token) else {
                return Ok(Some(false));
            };
            let mut fields = decoded.split('\u{0}');
            let _authzid = fields.next();
            let (Some(user), Some(pass)) = (fields.next(), fields.next()) else {
                return Ok(Some(false));
            };
            Ok(Some(verify_login(db, user, pass).await))
        }
        "LOGIN" => {
            io.write_all(b"334 VXNlcm5hbWU6\r\n").await?; // base64("Username:")
            io.flush().await?;
            let Some(user) = decode_b64(&read_auth_line(io).await?) else {
                return Ok(Some(false));
            };
            io.write_all(b"334 UGFzc3dvcmQ6\r\n").await?; // base64("Password:")
            io.flush().await?;
            let Some(pass) = decode_b64(&read_auth_line(io).await?) else {
                return Ok(Some(false));
            };
            Ok(Some(verify_login(db, &user, &pass).await))
        }
        _ => Ok(None),
    }
}

async fn verify_login(db: &Db, user: &str, pass: &str) -> bool {
    let ok = matches!(db.verify_mail_login(user, pass).await, Ok(Some(_)));
    if ok {
        tracing::info!(target: "auth", proto = "smtp", user = %user, "SMTP AUTH ok");
    } else {
        tracing::warn!(target: "auth", proto = "smtp", user = %user, "SMTP AUTH failed");
    }
    ok
}

/// Read one CRLF-terminated SASL continuation line (already base64). Length-capped:
/// an unauthenticated client must not be able to stream an unbounded AUTH line and
/// exhaust memory before any credential is even checked (the command loop is already
/// capped; this closes the same hole on the AUTH continuation).
async fn read_auth_line<R: AsyncBufReadExt + Unpin>(io: &mut R) -> std::io::Result<String> {
    let mut line = String::new();
    crate::line::read_line_capped_timeout(io, &mut line, crate::line::MAX_COMMAND_LINE).await?;
    Ok(line.trim_end().to_string())
}

/// Decode a base64 token to a UTF-8 string (SASL credentials); `None` if the
/// token is not valid base64 or not UTF-8.
fn decode_b64(token: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Read the DATA payload until the `<CRLF>.<CRLF>` terminator, applying
/// Hard ceiling on a single message body, enforced even when no size limit is
/// configured (`max_message_size_bytes == 0`) so an unlimited setting cannot be turned
/// into a memory-exhaustion DoS. Generous versus any real message.
const ABSOLUTE_MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// dot-unstuffing (RFC 5321 §4.5.2). `max` bounds how much is buffered (0 = use the
/// [`ABSOLUTE_MAX_BODY_BYTES`] hard ceiling, NOT unlimited): once the accumulated body
/// exceeds the effective cap, reading stops and `None` is returned so the caller can
/// reject with 552 — this caps memory before the size check (a client must not be able
/// to stream an unbounded body into RAM).
async fn read_data<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max: u64,
) -> std::io::Result<Option<String>> {
    let mut data = String::new();
    let mut line = String::new();
    // An unconfigured limit (`max == 0`) must NOT mean "unbounded": a hostile client
    // could otherwise stream an arbitrarily large body into RAM. Fall back to a hard
    // absolute ceiling so the body is always capped; an explicit `max` (admin choice)
    // still wins when smaller. This also bounds a single unterminated line.
    let effective_max = if max > 0 {
        max.min(ABSOLUTE_MAX_BODY_BYTES)
    } else {
        ABSOLUTE_MAX_BODY_BYTES
    };
    let line_cap = effective_max as usize;
    loop {
        line.clear();
        if crate::line::read_line_capped_timeout(reader, &mut line, line_cap).await? == 0 {
            break;
        }
        if line.trim_end_matches(['\r', '\n']) == "." {
            break;
        }
        let content = line.strip_prefix("..").map(|_| &line[1..]).unwrap_or(&line);
        data.push_str(content);
        if data.len() as u64 > effective_max {
            return Ok(None);
        }
    }
    Ok(Some(data))
}

async fn log_event(db: &Db, enabled: bool, message: String) {
    if !enabled {
        return;
    }
    let _ = db
        .append_log(NewLogEntry {
            domain: DomainKey::Mail,
            log_kind: LogKind::Operation,
            level: LogLevel::Info,
            message,
            at: Utc::now(),
            meta: None,
        })
        .await;
}

/// Park backup-MX recipients in the durable forwarding queue, grouped by their
/// target primary so one queue row carries all recipients bound for the same
/// host. Returns the number of recipients successfully queued.
async fn enqueue_backup(
    db: &Db,
    sender: &str,
    queue: &[(String, String, u16)],
    data: &str,
) -> usize {
    if queue.is_empty() {
        return 0;
    }
    let mut groups: Vec<((String, u16), Vec<String>)> = Vec::new();
    for (rcpt, host, port) in queue {
        let key = (host.clone(), *port);
        if let Some((_, rcpts)) = groups.iter_mut().find(|(k, _)| k == &key) {
            rcpts.push(rcpt.clone());
        } else {
            groups.push((key, vec![rcpt.clone()]));
        }
    }
    let mut queued = 0;
    for ((host, port), rcpts) in groups {
        match db
            .enqueue_backup_mail(sender, &rcpts, &host, port, data)
            .await
        {
            Ok(()) => queued += rcpts.len(),
            Err(e) => tracing::warn!("backup MX enqueue to {host}:{port} failed: {e}"),
        }
    }
    queued
}

/// How long to wait before retry `attempts` (1-based): 1, 2, 4, 8, 16, capped at
/// 30 minutes. Bounds the queue drain rate while a primary stays down.
fn backoff_delay(attempts: u32) -> chrono::Duration {
    let mins = 1u64 << attempts.saturating_sub(1).min(5);
    chrono::Duration::minutes(mins.min(30) as i64)
}

/// Forward one queued message to its primary: delete on success, reschedule with
/// [`backoff_delay`] on failure, and on final give-up return a non-delivery
/// report (DSN) to the sender before dropping it.
async fn forward_queued(
    db: &Db,
    relay: &Option<RelayConfig>,
    item: magnetite_db::QueuedForward,
    max_attempts: u32,
) {
    let accepted = crate::relay::forward_to_host(
        &item.primary_host,
        item.primary_port,
        &item.sender,
        &item.recipients,
        item.raw.as_bytes(),
    )
    .await;
    if accepted > 0 {
        // Log a delete failure: the row would otherwise stay due and be re-forwarded
        // (duplicate delivery) until the delete eventually succeeds.
        if let Err(e) = db.delete_backup_queue(&item.id).await {
            tracing::warn!(
                "backup MX: forwarded queue {} but could not delete it ({e}); it may be re-forwarded",
                item.id
            );
        }
        return;
    }
    let attempts = item.attempts + 1;
    if attempts >= max_attempts {
        tracing::warn!(
            "backup MX: giving up on queue {} after {attempts} attempts to {}:{}",
            item.id,
            item.primary_host,
            item.primary_port
        );
        send_bounce(db, relay, &item).await;
        if let Err(e) = db.delete_backup_queue(&item.id).await {
            tracing::warn!(
                "backup MX: could not delete abandoned queue {} ({e})",
                item.id
            );
        }
        return;
    }
    let next = Utc::now() + backoff_delay(attempts);
    let _ = db
        .reschedule_backup_mail(&item.id, attempts, next, "primary unreachable")
        .await;
}

/// Return a non-delivery report (RFC 3464) to the original sender for a message
/// the backup-MX queue could not deliver. A null return-path (empty sender) is
/// never bounced (avoids mail loops).
async fn send_bounce(db: &Db, relay: &Option<RelayConfig>, item: &magnetite_db::QueuedForward) {
    if item.sender.trim().is_empty() {
        return;
    }
    // Source the relay live from the DB (Web-UI editable), falling back to the file config.
    let relay = effective_relay(db, relay.clone()).await;
    let hostname = db
        .get_mail_config()
        .await
        .ok()
        .map(|c| c.hostname)
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| "localhost".to_string());
    let reason = format!(
        "Unable to deliver to the primary server {}:{} after repeated attempts.",
        item.primary_host, item.primary_port
    );
    let dsn = crate::dsn::build_bounce(
        Utc::now(),
        &hostname,
        &item.sender,
        &item.recipients,
        &reason,
        &item.raw,
    );
    // Deliver the bounce back to the sender: to a local mailbox when the sender is
    // hosted here, otherwise relayed out (with a null return-path).
    let snapshot = load_snapshot(db).await;
    match resolve_recipient(&snapshot, &item.sender) {
        Recipient::Deliver(locals) => {
            for local in &locals {
                let _ = db.deliver_to_mailbox(local, "", &dsn).await;
            }
        }
        _ => {
            crate::relay::relay_message(
                relay.as_ref(),
                "",
                std::slice::from_ref(&item.sender),
                dsn.as_bytes(),
            )
            .await;
        }
    }
}

/// Background worker that drains the backup-MX forwarding queue on a fixed tick,
/// forwarding due messages to their primary and retrying with backoff. Ends when
/// the shared shutdown signal fires.
async fn queue_task(db: Db, relay: Option<RelayConfig>, mut shutdown: watch::Receiver<bool>) {
    const TICK: Duration = Duration::from_secs(30);
    const BATCH: usize = 32;
    const MAX_ATTEMPTS: u32 = 12;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            _ = tokio::time::sleep(TICK) => {
                let due = db.due_backup_queue(BATCH).await.unwrap_or_default();
                for item in due {
                    forward_queued(&db, &relay, item, MAX_ATTEMPTS).await;
                }
            }
        }
    }
}

/// A stream handed to a protocol handler after the implicit-TLS handshake.
type MailTlsStream = tokio_rustls::server::TlsStream<TcpStream>;

/// Spawn the SMTPS (implicit-TLS SMTP) listener when the `smtps` port is set.
fn spawn_tls_smtp(
    port: Option<u16>,
    acceptor: &TlsAcceptor,
    db: &Db,
    shutdown: &watch::Receiver<bool>,
    ip: std::net::IpAddr,
    log_events: bool,
    relay: Option<RelayConfig>,
) {
    let Some(p) = port else { return };
    let a = SocketAddr::new(ip, p);
    let (acceptor, db, sd) = (acceptor.clone(), db.clone(), shutdown.clone());
    tokio::spawn(async move {
        let handler = move |tls: MailTlsStream| {
            let db = db.clone();
            let relay = relay.clone();
            // Already on TLS: session is secure, STARTTLS not offered.
            // Implicit-TLS submission: authenticated, no inbound SPF check.
            async move { handle_connection(tls, db, log_events, None, true, relay, None).await }
        };
        if let Err(e) = crate::tls::accept_loop(a, acceptor, sd, handler).await {
            tracing::error!("SMTPS server on {a} failed: {e}");
        }
    });
}

/// Spawn the IMAPS (implicit-TLS IMAP) listener when the `imaps` port is set.
fn spawn_tls_imap(
    port: Option<u16>,
    acceptor: &TlsAcceptor,
    db: &Db,
    shutdown: &watch::Receiver<bool>,
    ip: std::net::IpAddr,
) {
    let Some(p) = port else { return };
    let a = SocketAddr::new(ip, p);
    let (acceptor, db, sd) = (acceptor.clone(), db.clone(), shutdown.clone());
    tokio::spawn(async move {
        let handler = move |tls: MailTlsStream| {
            let db = db.clone();
            async move { crate::imap::handle_connection(tls, db, None, true).await }
        };
        if let Err(e) = crate::tls::accept_loop(a, acceptor, sd, handler).await {
            tracing::error!("IMAPS server on {a} failed: {e}");
        }
    });
}

/// Spawn the POP3S (implicit-TLS POP3) listener when the `pop3s` port is set.
fn spawn_tls_pop3(
    port: Option<u16>,
    acceptor: &TlsAcceptor,
    db: &Db,
    shutdown: &watch::Receiver<bool>,
    ip: std::net::IpAddr,
) {
    let Some(p) = port else { return };
    let a = SocketAddr::new(ip, p);
    let (acceptor, db, sd) = (acceptor.clone(), db.clone(), shutdown.clone());
    tokio::spawn(async move {
        let handler = move |tls: MailTlsStream| {
            let db = db.clone();
            async move { crate::pop3::handle_connection(tls, db, None, true).await }
        };
        if let Err(e) = crate::tls::accept_loop(a, acceptor, sd, handler).await {
            tracing::error!("POP3S server on {a} failed: {e}");
        }
    });
}

async fn run(
    addr: SocketAddr,
    db: Db,
    mut shutdown: watch::Receiver<bool>,
    health: Arc<AtomicU8>,
    log_events: bool,
    relay: Option<RelayConfig>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    health.store(H_HEALTHY, Ordering::Relaxed);
    // Offer STARTTLS on the plaintext port when a mail certificate is configured
    // (built once at startup, like the S-port acceptors — restart to change).
    let starttls = crate::tls::mail_tls_acceptor(&db).await;
    tracing::info!(
        "SMTP server listening on {addr} (STARTTLS {}, relay {})",
        if starttls.is_some() { "on" } else { "off" },
        if relay.is_some() {
            "smarthost"
        } else {
            "direct"
        }
    );

    let conns = crate::conn::limiter();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(v) => v, Err(_) => continue };
                // Bound concurrent connections: drop over the cap rather than spawn
                // an unbounded task per socket under a connection flood.
                let Ok(permit) = conns.clone().try_acquire_owned() else {
                    tracing::warn!(target: "conn", %peer, "SMTP conn limit reached; dropping");
                    continue;
                };
                tracing::debug!(target: "conn", %peer, "SMTP connection");
                let db = db.clone();
                let starttls = starttls.clone();
                let relay = relay.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // Inbound plaintext connection → SPF-check the connecting IP.
                    if let Err(e) = handle_connection(
                        stream, db, log_events, starttls, false, relay, Some(peer.ip()),
                    )
                    .await
                    {
                        tracing::debug!("SMTP connection error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::domains::mail::model::{BackupMxDomain, MailDomain};

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        db.save_mail_domain(&MailDomain {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: "example.com".into(),
            enabled: true,
            max_users: None,
            default_quota_bytes: None,
        })
        .await
        .unwrap();
        db.create_mail_user("alice", "example.com", None, 0, "password12", "admin")
            .await
            .unwrap();
        (db, dir)
    }

    async fn start_server(db: Db) -> (SocketAddr, watch::Sender<bool>) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let svc = MailService::new(addr, true, None);
        let (tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(svc.health(), ServiceHealth::Healthy);
        (addr, tx)
    }

    /// Minimal SMTP client: sends `cmd\r\n` and returns the 3-digit reply code.
    async fn cmd<R: AsyncBufReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        reader: &mut R,
        writer: &mut W,
        line: &str,
    ) -> u16 {
        writer.write_all(line.as_bytes()).await.unwrap();
        writer.write_all(b"\r\n").await.unwrap();
        read_code(reader).await
    }

    async fn read_code<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> u16 {
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        resp[..3].parse().unwrap_or(0)
    }

    #[tokio::test]
    async fn accepts_and_stores_local_mail() {
        let (db, _dir) = test_db().await;
        let (addr, _tx) = start_server(db.clone()).await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);

        assert_eq!(read_code(&mut reader).await, 220); // greeting
        assert_eq!(cmd(&mut reader, &mut wr, "EHLO client").await, 250);
        assert_eq!(
            cmd(&mut reader, &mut wr, "MAIL FROM:<sender@remote.org>").await,
            250
        );
        assert_eq!(
            cmd(&mut reader, &mut wr, "RCPT TO:<alice@example.com>").await,
            250
        );
        assert_eq!(cmd(&mut reader, &mut wr, "DATA").await, 354);
        wr.write_all(b"Subject: hi\r\n\r\nHello Alice\r\n.\r\n")
            .await
            .unwrap();
        assert_eq!(read_code(&mut reader).await, 250); // accepted
        assert_eq!(cmd(&mut reader, &mut wr, "QUIT").await, 221);

        assert_eq!(
            db.count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn rejects_unknown_and_relay() {
        let (db, _dir) = test_db().await;
        let (addr, _tx) = start_server(db).await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);
        assert_eq!(read_code(&mut reader).await, 220);
        assert_eq!(cmd(&mut reader, &mut wr, "EHLO client").await, 250);
        assert_eq!(cmd(&mut reader, &mut wr, "MAIL FROM:<x@y.org>").await, 250);
        // Unknown mailbox in a hosted domain.
        assert_eq!(
            cmd(&mut reader, &mut wr, "RCPT TO:<ghost@example.com>").await,
            550
        );
        // Foreign domain → relay denied.
        assert_eq!(
            cmd(&mut reader, &mut wr, "RCPT TO:<user@foreign.net>").await,
            550
        );
    }

    #[tokio::test]
    async fn over_quota_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        db.save_mail_domain(&MailDomain {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: "example.com".into(),
            enabled: true,
            max_users: None,
            default_quota_bytes: None,
        })
        .await
        .unwrap();
        // 5-byte mailbox.
        db.create_mail_user("tiny", "example.com", None, 5, "password12", "admin")
            .await
            .unwrap();
        let (addr, _tx) = start_server(db.clone()).await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);
        assert_eq!(read_code(&mut reader).await, 220);
        assert_eq!(cmd(&mut reader, &mut wr, "EHLO c").await, 250);
        assert_eq!(cmd(&mut reader, &mut wr, "MAIL FROM:<s@r.org>").await, 250);
        assert_eq!(
            cmd(&mut reader, &mut wr, "RCPT TO:<tiny@example.com>").await,
            250
        );
        assert_eq!(cmd(&mut reader, &mut wr, "DATA").await, 354);
        wr.write_all(b"this body is well over five bytes\r\n.\r\n")
            .await
            .unwrap();
        assert_eq!(read_code(&mut reader).await, 452); // mailbox full

        assert_eq!(
            db.count_mail_messages_for("tiny@example.com")
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn backoff_delay_grows_and_caps() {
        assert_eq!(backoff_delay(1), chrono::Duration::minutes(1));
        assert_eq!(backoff_delay(2), chrono::Duration::minutes(2));
        assert_eq!(backoff_delay(3), chrono::Duration::minutes(4));
        assert_eq!(backoff_delay(5), chrono::Duration::minutes(16));
        // Large attempt counts are capped at 30 minutes.
        assert_eq!(backoff_delay(20), chrono::Duration::minutes(30));
    }

    #[tokio::test]
    async fn backup_queue_roundtrip() {
        let (db, _dir) = test_db().await;
        db.enqueue_backup_mail(
            "s@remote.org",
            &["user@backup.test".to_string()],
            "mx.primary.test",
            25,
            "Subject: q\r\n\r\nbody\r\n",
        )
        .await
        .unwrap();
        assert_eq!(db.count_backup_queue().await.unwrap(), 1);

        // Due immediately on first insert.
        let due = db.due_backup_queue(10).await.unwrap();
        assert_eq!(due.len(), 1);
        let item = due[0].clone();
        assert_eq!(item.recipients, vec!["user@backup.test".to_string()]);
        assert_eq!(item.primary_host, "mx.primary.test");

        // Reschedule into the future → no longer due, but still listed.
        db.reschedule_backup_mail(
            &item.id,
            1,
            Utc::now() + chrono::Duration::minutes(10),
            "primary unreachable",
        )
        .await
        .unwrap();
        assert!(db.due_backup_queue(10).await.unwrap().is_empty());
        let entries = db.list_backup_queue(10).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attempts, 1);
        assert_eq!(
            entries[0].last_error.as_deref(),
            Some("primary unreachable")
        );

        db.delete_backup_queue(&item.id).await.unwrap();
        assert_eq!(db.count_backup_queue().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn backup_mx_queues_inbound_for_primary() {
        let (db, _dir) = test_db().await;
        // We are the backup MX for backup.test; the primary is unreachable here,
        // so an accepted message must be parked for later forwarding.
        db.save_backup_mx(&BackupMxDomain {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: "backup.test".into(),
            primary_host: "127.0.0.1".into(),
            primary_port: 1,
            enabled: true,
        })
        .await
        .unwrap();
        let (addr, _tx) = start_server(db.clone()).await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);
        assert_eq!(read_code(&mut reader).await, 220);
        assert_eq!(cmd(&mut reader, &mut wr, "EHLO client").await, 250);
        assert_eq!(
            cmd(&mut reader, &mut wr, "MAIL FROM:<s@remote.org>").await,
            250
        );
        // No AUTH: a backup-MX recipient is accepted (legitimate inbound MX,
        // not open relaying).
        assert_eq!(
            cmd(&mut reader, &mut wr, "RCPT TO:<user@backup.test>").await,
            250
        );
        assert_eq!(cmd(&mut reader, &mut wr, "DATA").await, 354);
        wr.write_all(b"Subject: hi\r\n\r\nqueued for primary\r\n.\r\n")
            .await
            .unwrap();
        assert_eq!(read_code(&mut reader).await, 250); // accepted (queued)
        assert_eq!(cmd(&mut reader, &mut wr, "QUIT").await, 221);

        // Parked in the durable queue for forwarding to the primary.
        assert_eq!(db.count_backup_queue().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn mailbox_replication_feed_apply_and_delete() {
        let (primary, _d1) = test_db().await;
        let (secondary, _d2) = test_db().await;

        primary
            .store_mail_message(
                "alice@example.com",
                "s1@remote.org",
                "Subject: a\r\n\r\n1\r\n",
            )
            .await
            .unwrap();
        primary
            .store_mail_message(
                "alice@example.com",
                "s2@remote.org",
                "Subject: b\r\n\r\n2\r\n",
            )
            .await
            .unwrap();

        // Full pull (empty cursor) → both messages, applied idempotently.
        let feed = primary.mail_repl_feed("", 100).await.unwrap();
        assert_eq!(feed.messages.len(), 2);
        let mut applied = 0;
        for m in &feed.messages {
            if secondary.apply_replicated_message(m).await.unwrap() {
                applied += 1;
            }
        }
        assert_eq!(applied, 2);
        assert_eq!(
            secondary
                .count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            2
        );
        // Re-applying the same feed inserts nothing (idempotent).
        for m in &feed.messages {
            assert!(!secondary.apply_replicated_message(m).await.unwrap());
        }
        assert_eq!(
            secondary
                .count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            2
        );

        // Delete one on the primary → deletion appears past the cursor and mirrors.
        let msgs = primary
            .list_mail_messages(Some("alice@example.com"), 10)
            .await
            .unwrap();
        primary.delete_mail_message(&msgs[0].id).await.unwrap();
        let feed2 = primary.mail_repl_feed(&feed.cursor, 100).await.unwrap();
        assert_eq!(feed2.deletions.len(), 1);
        let mut deleted = 0;
        for repl_id in &feed2.deletions {
            if secondary.apply_replicated_deletion(repl_id).await.unwrap() {
                deleted += 1;
            }
        }
        assert_eq!(deleted, 1);
        assert_eq!(
            secondary
                .count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            1
        );

        // Replication state accumulates across passes.
        secondary
            .record_mail_repl_sync(&feed.cursor, 2, 0, None)
            .await
            .unwrap();
        secondary
            .record_mail_repl_sync(&feed2.cursor, 0, 1, Some("transient"))
            .await
            .unwrap();
        let st = secondary.get_mail_repl_state().await.unwrap();
        assert_eq!(st.applied, 2);
        assert_eq!(st.deleted, 1);
        assert_eq!(st.cursor, feed2.cursor);
        assert_eq!(st.last_error.as_deref(), Some("transient"));
        assert!(st.last_sync.is_some());
    }

    #[tokio::test]
    async fn mailbox_replication_syncs_flags() {
        let (primary, _d1) = test_db().await;
        let (secondary, _d2) = test_db().await;

        primary
            .store_mail_message(
                "alice@example.com",
                "s@remote.org",
                "Subject: a\r\n\r\n1\r\n",
            )
            .await
            .unwrap();
        let feed = primary.mail_repl_feed("", 100).await.unwrap();
        for m in &feed.messages {
            secondary.apply_replicated_message(m).await.unwrap();
        }

        // Set a flag on the primary → it appears in the feed past the cursor.
        let msgs = primary
            .list_mail_messages(Some("alice@example.com"), 10)
            .await
            .unwrap();
        primary
            .set_mail_flags(&msgs[0].id, &["\\Seen".to_string()])
            .await
            .unwrap();
        let feed2 = primary.mail_repl_feed(&feed.cursor, 100).await.unwrap();
        assert_eq!(feed2.flag_updates.len(), 1);
        assert_eq!(feed2.flag_updates[0].flags, vec!["\\Seen".to_string()]);

        // The secondary mirrors the flag by repl_id.
        for update in &feed2.flag_updates {
            assert!(secondary
                .apply_replicated_flags(&update.repl_id, &update.flags)
                .await
                .unwrap());
        }
        let mirrored = secondary
            .list_mail_messages(Some("alice@example.com"), 10)
            .await
            .unwrap();
        assert_eq!(mirrored[0].flags, vec!["\\Seen".to_string()]);
    }

    #[tokio::test]
    async fn backup_giveup_bounces_to_local_sender() {
        let (db, _dir) = test_db().await;
        // A queued message from a local sender whose primary never came back.
        let item = magnetite_db::QueuedForward {
            id: "q:test".into(),
            sender: "alice@example.com".into(),
            recipients: vec!["user@backup.test".into()],
            primary_host: "127.0.0.1".into(),
            primary_port: 1,
            raw: "Subject: hi\r\n\r\nbody\r\n".into(),
            attempts: 11,
        };
        send_bounce(&db, &None, &item).await;

        // A non-delivery report lands in the local sender's mailbox.
        assert_eq!(
            db.count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            1
        );
        let msgs = db
            .list_mail_messages(Some("alice@example.com"), 5)
            .await
            .unwrap();
        let raw = db.get_mail_message_raw(&msgs[0].id).await.unwrap().unwrap();
        assert!(raw.contains("Undelivered Mail Returned to Sender"));
        assert!(raw.contains("Final-Recipient: rfc822; user@backup.test"));
    }

    #[tokio::test]
    async fn backup_giveup_never_bounces_null_sender() {
        let (db, _dir) = test_db().await;
        // A null return-path (empty sender) must never be bounced (loop guard).
        let item = magnetite_db::QueuedForward {
            id: "q:test".into(),
            sender: String::new(),
            recipients: vec!["user@backup.test".into()],
            primary_host: "127.0.0.1".into(),
            primary_port: 1,
            raw: "Subject: hi\r\n\r\nbody\r\n".into(),
            attempts: 11,
        };
        send_bounce(&db, &None, &item).await;
        assert_eq!(db.count_mail_messages().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn read_data_unstuffs_and_terminates() {
        let input = b"line one\r\n..dotted\r\n.\r\nIGNORED";
        let mut reader = BufReader::new(&input[..]);
        let data = read_data(&mut reader, 0).await.unwrap().unwrap();
        assert_eq!(data, "line one\r\n.dotted\r\n");
    }

    #[tokio::test]
    async fn read_data_rejects_body_over_max() {
        // Each line fits the per-line cap, but the body accumulates past the 8-byte
        // limit before the terminator → None (caller replies 552).
        let input = b"aaaa\r\nbbbb\r\n.\r\n";
        let mut reader = BufReader::new(&input[..]);
        assert!(read_data(&mut reader, 8).await.unwrap().is_none());
    }

    /// A rustls verifier that accepts any server certificate (test client).
    #[derive(Debug)]
    struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    async fn free_port() -> u16 {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    }

    /// End-to-end implicit TLS: a rustls client speaks POP3 over the POP3S port,
    /// proving the certificate is presented and the plaintext handler runs on the
    /// decrypted stream.
    #[tokio::test]
    async fn pop3s_serves_over_implicit_tls() {
        use tokio_rustls::TlsConnector;

        let (db, _dir) = test_db().await;
        db.store_mail_message(
            "alice@example.com",
            "s@remote.org",
            "Subject: hi\r\n\r\nyo\r\n",
        )
        .await
        .unwrap();

        // Self-signed cert for the mail host, stored with its private key.
        let cert =
            rcgen::generate_simple_self_signed(vec!["mail.example.com".to_string()]).unwrap();
        db.create_certificate(
            "mailcert",
            "CN=mail.example.com",
            "self",
            &["mail.example.com".to_string()],
            Utc::now(),
            Utc::now() + chrono::Duration::days(90),
            &cert.cert.pem(),
            None,
            Some(&cert.key_pair.serialize_pem()),
            "admin",
        )
        .await
        .unwrap();

        // Point the mail config at the cert and enable POP3S on a free port.
        let pop3s_port = free_port().await;
        let mut config = db.get_mail_config().await.unwrap();
        config.hostname = "mail.example.com".into();
        config.tls_cert_name = Some("mailcert".into());
        if let Some(p) = config.protocols.get_mut("pop3s") {
            p.enabled = true;
            p.port = pop3s_port;
        }
        db.save_mail_config(&config).await.unwrap();

        let smtp_port = free_port().await;
        let smtp_addr: SocketAddr = format!("127.0.0.1:{smtp_port}").parse().unwrap();
        let svc = MailService::new(smtp_addr, false, None);
        let (_tx, rx) = watch::channel(false);
        svc.start(db.clone(), rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // TLS client accepting any cert.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client));
        let server_name = rustls::pki_types::ServerName::try_from("mail.example.com").unwrap();
        let pop3s_addr: SocketAddr = format!("127.0.0.1:{pop3s_port}").parse().unwrap();

        // Retry until the POP3S listener is up and the handshake succeeds.
        let tls = {
            let mut s = None;
            for _ in 0..50 {
                if let Ok(tcp) = TcpStream::connect(pop3s_addr).await {
                    if let Ok(t) = connector.connect(server_name.clone(), tcp).await {
                        s = Some(t);
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            s.expect("POP3S not serving TLS")
        };

        let (rd, mut wr) = tokio::io::split(tls);
        let mut reader = BufReader::new(rd);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.starts_with("+OK"), "greeting: {greeting:?}");

        // POP3 replies are +OK/-ERR lines, not 3-digit codes.
        let mut reply = String::new();
        wr.write_all(b"USER alice@example.com\r\n").await.unwrap();
        reader.read_line(&mut reply).await.unwrap();
        assert!(reply.starts_with("+OK"), "user: {reply:?}");

        reply.clear();
        wr.write_all(b"PASS password12\r\n").await.unwrap();
        reader.read_line(&mut reply).await.unwrap();
        assert!(reply.starts_with("+OK"), "pass: {reply:?}");

        reply.clear();
        wr.write_all(b"STAT\r\n").await.unwrap();
        reader.read_line(&mut reply).await.unwrap();
        assert!(reply.starts_with("+OK 1"), "stat: {reply:?}");
    }

    /// Store a self-signed cert named `mailcert` and point the mail config at it,
    /// enabling STARTTLS on the plaintext ports.
    async fn seed_mail_cert(db: &Db) {
        let cert =
            rcgen::generate_simple_self_signed(vec!["mail.example.com".to_string()]).unwrap();
        db.create_certificate(
            "mailcert",
            "CN=mail.example.com",
            "self",
            &["mail.example.com".to_string()],
            Utc::now(),
            Utc::now() + chrono::Duration::days(90),
            &cert.cert.pem(),
            None,
            Some(&cert.key_pair.serialize_pem()),
            "admin",
        )
        .await
        .unwrap();
        let mut config = db.get_mail_config().await.unwrap();
        config.hostname = "mail.example.com".into();
        config.tls_cert_name = Some("mailcert".into());
        db.save_mail_config(&config).await.unwrap();
    }

    fn tls_client() -> tokio_rustls::TlsConnector {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    /// Read SMTP reply lines until the final `NNN ` (space) line; return them joined.
    async fn read_smtp_reply<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> String {
        let mut acc = String::new();
        loop {
            let mut l = String::new();
            reader.read_line(&mut l).await.unwrap();
            let done = l.len() >= 4 && l.as_bytes()[3] == b' ';
            acc.push_str(&l);
            if done || l.is_empty() {
                break;
            }
        }
        acc
    }

    /// End-to-end SMTP STARTTLS + AUTH LOGIN: upgrade the plaintext session to
    /// TLS, authenticate, then submit a message that is stored.
    #[tokio::test]
    async fn smtp_starttls_then_auth_and_deliver() {
        use base64::Engine;

        let (db, _dir) = test_db().await;
        seed_mail_cert(&db).await;

        let smtp_port = free_port().await;
        let smtp_addr: SocketAddr = format!("127.0.0.1:{smtp_port}").parse().unwrap();
        let svc = MailService::new(smtp_addr, false, None);
        let (_tx, rx) = watch::channel(false);
        svc.start(db.clone(), rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Plaintext phase: greeting, EHLO advertises STARTTLS.
        let tcp = {
            let mut s = None;
            for _ in 0..50 {
                if let Ok(c) = TcpStream::connect(smtp_addr).await {
                    s = Some(c);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            s.expect("SMTP not listening")
        };
        let (rd, mut wr) = tokio::io::split(tcp);
        let mut reader = BufReader::new(rd);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.starts_with("220"), "greeting: {greeting:?}");

        wr.write_all(b"EHLO client\r\n").await.unwrap();
        let ehlo = read_smtp_reply(&mut reader).await;
        assert!(
            ehlo.contains("STARTTLS"),
            "no STARTTLS advertised: {ehlo:?}"
        );

        wr.write_all(b"STARTTLS\r\n").await.unwrap();
        let mut r = String::new();
        reader.read_line(&mut r).await.unwrap();
        assert!(r.starts_with("220"), "starttls: {r:?}");

        // Reunite the split halves and perform the TLS handshake.
        let tcp = reader.into_inner().unsplit(wr);
        let server_name = rustls::pki_types::ServerName::try_from("mail.example.com").unwrap();
        let tls = tls_client().connect(server_name, tcp).await.unwrap();
        let (rd, mut wr) = tokio::io::split(tls);
        let mut reader = BufReader::new(rd);

        // Over TLS: EHLO now advertises AUTH.
        wr.write_all(b"EHLO client\r\n").await.unwrap();
        let ehlo = read_smtp_reply(&mut reader).await;
        assert!(
            ehlo.contains("AUTH"),
            "no AUTH advertised over TLS: {ehlo:?}"
        );

        // AUTH LOGIN.
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        wr.write_all(b"AUTH LOGIN\r\n").await.unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("334"), "auth user prompt: {line:?}");
        wr.write_all(format!("{}\r\n", b64("alice@example.com")).as_bytes())
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("334"), "auth pass prompt: {line:?}");
        wr.write_all(format!("{}\r\n", b64("password12")).as_bytes())
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("235"), "auth result: {line:?}");

        // Submit a message.
        wr.write_all(b"MAIL FROM:<alice@example.com>\r\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250"));
        wr.write_all(b"RCPT TO:<alice@example.com>\r\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250"));
        wr.write_all(b"DATA\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("354"));
        wr.write_all(b"Subject: secure\r\n\r\nover starttls\r\n.\r\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250"), "data result: {line:?}");

        assert_eq!(
            db.count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            1
        );
    }

    /// A throwaway SMTP sink that accepts one transaction and reports the
    /// envelope recipients + message body it received. Stands in for a smarthost.
    async fn fake_smtp_sink() -> (
        u16,
        tokio::sync::mpsc::UnboundedReceiver<(Vec<String>, String)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let (rd, mut wr) = tokio::io::split(stream);
                    let mut reader = BufReader::new(rd);
                    wr.write_all(b"220 sink ESMTP\r\n").await.ok();
                    let mut rcpts = Vec::new();
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        let up = line.trim_end().to_ascii_uppercase();
                        if up.starts_with("EHLO") || up.starts_with("HELO") {
                            wr.write_all(b"250 sink\r\n").await.ok();
                        } else if up.starts_with("RCPT") {
                            rcpts.push(line.trim_end().to_string());
                            wr.write_all(b"250 ok\r\n").await.ok();
                        } else if up.starts_with("DATA") {
                            wr.write_all(b"354 go\r\n").await.ok();
                            let mut body = String::new();
                            loop {
                                let mut l = String::new();
                                if reader.read_line(&mut l).await.unwrap_or(0) == 0 {
                                    break;
                                }
                                if l.trim_end_matches(['\r', '\n']) == "." {
                                    break;
                                }
                                body.push_str(&l);
                            }
                            wr.write_all(b"250 queued\r\n").await.ok();
                            let _ = tx.send((rcpts.clone(), body));
                        } else if up.starts_with("QUIT") {
                            wr.write_all(b"221 bye\r\n").await.ok();
                            break;
                        } else {
                            // MAIL/RSET/NOOP/etc.
                            wr.write_all(b"250 ok\r\n").await.ok();
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    /// End-to-end outbound relay: an authenticated submission to a foreign domain
    /// is relayed through the configured smarthost (the fake sink).
    #[tokio::test]
    async fn authenticated_submission_relays_to_smarthost() {
        use base64::Engine;

        let (db, _dir) = test_db().await;
        seed_mail_cert(&db).await;

        // Smarthost sink + mail service pointed at it.
        let (sink_port, mut sink_rx) = fake_smtp_sink().await;
        let relay = RelayConfig {
            host: "127.0.0.1".into(),
            port: sink_port,
            username: None,
            password: None,
        };
        let smtp_port = free_port().await;
        let smtp_addr: SocketAddr = format!("127.0.0.1:{smtp_port}").parse().unwrap();
        let svc = MailService::new(smtp_addr, false, Some(relay));
        let (_tx, rx) = watch::channel(false);
        svc.start(db.clone(), rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Connect, upgrade to TLS, authenticate (required to relay).
        let tcp = {
            let mut s = None;
            for _ in 0..50 {
                if let Ok(c) = TcpStream::connect(smtp_addr).await {
                    s = Some(c);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            s.expect("SMTP not listening")
        };
        let (rd, mut wr) = tokio::io::split(tcp);
        let mut reader = BufReader::new(rd);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap(); // greeting
        wr.write_all(b"EHLO client\r\n").await.unwrap();
        let _ = read_smtp_reply(&mut reader).await;
        wr.write_all(b"STARTTLS\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("220"));

        let tcp = reader.into_inner().unsplit(wr);
        let server_name = rustls::pki_types::ServerName::try_from("mail.example.com").unwrap();
        let tls = tls_client().connect(server_name, tcp).await.unwrap();
        let (rd, mut wr) = tokio::io::split(tls);
        let mut reader = BufReader::new(rd);
        wr.write_all(b"EHLO client\r\n").await.unwrap();
        let _ = read_smtp_reply(&mut reader).await;

        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        wr.write_all(b"AUTH LOGIN\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        wr.write_all(format!("{}\r\n", b64("alice@example.com")).as_bytes())
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        wr.write_all(format!("{}\r\n", b64("password12")).as_bytes())
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("235"), "auth: {line:?}");

        // Submit to a FOREIGN domain — accepted for relay, not stored locally.
        wr.write_all(b"MAIL FROM:<alice@example.com>\r\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250"));
        wr.write_all(b"RCPT TO:<bob@remote.test>\r\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250"), "foreign rcpt: {line:?}");
        wr.write_all(b"DATA\r\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("354"));
        wr.write_all(b"Subject: relayed\r\n\r\nhello remote\r\n.\r\n")
            .await
            .unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("250"), "relay accept: {line:?}");

        // The smarthost received the message for the foreign recipient.
        let (rcpts, body) = tokio::time::timeout(std::time::Duration::from_secs(5), sink_rx.recv())
            .await
            .expect("smarthost timed out")
            .expect("smarthost channel closed");
        assert!(
            rcpts.iter().any(|r| r.contains("bob@remote.test")),
            "smarthost recipients: {rcpts:?}"
        );
        assert!(body.contains("hello remote"), "smarthost body: {body:?}");

        // Nothing stored locally for the foreign recipient.
        assert_eq!(
            db.count_mail_messages_for("bob@remote.test").await.unwrap(),
            0
        );
    }
}
