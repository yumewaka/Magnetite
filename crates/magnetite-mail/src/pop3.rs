//! The embedded POP3 retrieval server (E4c). Lets mail clients download and
//! delete messages from a mailbox. Runs alongside the SMTP server, on the port
//! from the mail config's `pop3` protocol entry.
//!
//! Scope: USER/PASS auth against the mail user, CAPA, STAT/LIST/UIDL/RETR/DELE/
//! RSET/NOOP/QUIT, and STLS (STARTTLS upgrade) when a mail certificate is
//! configured. Deferred: APOP, TOP.

use crate::tls::Flow;
use magnetite_db::Db;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

/// Bind and serve POP3 until `shutdown` fires.
pub(crate) async fn serve(
    addr: SocketAddr,
    db: Db,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    // STLS is offered when a mail certificate is configured (built once, like
    // the S-port acceptors).
    let starttls = crate::tls::mail_tls_acceptor(&db).await;
    tracing::info!(
        "POP3 server listening on {addr} (STLS {})",
        if starttls.is_some() { "on" } else { "off" }
    );
    let conns = crate::conn::limiter();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(v) => v, Err(_) => continue };
                let Ok(permit) = conns.clone().try_acquire_owned() else {
                    tracing::warn!(target: "conn", %peer, "POP3 conn limit reached; dropping");
                    continue;
                };
                tracing::debug!(target: "conn", %peer, "POP3 connection");
                let db = db.clone();
                let starttls = starttls.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, db, starttls, false).await {
                        tracing::debug!("POP3 connection error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

/// One dot-stuffed multiline RETR body terminated by `<CRLF>.<CRLF>`.
fn dot_stuff(raw: &str) -> String {
    let mut body = raw.replace("\r\n.", "\r\n..");
    if body.starts_with('.') {
        body.insert(0, '.');
    }
    if !body.ends_with("\r\n") {
        body.push_str("\r\n");
    }
    body.push_str(".\r\n");
    body
}

pub(crate) async fn handle_connection<S>(
    stream: S,
    db: Db,
    starttls: Option<TlsAcceptor>,
    secure: bool,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut io = BufReader::new(stream);
    io.write_all(b"+OK Magnetite POP3 ready\r\n").await?;

    let offer_tls = starttls.is_some() && !secure;
    if let Flow::StartTls = pop3_dialog(&mut io, &db, offer_tls).await? {
        // STLS: reunite the stream, wrap in TLS, resume on the encrypted channel.
        let acceptor = starttls.expect("STLS only offered when acceptor present");
        let tls = acceptor.accept(io.into_inner()).await?;
        let mut io = BufReader::new(tls);
        pop3_dialog(&mut io, &db, false).await?;
    }
    Ok(())
}

/// The POP3 command loop. Returns [`Flow::StartTls`] when the client issued
/// `STLS` (and it was offered). `offer_tls` advertises STLS in CAPA.
async fn pop3_dialog<S>(io: &mut BufReader<S>, db: &Db, offer_tls: bool) -> std::io::Result<Flow>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut user = String::new();
    let mut mailbox: Vec<(String, String)> = Vec::new(); // (id, raw)
    let mut deleted: Vec<bool> = Vec::new();
    let mut authed = false;
    let mut line = String::new();

    loop {
        line.clear();
        if crate::line::read_line_capped_timeout(io, &mut line, crate::line::MAX_COMMAND_LINE)
            .await?
            == 0
        {
            return Ok(Flow::Done);
        }
        let trimmed = line.trim_end();
        let mut parts = trimmed.split_whitespace();
        let command = parts.next().unwrap_or("").to_ascii_uppercase();
        let arg = parts.next().unwrap_or("");

        match command.as_str() {
            "CAPA" => {
                io.write_all(b"+OK Capability list follows\r\n").await?;
                io.write_all(b"USER\r\nUIDL\r\n").await?;
                if offer_tls {
                    io.write_all(b"STLS\r\n").await?;
                }
                io.write_all(b".\r\n").await?;
            }
            "STLS" => {
                if offer_tls {
                    io.write_all(b"+OK Begin TLS negotiation\r\n").await?;
                    io.flush().await?;
                    return Ok(Flow::StartTls);
                }
                io.write_all(b"-ERR STLS not available\r\n").await?;
            }
            "USER" if !authed => {
                user = arg.to_string();
                io.write_all(b"+OK\r\n").await?;
            }
            "PASS" if !authed => match db.verify_mail_login(&user, arg).await {
                Ok(Some(u)) => {
                    mailbox = db.fetch_mailbox_raw(&u.email).await.unwrap_or_default();
                    deleted = vec![false; mailbox.len()];
                    authed = true;
                    tracing::info!(target: "auth", proto = "pop3", user = %user, "POP3 login ok");
                    io.write_all(b"+OK mailbox ready\r\n").await?;
                }
                _ => {
                    tracing::warn!(target: "auth", proto = "pop3", user = %user, "POP3 login failed");
                    io.write_all(b"-ERR authentication failed\r\n").await?;
                }
            },
            "STAT" if authed => {
                let (count, size) = mailbox
                    .iter()
                    .zip(&deleted)
                    .filter(|(_, d)| !**d)
                    .fold((0usize, 0usize), |(c, s), ((_, raw), _)| {
                        (c + 1, s + raw.len())
                    });
                io.write_all(format!("+OK {count} {size}\r\n").as_bytes())
                    .await?;
            }
            "LIST" if authed => {
                io.write_all(b"+OK\r\n").await?;
                for (i, ((_, raw), del)) in mailbox.iter().zip(&deleted).enumerate() {
                    if !*del {
                        io.write_all(format!("{} {}\r\n", i + 1, raw.len()).as_bytes())
                            .await?;
                    }
                }
                io.write_all(b".\r\n").await?;
            }
            "UIDL" if authed => {
                io.write_all(b"+OK\r\n").await?;
                for (i, ((id, _), del)) in mailbox.iter().zip(&deleted).enumerate() {
                    if !*del {
                        io.write_all(format!("{} {}\r\n", i + 1, id).as_bytes())
                            .await?;
                    }
                }
                io.write_all(b".\r\n").await?;
            }
            "RETR" if authed => match message_index(arg, &mailbox, &deleted) {
                Some(idx) => {
                    let raw = &mailbox[idx].1;
                    io.write_all(format!("+OK {} octets\r\n", raw.len()).as_bytes())
                        .await?;
                    io.write_all(dot_stuff(raw).as_bytes()).await?;
                }
                None => io.write_all(b"-ERR no such message\r\n").await?,
            },
            "DELE" if authed => match message_index(arg, &mailbox, &deleted) {
                Some(idx) => {
                    deleted[idx] = true;
                    io.write_all(b"+OK marked for deletion\r\n").await?;
                }
                None => io.write_all(b"-ERR no such message\r\n").await?,
            },
            "RSET" if authed => {
                deleted.iter_mut().for_each(|d| *d = false);
                io.write_all(b"+OK\r\n").await?;
            }
            "NOOP" if authed => io.write_all(b"+OK\r\n").await?,
            "QUIT" => {
                // Commit deletions.
                for ((id, _), del) in mailbox.iter().zip(&deleted) {
                    if *del {
                        let _ = db.delete_mail_message(id).await;
                    }
                }
                io.write_all(b"+OK Bye\r\n").await?;
                return Ok(Flow::Done);
            }
            _ => {
                io.write_all(b"-ERR command not supported\r\n").await?;
            }
        }
    }
}

/// Parse a 1-based message number, rejecting out-of-range / already-deleted.
fn message_index(arg: &str, mailbox: &[(String, String)], deleted: &[bool]) -> Option<usize> {
    let n: usize = arg.parse().ok()?;
    if n == 0 || n > mailbox.len() || deleted[n - 1] {
        None
    } else {
        Some(n - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use magnetite_core::domains::mail::model::MailDomain;
    use tokio::io::AsyncBufReadExt;
    use tokio::net::TcpStream;

    async fn seeded_db() -> (Db, tempfile::TempDir) {
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
        db.store_mail_message("alice@example.com", "a@x.org", "Subject: one\r\n\r\nhi\r\n")
            .await
            .unwrap();
        db.store_mail_message("alice@example.com", "b@x.org", "Subject: two\r\n\r\nyo\r\n")
            .await
            .unwrap();
        (db, dir)
    }

    async fn start_pop3(db: Db) -> (SocketAddr, watch::Sender<bool>) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let (tx, rx) = watch::channel(false);
        tokio::spawn(serve(addr, db, rx));
        (addr, tx)
    }

    async fn line<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> String {
        let mut s = String::new();
        reader.read_line(&mut s).await.unwrap();
        s.trim_end().to_string()
    }

    async fn send<W: AsyncWriteExt + Unpin>(writer: &mut W, cmd: &str) {
        writer.write_all(cmd.as_bytes()).await.unwrap();
        writer.write_all(b"\r\n").await.unwrap();
    }

    #[tokio::test]
    async fn pop3_retrieve_and_delete() {
        let (db, _dir) = seeded_db().await;
        let (addr, _tx) = start_pop3(db.clone()).await;

        // Retry until the listener is up.
        let stream = {
            let mut s = None;
            for _ in 0..50 {
                if let Ok(c) = TcpStream::connect(addr).await {
                    s = Some(c);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            s.expect("POP3 not listening")
        };
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);

        assert!(line(&mut reader).await.starts_with("+OK")); // greeting
        send(&mut wr, "USER alice@example.com").await;
        assert!(line(&mut reader).await.starts_with("+OK"));
        send(&mut wr, "PASS password12").await;
        assert!(line(&mut reader).await.starts_with("+OK"));
        send(&mut wr, "STAT").await;
        assert!(line(&mut reader).await.starts_with("+OK 2"));

        send(&mut wr, "RETR 1").await;
        assert!(line(&mut reader).await.starts_with("+OK")); // +OK N octets
        let mut body = String::new();
        loop {
            let l = line(&mut reader).await;
            if l == "." {
                break;
            }
            body.push_str(&l);
        }
        assert!(body.contains("Subject: one"));

        send(&mut wr, "DELE 1").await;
        assert!(line(&mut reader).await.starts_with("+OK"));
        send(&mut wr, "QUIT").await;
        assert!(line(&mut reader).await.starts_with("+OK"));

        // The deleted message is gone; one remains.
        assert_eq!(
            db.count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn pop3_rejects_bad_password() {
        let (db, _dir) = seeded_db().await;
        let (addr, _tx) = start_pop3(db).await;
        let stream = {
            let mut s = None;
            for _ in 0..50 {
                if let Ok(c) = TcpStream::connect(addr).await {
                    s = Some(c);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            s.unwrap()
        };
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);
        assert!(line(&mut reader).await.starts_with("+OK"));
        send(&mut wr, "USER alice@example.com").await;
        assert!(line(&mut reader).await.starts_with("+OK"));
        send(&mut wr, "PASS wrongpass").await;
        assert!(line(&mut reader).await.starts_with("-ERR"));
    }

    /// End-to-end POP3 STLS: CAPA advertises STLS, the client upgrades to TLS,
    /// then authenticates and reads the mailbox over the encrypted channel.
    #[tokio::test]
    async fn pop3_stls_upgrades_to_tls() {
        let (db, _dir) = seeded_db().await;
        // Certificate + config so `serve` offers STLS.
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

        let (addr, _tx) = start_pop3(db.clone()).await;
        let tcp = {
            let mut s = None;
            for _ in 0..50 {
                if let Ok(c) = TcpStream::connect(addr).await {
                    s = Some(c);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            s.expect("POP3 not listening")
        };
        let (rd, mut wr) = tokio::io::split(tcp);
        let mut reader = BufReader::new(rd);
        assert!(line(&mut reader).await.starts_with("+OK")); // greeting

        send(&mut wr, "CAPA").await;
        let mut saw_stls = false;
        loop {
            let l = line(&mut reader).await;
            if l == "." {
                break;
            }
            if l == "STLS" {
                saw_stls = true;
            }
        }
        assert!(saw_stls, "CAPA did not advertise STLS");

        send(&mut wr, "STLS").await;
        assert!(line(&mut reader).await.starts_with("+OK"));

        // Upgrade to TLS and finish the session over the encrypted channel.
        let tcp = reader.into_inner().unsplit(wr);
        let server_name = rustls::pki_types::ServerName::try_from("mail.example.com").unwrap();
        let tls = crate::tls::testutil::danger_connector()
            .connect(server_name, tcp)
            .await
            .unwrap();
        let (rd, mut wr) = tokio::io::split(tls);
        let mut reader = BufReader::new(rd);

        send(&mut wr, "USER alice@example.com").await;
        assert!(line(&mut reader).await.starts_with("+OK"));
        send(&mut wr, "PASS password12").await;
        assert!(line(&mut reader).await.starts_with("+OK"));
        send(&mut wr, "STAT").await;
        assert!(line(&mut reader).await.starts_with("+OK 2"));
    }
}
