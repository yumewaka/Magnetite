//! The embedded IMAP4rev1 retrieval server (E4d) — a pragmatic subset that lets
//! a mail client authenticate, browse folders, fetch messages, upload and expunge.
//!
//! Supported: CAPABILITY, NOOP, LOGIN, LOGOUT, SELECT/EXAMINE (any folder), LIST/LSUB
//! (real folder enumeration), CREATE, APPEND (with flags), FETCH and UID FETCH (FLAGS,
//! RFC822.SIZE, INTERNALDATE, UID, BODY[]/BODY.PEEK[]/RFC822, BODY[HEADER]/RFC822.HEADER;
//! macros ALL/FAST/FULL), STORE ±FLAGS (persisted: \Seen/\Answered/\Flagged/\Deleted/
//! \Draft, with `\Seen` set on non-PEEK body fetch), EXPUNGE, CLOSE. Folders and persisted
//! flags replicate to a secondary (Step 2). Deferred: persistent UIDs, SEARCH,
//! ENVELOPE/BODYSTRUCTURE, partial fetch, IDLE.

use crate::tls::Flow;
use chrono::Utc;
use magnetite_core::domains::mail::model::MailMessage;
use magnetite_db::Db;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

/// Bind and serve IMAP until `shutdown` fires.
pub(crate) async fn serve(
    addr: SocketAddr,
    db: Db,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    // STARTTLS is offered when a mail certificate is configured.
    let starttls = crate::tls::mail_tls_acceptor(&db).await;
    tracing::info!(
        "IMAP server listening on {addr} (STARTTLS {})",
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
                    tracing::warn!(target: "conn", %peer, "IMAP conn limit reached; dropping");
                    continue;
                };
                tracing::debug!(target: "conn", %peer, "IMAP connection");
                let db = db.clone();
                let starttls = starttls.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, db, starttls, false).await {
                        tracing::debug!("IMAP connection error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

/// Expand an IMAP sequence set (`1`, `2:4`, `2:*`, `*`, comma lists) to 1-based
/// indices within `[1, count]`.
fn expand_seq_set(spec: &str, count: usize) -> Vec<usize> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let bound = |t: &str| -> Option<usize> {
            if t == "*" {
                Some(count)
            } else {
                t.parse::<usize>().ok()
            }
        };
        if let Some((a, b)) = part.split_once(':') {
            if let (Some(mut lo), Some(mut hi)) = (bound(a), bound(b)) {
                if lo > hi {
                    std::mem::swap(&mut lo, &mut hi);
                }
                for n in lo..=hi {
                    if (1..=count).contains(&n) {
                        out.push(n);
                    }
                }
            }
        } else if let Some(n) = bound(part) {
            if (1..=count).contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

/// The header block of a raw message (through the blank separator line).
fn header_block(raw: &str) -> String {
    match raw.split_once("\r\n\r\n") {
        Some((head, _)) => format!("{head}\r\n\r\n"),
        None => raw.to_string(),
    }
}

fn internaldate(msg: &MailMessage) -> String {
    msg.received_at.format("%d-%b-%Y %H:%M:%S %z").to_string()
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
    let offer_tls = starttls.is_some() && !secure;
    let greeting = if offer_tls {
        "* OK [CAPABILITY IMAP4rev1 STARTTLS] Magnetite IMAP ready\r\n"
    } else {
        "* OK [CAPABILITY IMAP4rev1] Magnetite IMAP ready\r\n"
    };
    io.write_all(greeting.as_bytes()).await?;

    if let Flow::StartTls = imap_dialog(&mut io, &db, offer_tls).await? {
        // STARTTLS: reunite the stream, wrap in TLS, resume on the encrypted
        // channel (no greeting is resent — the client sends the next command).
        let acceptor = starttls.expect("STARTTLS only offered when acceptor present");
        let tls = acceptor.accept(io.into_inner()).await?;
        let mut io = BufReader::new(tls);
        imap_dialog(&mut io, &db, false).await?;
    }
    Ok(())
}

/// The IMAP command loop. Returns [`Flow::StartTls`] when the client issued
/// `STARTTLS` (and it was offered). `offer_tls` advertises STARTTLS in the
/// CAPABILITY response.
async fn imap_dialog<S>(io: &mut BufReader<S>, db: &Db, offer_tls: bool) -> std::io::Result<Flow>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let capability = if offer_tls {
        "* CAPABILITY IMAP4rev1 STARTTLS\r\n"
    } else {
        "* CAPABILITY IMAP4rev1\r\n"
    };

    let mut email = String::new();
    let mut authed = false;
    let mut selected = false;
    let mut folder = "INBOX".to_string();
    let mut mailbox: Vec<MailMessage> = Vec::new();
    let mut deleted: Vec<bool> = Vec::new();
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
        let mut parts = trimmed.splitn(3, ' ');
        let tag = parts.next().unwrap_or("*");
        let command = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("");

        match command.as_str() {
            "CAPABILITY" => {
                io.write_all(capability.as_bytes()).await?;
                io.write_all(format!("{tag} OK CAPABILITY completed\r\n").as_bytes())
                    .await?;
            }
            "STARTTLS" => {
                if offer_tls {
                    io.write_all(format!("{tag} OK Begin TLS negotiation now\r\n").as_bytes())
                        .await?;
                    io.flush().await?;
                    return Ok(Flow::StartTls);
                }
                io.write_all(format!("{tag} BAD STARTTLS not available\r\n").as_bytes())
                    .await?;
            }
            "NOOP" => {
                io.write_all(format!("{tag} OK NOOP completed\r\n").as_bytes())
                    .await?;
            }
            "LOGOUT" => {
                io.write_all(b"* BYE Magnetite logging out\r\n").await?;
                io.write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
                    .await?;
                return Ok(Flow::Done);
            }
            "LOGIN" if !authed => {
                let mut args = rest.split_whitespace();
                let user = unquote(args.next().unwrap_or(""));
                let pass = unquote(args.next().unwrap_or(""));
                match db.verify_mail_login(&user, &pass).await {
                    Ok(Some(u)) => {
                        email = u.email;
                        authed = true;
                        tracing::info!(target: "auth", proto = "imap", user = %user, "IMAP login ok");
                        io.write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                            .await?;
                    }
                    _ => {
                        tracing::warn!(target: "auth", proto = "imap", user = %user, "IMAP login failed");
                        io.write_all(format!("{tag} NO LOGIN failed\r\n").as_bytes())
                            .await?;
                    }
                }
            }
            "SELECT" | "EXAMINE" if authed => {
                // Select the named folder (default INBOX). `INBOX` is case-insensitive;
                // an imported/created folder is matched by its exact name.
                let name = unquote(rest.trim());
                folder = if name.is_empty() {
                    "INBOX".to_string()
                } else {
                    name
                };
                mailbox = load_mailbox(db, &email, &folder).await;
                deleted = derive_deleted(&mailbox);
                selected = true;
                let n = mailbox.len();
                let response = format!(
                    "* {n} EXISTS\r\n\
                     * 0 RECENT\r\n\
                     * FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n\
                     * OK [UIDVALIDITY 1] UIDs valid\r\n\
                     * OK [UIDNEXT {}] Predicted next UID\r\n\
                     {tag} OK [READ-WRITE] SELECT completed\r\n",
                    n + 1
                );
                io.write_all(response.as_bytes()).await?;
            }
            "LIST" | "LSUB" if authed => {
                // Enumerate the mailbox's real folders (always including INBOX), so a
                // client sees every imported/created folder. Hierarchy delimiter is "/".
                let folders = db.list_folders(&email).await.unwrap_or_default();
                for f in &folders {
                    io.write_all(format!("* {command} () \"/\" \"{f}\"\r\n").as_bytes())
                        .await?;
                }
                io.write_all(format!("{tag} OK {command} completed\r\n").as_bytes())
                    .await?;
            }
            "CREATE" if authed => {
                // Folders are implicit — a folder exists once it holds a message (APPEND
                // or import). Acknowledge so a client's CREATE-then-APPEND flow works.
                io.write_all(format!("{tag} OK CREATE completed\r\n").as_bytes())
                    .await?;
            }
            "APPEND" if authed => {
                append(db, io, &email, tag, rest).await?;
            }
            "FETCH" if selected => {
                let (seq, items) = split_seq_items(rest);
                fetch(db, io, &mailbox, &seq, &items, false).await?;
                io.write_all(format!("{tag} OK FETCH completed\r\n").as_bytes())
                    .await?;
            }
            "UID" if selected => {
                let mut sub = rest.splitn(2, ' ');
                let subcommand = sub.next().unwrap_or("").to_ascii_uppercase();
                let subrest = sub.next().unwrap_or("");
                match subcommand.as_str() {
                    "FETCH" => {
                        let (seq, items) = split_seq_items(subrest);
                        fetch(db, io, &mailbox, &seq, &items, true).await?;
                        io.write_all(format!("{tag} OK UID FETCH completed\r\n").as_bytes())
                            .await?;
                    }
                    "STORE" => {
                        let (seq, flags) = split_seq_items(subrest);
                        store(db, io, &mailbox, &mut deleted, &seq, flags).await?;
                        mailbox = load_mailbox(db, &email, &folder).await;
                        deleted = derive_deleted(&mailbox);
                        io.write_all(format!("{tag} OK UID STORE completed\r\n").as_bytes())
                            .await?;
                    }
                    _ => {
                        io.write_all(format!("{tag} BAD unsupported UID command\r\n").as_bytes())
                            .await?;
                    }
                }
            }
            "STORE" if selected => {
                let (seq, flags) = split_seq_items(rest);
                store(db, io, &mailbox, &mut deleted, &seq, flags).await?;
                mailbox = load_mailbox(db, &email, &folder).await;
                deleted = derive_deleted(&mailbox);
                io.write_all(format!("{tag} OK STORE completed\r\n").as_bytes())
                    .await?;
            }
            "EXPUNGE" if selected => {
                expunge(db, io, &mailbox, &deleted).await?;
                mailbox = load_mailbox(db, &email, &folder).await;
                deleted = vec![false; mailbox.len()];
                io.write_all(format!("{tag} OK EXPUNGE completed\r\n").as_bytes())
                    .await?;
            }
            "CLOSE" if selected => {
                expunge_silent(db, &mailbox, &deleted).await;
                selected = false;
                mailbox.clear();
                deleted.clear();
                io.write_all(format!("{tag} OK CLOSE completed\r\n").as_bytes())
                    .await?;
            }
            _ => {
                io.write_all(format!("{tag} BAD command not supported\r\n").as_bytes())
                    .await?;
            }
        }
    }
}

async fn load_mailbox(db: &Db, email: &str, folder: &str) -> Vec<MailMessage> {
    let mut msgs = db
        .list_mailbox_folder(email, folder, 1000)
        .await
        .unwrap_or_default();
    msgs.reverse(); // list is newest-first; IMAP sequence is arrival order
    msgs
}

/// Handle `APPEND <mailbox> [(<flags>)] [<date-time>] {<size>[+]}` — store a client-
/// uploaded message into `folder` with the given flags. Reads the message literal (the
/// `{size}` octet count) from the stream after sending the `+` continuation (unless a
/// non-synchronising `{size+}` literal was used). The sender is taken from the message's
/// `From:` header; the date defaults to now.
async fn append<S>(
    db: &Db,
    io: &mut BufReader<S>,
    email: &str,
    tag: &str,
    rest: &str,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Parse the mailbox name, optional (flags) and date, and the trailing {size} literal.
    let Some(brace) = rest.rfind('{') else {
        io.write_all(format!("{tag} BAD APPEND expects a literal\r\n").as_bytes())
            .await?;
        return Ok(());
    };
    let head = rest[..brace].trim();
    let literal = &rest[brace + 1..];
    let non_sync = literal.contains('+');
    let size: usize = literal
        .trim_end_matches(['}', '+'])
        .trim()
        .parse()
        .unwrap_or(0);

    // Bound the client-declared literal size before allocating a buffer for it, so an
    // `APPEND INBOX {4000000000}` cannot force a multi-GB allocation. 64 MiB is well
    // above any real message.
    const MAX_APPEND_SIZE: usize = 64 * 1024 * 1024;
    if size > MAX_APPEND_SIZE {
        io.write_all(format!("{tag} NO [LIMIT] message too large\r\n").as_bytes())
            .await?;
        if non_sync {
            // A non-synchronising literal is already streaming; we can't resync — close.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "APPEND literal exceeds maximum size",
            ));
        }
        return Ok(());
    }

    // The mailbox is the first token; flags are the parenthesised group if present.
    let mailbox = unquote(head.split_whitespace().next().unwrap_or("INBOX"));
    let folder = if mailbox.is_empty() {
        "INBOX".to_string()
    } else {
        mailbox
    };
    let flags = head
        .find('(')
        .zip(head.find(')'))
        .filter(|(o, c)| o < c)
        .map(|(o, c)| {
            head[o + 1..c]
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Read the message literal. Synchronising literals require a continuation first.
    if !non_sync {
        io.write_all(b"+ OK\r\n").await?;
        io.flush().await?;
    }
    let mut raw = vec![0u8; size];
    if io.read_exact(&mut raw).await.is_err() {
        io.write_all(format!("{tag} NO APPEND read failed\r\n").as_bytes())
            .await?;
        return Ok(());
    }
    // Consume the trailing CRLF after the literal.
    let mut tail = String::new();
    let _ = io.read_line(&mut tail).await?;

    let raw = String::from_utf8_lossy(&raw).into_owned();
    let sender = header_value(&raw, "From").unwrap_or_default();
    match db
        .store_imported_message(email, &folder, &sender, &raw, &flags, Utc::now())
        .await
    {
        Ok(()) => {
            io.write_all(format!("{tag} OK APPEND completed\r\n").as_bytes())
                .await?;
        }
        Err(e) => {
            io.write_all(format!("{tag} NO APPEND failed: {e}\r\n").as_bytes())
                .await?;
        }
    }
    Ok(())
}

/// Extract the first value of an RFC822 `header` (case-insensitive) from a raw message.
fn header_value(raw: &str, header: &str) -> Option<String> {
    for line in raw.lines() {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case(header) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Split "`<seq-set> <items…>`" into the sequence set and the rest (items or
/// STORE flags), tolerating a parenthesised item list.
fn split_seq_items(rest: &str) -> (String, String) {
    let rest = rest.trim();
    match rest.split_once(' ') {
        Some((seq, items)) => (seq.to_string(), items.trim().to_string()),
        None => (rest.to_string(), String::new()),
    }
}

fn expand_items(items: &str) -> Vec<String> {
    let inner = items.trim().trim_start_matches('(').trim_end_matches(')');
    match inner.trim().to_ascii_uppercase().as_str() {
        "ALL" => vec!["FLAGS", "INTERNALDATE", "RFC822.SIZE"],
        "FAST" => vec!["FLAGS", "INTERNALDATE", "RFC822.SIZE"],
        "FULL" => vec!["FLAGS", "INTERNALDATE", "RFC822.SIZE", "BODY[]"],
        _ => return inner.split_whitespace().map(|s| s.to_string()).collect(),
    }
    .into_iter()
    .map(String::from)
    .collect()
}

async fn fetch<W: AsyncWriteExt + Unpin>(
    db: &Db,
    writer: &mut W,
    mailbox: &[MailMessage],
    seq_spec: &str,
    items: &str,
    is_uid: bool,
) -> std::io::Result<()> {
    let requested = expand_items(items);
    let wants_uid = is_uid || requested.iter().any(|i| i.eq_ignore_ascii_case("UID"));
    // A non-PEEK body fetch sets the `\Seen` flag (RFC 3501 §6.4.5).
    let marks_seen = requested
        .iter()
        .any(|i| matches!(i.to_ascii_uppercase().as_str(), "BODY[]" | "RFC822"));
    for seq in expand_seq_set(seq_spec, mailbox.len()) {
        let msg = &mailbox[seq - 1];
        let uid = seq; // UID == sequence number in this minimal server
                       // Effective flags for this response, persisting `\Seen` if newly set.
        let mut eff_flags = msg.flags.clone();
        if marks_seen && !contains_flag(&eff_flags, "\\Seen") {
            eff_flags.push("\\Seen".to_string());
            let _ = db.set_mail_flags(&msg.id, &eff_flags).await;
        }
        let mut pieces: Vec<String> = Vec::new();
        for item in &requested {
            let upper = item.to_ascii_uppercase();
            match upper.as_str() {
                "FLAGS" => pieces.push(format!("FLAGS ({})", format_flags(&eff_flags))),
                "RFC822.SIZE" => pieces.push(format!("RFC822.SIZE {}", msg.size_bytes)),
                "UID" => pieces.push(format!("UID {uid}")),
                "INTERNALDATE" => pieces.push(format!("INTERNALDATE \"{}\"", internaldate(msg))),
                "BODY[]" | "BODY.PEEK[]" | "RFC822" => {
                    let raw = db
                        .get_mail_message_raw(&msg.id)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let label = if upper == "RFC822" {
                        "RFC822"
                    } else {
                        "BODY[]"
                    };
                    pieces.push(format!("{label} {{{}}}\r\n{raw}", raw.len()));
                }
                "BODY[HEADER]" | "BODY.PEEK[HEADER]" | "RFC822.HEADER" => {
                    let raw = db
                        .get_mail_message_raw(&msg.id)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let head = header_block(&raw);
                    let label = if upper == "RFC822.HEADER" {
                        "RFC822.HEADER"
                    } else {
                        "BODY[HEADER]"
                    };
                    pieces.push(format!("{label} {{{}}}\r\n{head}", head.len()));
                }
                _ => {}
            }
        }
        if wants_uid && !pieces.iter().any(|p| p.starts_with("UID ")) {
            pieces.push(format!("UID {uid}"));
        }
        writer
            .write_all(format!("* {seq} FETCH ({})\r\n", pieces.join(" ")).as_bytes())
            .await?;
    }
    Ok(())
}

/// IMAP STORE mode: replace, add (`+FLAGS`), or remove (`-FLAGS`) flags.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoreMode {
    Replace,
    Add,
    Remove,
}

/// Whether a flag list contains `flag` (case-insensitively).
fn contains_flag(flags: &[String], flag: &str) -> bool {
    flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
}

/// Canonicalise an IMAP flag token (system flags to their `\Seen` spelling;
/// keywords pass through). Empty tokens are dropped.
fn canonical_flag(token: &str) -> Option<String> {
    let t = token.trim();
    if t.is_empty() {
        return None;
    }
    Some(match t.to_ascii_uppercase().as_str() {
        "\\SEEN" => "\\Seen".to_string(),
        "\\ANSWERED" => "\\Answered".to_string(),
        "\\FLAGGED" => "\\Flagged".to_string(),
        "\\DELETED" => "\\Deleted".to_string(),
        "\\DRAFT" => "\\Draft".to_string(),
        _ => t.to_string(),
    })
}

/// Parse a STORE flag argument (`[+|-]FLAGS[.SILENT] (\Seen …)`) into the mode,
/// the flag list, and whether the response is suppressed (`.SILENT`).
fn parse_store_flags(arg: &str) -> (StoreMode, Vec<String>, bool) {
    let trimmed = arg.trim();
    let upper = trimmed.to_ascii_uppercase();
    let (mode, after) = if let Some(rest) = upper.strip_prefix("+FLAGS") {
        (StoreMode::Add, &trimmed[trimmed.len() - rest.len()..])
    } else if let Some(rest) = upper.strip_prefix("-FLAGS") {
        (StoreMode::Remove, &trimmed[trimmed.len() - rest.len()..])
    } else if let Some(rest) = upper.strip_prefix("FLAGS") {
        (StoreMode::Replace, &trimmed[trimmed.len() - rest.len()..])
    } else {
        (StoreMode::Replace, trimmed)
    };
    let after = after.trim();
    let silent = after.to_ascii_uppercase().starts_with(".SILENT");
    let after = if silent { after[7..].trim() } else { after };
    let inner = after.trim().trim_start_matches('(').trim_end_matches(')');
    let flags = inner
        .split_whitespace()
        .filter_map(canonical_flag)
        .collect();
    (mode, flags, silent)
}

/// Compute the new flag set for a message given the STORE mode and flag list.
fn apply_flag_mode(current: &[String], mode: StoreMode, flags: &[String]) -> Vec<String> {
    match mode {
        StoreMode::Replace => {
            let mut out: Vec<String> = Vec::new();
            for f in flags {
                if !contains_flag(&out, f) {
                    out.push(f.clone());
                }
            }
            out
        }
        StoreMode::Add => {
            let mut out = current.to_vec();
            for f in flags {
                if !contains_flag(&out, f) {
                    out.push(f.clone());
                }
            }
            out
        }
        StoreMode::Remove => current
            .iter()
            .filter(|f| !contains_flag(flags, f))
            .cloned()
            .collect(),
    }
}

/// The IMAP wire form of a flag list (space-separated inside the caller's parens).
fn format_flags(flags: &[String]) -> String {
    flags.join(" ")
}

/// Per-message `\Deleted` state derived from persisted flags (drives EXPUNGE).
fn derive_deleted(mailbox: &[MailMessage]) -> Vec<bool> {
    mailbox
        .iter()
        .map(|m| contains_flag(&m.flags, "\\Deleted"))
        .collect()
}

async fn store<W: AsyncWriteExt + Unpin>(
    db: &Db,
    writer: &mut W,
    mailbox: &[MailMessage],
    deleted: &mut [bool],
    seq_spec: &str,
    flags_arg: String,
) -> std::io::Result<()> {
    let (mode, flags, silent) = parse_store_flags(&flags_arg);
    for seq in expand_seq_set(seq_spec, mailbox.len()) {
        let msg = &mailbox[seq - 1];
        let new_flags = apply_flag_mode(&msg.flags, mode, &flags);
        let _ = db.set_mail_flags(&msg.id, &new_flags).await;
        deleted[seq - 1] = contains_flag(&new_flags, "\\Deleted");
        if !silent {
            writer
                .write_all(
                    format!("* {seq} FETCH (FLAGS ({}))\r\n", format_flags(&new_flags)).as_bytes(),
                )
                .await?;
        }
    }
    Ok(())
}

async fn expunge<W: AsyncWriteExt + Unpin>(
    db: &Db,
    writer: &mut W,
    mailbox: &[MailMessage],
    deleted: &[bool],
) -> std::io::Result<()> {
    // Emit EXPUNGE in descending sequence order so earlier numbers stay valid.
    for seq in (1..=mailbox.len()).rev() {
        if deleted[seq - 1] {
            let _ = db.delete_mail_message(&mailbox[seq - 1].id).await;
            writer
                .write_all(format!("* {seq} EXPUNGE\r\n").as_bytes())
                .await?;
        }
    }
    Ok(())
}

async fn expunge_silent(db: &Db, mailbox: &[MailMessage], deleted: &[bool]) {
    for (msg, del) in mailbox.iter().zip(deleted) {
        if *del {
            let _ = db.delete_mail_message(&msg.id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use magnetite_core::domains::mail::model::MailDomain;
    use tokio::net::TcpStream;

    #[test]
    fn seq_set_expansion() {
        assert_eq!(expand_seq_set("1", 3), vec![1]);
        assert_eq!(expand_seq_set("2:*", 3), vec![2, 3]);
        assert_eq!(expand_seq_set("*", 3), vec![3]);
        assert_eq!(expand_seq_set("1,3", 3), vec![1, 3]);
        assert_eq!(expand_seq_set("3:1", 3), vec![1, 2, 3]);
        assert!(expand_seq_set("5", 3).is_empty());
    }

    #[test]
    fn store_flag_parsing_and_modes() {
        let (mode, flags, silent) = parse_store_flags("+FLAGS (\\Seen \\flagged)");
        assert!(matches!(mode, StoreMode::Add));
        assert_eq!(flags, vec!["\\Seen".to_string(), "\\Flagged".to_string()]);
        assert!(!silent);

        let (mode, flags, silent) = parse_store_flags("FLAGS.SILENT (\\Deleted)");
        assert!(matches!(mode, StoreMode::Replace));
        assert_eq!(flags, vec!["\\Deleted".to_string()]);
        assert!(silent);

        let current = vec!["\\Seen".to_string()];
        assert_eq!(
            apply_flag_mode(&current, StoreMode::Add, &["\\Flagged".to_string()]),
            vec!["\\Seen".to_string(), "\\Flagged".to_string()]
        );
        assert_eq!(
            apply_flag_mode(&current, StoreMode::Remove, &["\\seen".to_string()]),
            Vec::<String>::new()
        );
        assert_eq!(
            apply_flag_mode(&current, StoreMode::Replace, &["\\Draft".to_string()]),
            vec!["\\Draft".to_string()]
        );
    }

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

    async fn start_imap(db: Db) -> (SocketAddr, watch::Sender<bool>) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let (tx, rx) = watch::channel(false);
        tokio::spawn(serve(addr, db, rx));
        (addr, tx)
    }

    async fn connect(addr: SocketAddr) -> TcpStream {
        for _ in 0..50 {
            if let Ok(c) = TcpStream::connect(addr).await {
                return c;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("IMAP not listening");
    }

    /// Send `tag CMD` and read lines until the tagged status; return all text.
    async fn cmd<R: AsyncBufReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        reader: &mut R,
        writer: &mut W,
        tag: &str,
        command: &str,
    ) -> String {
        writer
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await
            .unwrap();
        let mut acc = String::new();
        loop {
            let mut l = String::new();
            if reader.read_line(&mut l).await.unwrap() == 0 {
                break;
            }
            acc.push_str(&l);
            if l.starts_with(&format!("{tag} ")) {
                break;
            }
        }
        acc
    }

    #[tokio::test]
    async fn imap_login_select_fetch_expunge() {
        let (db, _dir) = seeded_db().await;
        let (addr, _tx) = start_imap(db.clone()).await;
        let stream = connect(addr).await;
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);

        // Greeting.
        let mut greet = String::new();
        reader.read_line(&mut greet).await.unwrap();
        assert!(greet.contains("OK"));

        assert!(cmd(&mut reader, &mut wr, "a", "CAPABILITY")
            .await
            .contains("a OK"));
        assert!(cmd(
            &mut reader,
            &mut wr,
            "b",
            "LOGIN alice@example.com password12"
        )
        .await
        .contains("b OK"));
        let sel = cmd(&mut reader, &mut wr, "c", "SELECT INBOX").await;
        assert!(sel.contains("2 EXISTS"));
        assert!(sel.contains("c OK"));

        let fetched = cmd(&mut reader, &mut wr, "d", "FETCH 1 (RFC822.SIZE BODY[])").await;
        assert!(fetched.contains("Subject: one"));
        assert!(fetched.contains("d OK"));

        let uidf = cmd(&mut reader, &mut wr, "e", "UID FETCH 2 (UID)").await;
        assert!(uidf.contains("UID 2"));

        assert!(cmd(&mut reader, &mut wr, "f", "STORE 1 +FLAGS (\\Deleted)")
            .await
            .contains("f OK"));
        let exp = cmd(&mut reader, &mut wr, "g", "EXPUNGE").await;
        assert!(exp.contains("1 EXPUNGE"));
        assert!(exp.contains("g OK"));
        assert!(cmd(&mut reader, &mut wr, "h", "LOGOUT")
            .await
            .contains("h OK"));

        assert_eq!(
            db.count_mail_messages_for("alice@example.com")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn imap_rejects_bad_login() {
        let (db, _dir) = seeded_db().await;
        let (addr, _tx) = start_imap(db).await;
        let stream = connect(addr).await;
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);
        let mut greet = String::new();
        reader.read_line(&mut greet).await.unwrap();
        assert!(
            cmd(&mut reader, &mut wr, "a", "LOGIN alice@example.com wrong")
                .await
                .contains("a NO")
        );
    }

    /// End-to-end IMAP STARTTLS: the greeting/CAPABILITY advertise STARTTLS, the
    /// client upgrades to TLS, then logs in and selects INBOX over TLS.
    #[tokio::test]
    async fn imap_starttls_upgrades_to_tls() {
        let (db, _dir) = seeded_db().await;
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

        let (addr, _tx) = start_imap(db.clone()).await;
        let tcp = connect(addr).await;
        let (rd, mut wr) = tokio::io::split(tcp);
        let mut reader = BufReader::new(rd);
        let mut greet = String::new();
        reader.read_line(&mut greet).await.unwrap();
        assert!(greet.contains("STARTTLS"), "greeting: {greet:?}");

        assert!(cmd(&mut reader, &mut wr, "a", "STARTTLS")
            .await
            .contains("a OK"));

        // Upgrade to TLS, then complete auth + select over the encrypted channel.
        let tcp = reader.into_inner().unsplit(wr);
        let server_name = rustls::pki_types::ServerName::try_from("mail.example.com").unwrap();
        let tls = crate::tls::testutil::danger_connector()
            .connect(server_name, tcp)
            .await
            .unwrap();
        let (rd, mut wr) = tokio::io::split(tls);
        let mut reader = BufReader::new(rd);

        assert!(cmd(
            &mut reader,
            &mut wr,
            "b",
            "LOGIN alice@example.com password12"
        )
        .await
        .contains("b OK"));
        let sel = cmd(&mut reader, &mut wr, "c", "SELECT INBOX").await;
        assert!(sel.contains("2 EXISTS"), "select: {sel:?}");
        assert!(sel.contains("c OK"));
    }
}
