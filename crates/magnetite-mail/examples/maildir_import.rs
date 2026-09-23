//! Maildir → Magnetite mail importer (migration blocker B1): bulk-load existing Maildir
//! mailboxes into the mail store with **full fidelity** — every IMAP subfolder, the
//! read/unread + flagged/answered/… flags, and the original received date are preserved.
//!
//! Run it **OFFLINE**, with the Magnetite server STOPPED: the embedded RocksDB store is
//! single-writer, so a second process cannot open it while the server holds it. Import,
//! then start (and enable) the service.
//!
//! Environment:
//!   MAGNETITE_DB_PATH        the mail store directory (e.g. `.../data/magnetite-db`) [required]
//!   MAILDIR_ROOT             a directory whose immediate subdirectories are per-user
//!                            Maildir parents [required]
//!   MAIL_DOMAIN              the email domain, so `<user>` → `<user>@<MAIL_DOMAIN>` [required]
//!   MAILDIR_SUBPATH          the Maildir directory under each `<user>` (default `Maildir`)
//!   MAIL_DEFAULT_PASSWORD    if set (and the mail domain exists), create any missing
//!                            `mailuser` with this temporary password (reset it afterwards)
//!
//! On-disk layout expected (Maildir / Maildir++):
//!   MAILDIR_ROOT/<user>/<MAILDIR_SUBPATH>/{cur,new,tmp}          → folder `INBOX`
//!   MAILDIR_ROOT/<user>/<MAILDIR_SUBPATH>/.Sent/{cur,new}        → folder `Sent`
//!   MAILDIR_ROOT/<user>/<MAILDIR_SUBPATH>/.Lists.dev/{cur,new}   → folder `Lists/dev`
//!
//! Maildir `cur/` filenames carry flags in a `:2,<info>` suffix (S=\Seen, F=\Flagged,
//! R=\Answered, T=\Deleted, D=\Draft); `new/` messages are unseen. The received date is
//! taken from the message `Date:` header, falling back to the file mtime.

use chrono::{DateTime, Utc};
use magnetite_db::Db;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

type Res<T> = Result<T, Box<dyn Error>>;

fn main() -> Res<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

fn env_required(key: &str) -> Res<String> {
    std::env::var(key).map_err(|_| format!("{key} must be set").into())
}

async fn run() -> Res<()> {
    let db_path = env_required("MAGNETITE_DB_PATH")?;
    let root = PathBuf::from(env_required("MAILDIR_ROOT")?);
    let domain = env_required("MAIL_DOMAIN")?;
    let subpath = std::env::var("MAILDIR_SUBPATH").unwrap_or_else(|_| "Maildir".to_string());
    let default_password = std::env::var("MAIL_DEFAULT_PASSWORD").ok();

    let db = Db::connect(&db_path).await?;
    println!(
        "maildir-import: store {db_path}, root {}, domain @{domain}",
        root.display()
    );

    // Existing mail users, so we can report (or create) the ones a mailbox needs.
    let existing: BTreeSet<String> = db
        .list_mail_users()
        .await?
        .into_iter()
        .map(|u| u.email.to_lowercase())
        .collect();

    let mut total_msgs = 0usize;
    let mut total_users = 0usize;
    let mut missing_users: Vec<String> = Vec::new();

    for (user, maildir) in discover_users(&root, &subpath)? {
        let email = format!("{user}@{domain}");
        // Ensure a mail user owns the mailbox (else IMAP login and quota won't work).
        if !existing.contains(&email.to_lowercase()) {
            match &default_password {
                Some(pw) => match db
                    .create_mail_user(&user, &domain, None, 0, pw, "maildir-import")
                    .await
                {
                    Ok(_) => {
                        println!("  created mail user {email} (TEMPORARY password — reset it)")
                    }
                    Err(e) => {
                        println!("  WARN could not create mail user {email}: {e}");
                        missing_users.push(email.clone());
                    }
                },
                None => missing_users.push(email.clone()),
            }
        }

        let mut user_msgs = 0usize;
        for (folder, dir) in folders_in_maildir(&maildir)? {
            for msg in read_folder_messages(&dir)? {
                db.store_imported_message(
                    &email,
                    &folder,
                    &msg.sender,
                    &msg.raw,
                    &msg.flags,
                    msg.received_at,
                )
                .await?;
                user_msgs += 1;
            }
        }
        println!("  {email}: {user_msgs} message(s)");
        total_msgs += user_msgs;
        total_users += 1;
    }

    println!("maildir-import: done — {total_users} mailbox(es), {total_msgs} message(s)");
    if !missing_users.is_empty() {
        println!(
            "maildir-import: {} recipient(s) have NO mail user (messages imported, but IMAP \
             login won't work until you create them — set MAIL_DEFAULT_PASSWORD or create them \
             in the web UI): {}",
            missing_users.len(),
            missing_users.join(", ")
        );
    }
    Ok(())
}

/// Each immediate subdirectory of `root` that contains a `subpath` Maildir → `(user, maildir)`.
fn discover_users(root: &Path, subpath: &str) -> Res<Vec<(String, PathBuf)>> {
    let mut users = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let maildir = entry.path().join(subpath);
        if maildir.join("cur").is_dir() || maildir.join("new").is_dir() {
            let user = entry.file_name().to_string_lossy().into_owned();
            users.push((user, maildir));
        }
    }
    users.sort();
    Ok(users)
}

/// The IMAP folders in a Maildir: `INBOX` for the top level, plus each Maildir++
/// subfolder directory (`.Sent`, `.Lists.dev`) mapped to a `/`-separated folder name.
fn folders_in_maildir(maildir: &Path) -> Res<Vec<(String, PathBuf)>> {
    let mut folders = vec![("INBOX".to_string(), maildir.to_path_buf())];
    for entry in std::fs::read_dir(maildir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // Maildir++ subfolders are dot-prefixed dirs; the dotted path is the hierarchy.
        if let Some(rest) = name.strip_prefix('.') {
            if rest.is_empty() {
                continue; // skip "." / ".."-like artefacts
            }
            let folder = rest.replace('.', "/");
            folders.push((folder, entry.path()));
        }
    }
    folders.sort();
    Ok(folders)
}

struct ImportedMessage {
    raw: String,
    sender: String,
    flags: Vec<String>,
    received_at: DateTime<Utc>,
}

/// Read every message in a folder's `cur/` and `new/` subdirectories.
fn read_folder_messages(folder_dir: &Path) -> Res<Vec<ImportedMessage>> {
    let mut out = Vec::new();
    for sub in ["cur", "new"] {
        let dir = folder_dir.join(sub);
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let raw = match std::fs::read(&path) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(e) => {
                    println!("  WARN skipping {}: {e}", path.display());
                    continue;
                }
            };
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let flags = flags_from_filename(&file_name);
            let received_at = received_date(&raw, &path);
            let sender = header_value(&raw, "From").unwrap_or_default();
            out.push(ImportedMessage {
                raw,
                sender,
                flags,
                received_at,
            });
        }
    }
    Ok(out)
}

/// Parse IMAP flags from a Maildir `cur/` filename's `:2,<info>` suffix.
fn flags_from_filename(file_name: &str) -> Vec<String> {
    let Some(info) = file_name.split(":2,").nth(1) else {
        return Vec::new(); // `new/` message (or no info) — unseen, no flags
    };
    let mut flags = Vec::new();
    for c in info.chars() {
        let flag = match c {
            'S' => "\\Seen",
            'F' => "\\Flagged",
            'R' => "\\Answered",
            'T' => "\\Deleted",
            'D' => "\\Draft",
            _ => continue, // 'P' (passed) and unknowns have no IMAP system flag
        };
        flags.push(flag.to_string());
    }
    flags
}

/// The message's received date: the `Date:` header (RFC 2822) if parseable, else the
/// file's modification time, else now.
fn received_date(raw: &str, path: &Path) -> DateTime<Utc> {
    if let Some(date) = header_value(raw, "Date") {
        if let Ok(dt) = DateTime::parse_from_rfc2822(date.trim()) {
            return dt.with_timezone(&Utc);
        }
    }
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(|_| Utc::now())
}

/// The first value of an RFC 822 `header` (case-insensitive) from a raw message.
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
