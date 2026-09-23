//! A length-capped line reader shared by the SMTP/IMAP/POP3 command loops (and the
//! SMTP DATA reader). `tokio`'s `read_line` grows the buffer until a newline or EOF
//! with no limit, so an attacker can stream a single line of arbitrary length and
//! exhaust memory before any command is even parsed. [`read_line_capped`] bounds each
//! line, disconnecting a client that exceeds the cap.

use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Maximum length of a single protocol command line (SMTP/IMAP/POP3). Generous versus
/// the RFC limits (SMTP command lines are ≤512 bytes) so no legitimate client is cut,
/// while still bounding a hostile unbounded line.
pub(crate) const MAX_COMMAND_LINE: usize = 64 * 1024;

/// Maximum time to wait for one complete protocol line to arrive. A capped line still
/// leaves a "slow-loris" client free to hold a connection open forever by dribbling a
/// byte every few minutes (or sending nothing at all), tying up a task and a socket.
/// This bounds each line read; a client that cannot deliver a full line in time is
/// dropped. Generous versus the RFC 5321 §4.5.3.2 timeouts (≥5min) so a genuinely slow
/// but honest link is not cut.
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// [`read_line_capped`] with an idle deadline: the whole line must arrive within
/// [`IO_TIMEOUT`], else a [`TimedOut`](std::io::ErrorKind::TimedOut) error drops the
/// connection. This is the slow-loris guard for the command loops; use it for every
/// network read (the plain [`read_line_capped`] stays for in-memory/test readers).
pub(crate) async fn read_line_capped_timeout<R>(
    reader: &mut R,
    line: &mut String,
    max: usize,
) -> std::io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    read_line_capped_within(reader, line, max, IO_TIMEOUT).await
}

/// [`read_line_capped_timeout`] with an explicit deadline (kept private so tests can use
/// a short one; production always goes through the [`IO_TIMEOUT`] wrapper above).
async fn read_line_capped_within<R>(
    reader: &mut R,
    line: &mut String,
    max: usize,
    timeout: Duration,
) -> std::io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    match tokio::time::timeout(timeout, read_line_capped(reader, line, max)).await {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for a command line",
        )),
    }
}

/// Read one line (up to and including the terminating `\n`) into `line`, but never
/// buffer more than `max` bytes for it: a longer line yields an `InvalidData` error so
/// the connection is dropped instead of the process running out of memory. Returns the
/// number of bytes read (`0` = EOF, matching `read_line`). Invalid UTF-8 is replaced
/// lossily — mail command lines are ASCII.
pub(crate) async fn read_line_capped<R>(
    reader: &mut R,
    line: &mut String,
    max: usize,
) -> std::io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    let mut total = 0usize;
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            break; // EOF
        }
        let newline = buf.iter().position(|&b| b == b'\n');
        let take = newline.map(|i| i + 1).unwrap_or(buf.len());
        if total + take > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line exceeds maximum length",
            ));
        }
        // Copy out before consuming so the immutable `buf` borrow of `reader` is released.
        let chunk = String::from_utf8_lossy(&buf[..take]).into_owned();
        line.push_str(&chunk);
        total += take;
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_a_line_and_caps_an_overlong_one() {
        let mut r = std::io::Cursor::new(b"HELO world\r\ntoolong".to_vec());
        let mut line = String::new();
        let n = read_line_capped(&mut r, &mut line, 64).await.unwrap();
        assert_eq!(n, 12);
        assert_eq!(line, "HELO world\r\n");

        // The remaining unterminated "toolong" (7 bytes) is fine under a big cap,
        // but a tiny cap rejects it.
        let mut line2 = String::new();
        let err = read_line_capped(&mut r, &mut line2, 3).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn eof_returns_zero() {
        let mut r = std::io::Cursor::new(Vec::new());
        let mut line = String::new();
        assert_eq!(read_line_capped(&mut r, &mut line, 64).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn timeout_drops_a_silent_client() {
        use tokio::io::{duplex, AsyncWriteExt};

        // A peer that connects, sends a partial line, then goes silent forever.
        let (client, server) = duplex(4096);
        let mut server = tokio::io::BufReader::new(server);
        let mut keep = client; // hold the write half open (never send `\n`)
        keep.write_all(b"HEL").await.unwrap();

        // A short real deadline (no tokio test-util needed): the line never completes.
        let mut line = String::new();
        let short = Duration::from_millis(50);
        let err = read_line_capped_within(&mut server, &mut line, MAX_COMMAND_LINE, short)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(line, "HEL"); // partial data was consumed before the deadline
    }
}
