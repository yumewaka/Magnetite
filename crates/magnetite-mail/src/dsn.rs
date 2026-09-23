//! Delivery Status Notification (bounce) generation, RFC 3464. When the backup-MX
//! queue gives up on a message, we return a non-delivery report to the original
//! sender instead of silently dropping it — standard, interoperable behaviour.
//!
//! The report is a `multipart/report; report-type=delivery-status` message with
//! three parts: a human-readable explanation, a `message/delivery-status` block
//! (per-recipient machine-readable status), and the returned original message.

use chrono::{DateTime, Utc};

/// Build an RFC 3464 non-delivery report. `original_sender` becomes the bounce
/// recipient; the bounce itself uses a null return-path (it is never bounced).
/// `now` is threaded in for deterministic output (and testability).
pub(crate) fn build_bounce(
    now: DateTime<Utc>,
    hostname: &str,
    original_sender: &str,
    recipients: &[String],
    reason: &str,
    original_raw: &str,
) -> String {
    let host = if hostname.trim().is_empty() {
        "localhost"
    } else {
        hostname.trim()
    };
    // A boundary that will not collide with typical message content.
    let boundary = format!("=_magnetite_dsn_{}", now.timestamp_millis());
    let date = now.format("%a, %d %b %Y %H:%M:%S +0000").to_string();

    let mut failed = String::new();
    for rcpt in recipients {
        failed.push_str(&format!("  <{rcpt}>\r\n"));
    }

    let mut per_recipient = String::new();
    for rcpt in recipients {
        per_recipient.push_str(&format!(
            "Final-Recipient: rfc822; {rcpt}\r\n\
             Action: failed\r\n\
             Status: 5.4.7\r\n\
             Diagnostic-Code: smtp; {reason}\r\n\r\n"
        ));
    }

    format!(
        "From: Mail Delivery System <MAILER-DAEMON@{host}>\r\n\
         To: <{original_sender}>\r\n\
         Subject: Undelivered Mail Returned to Sender\r\n\
         Date: {date}\r\n\
         Auto-Submitted: auto-replied\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status;\r\n\
         \tboundary=\"{boundary}\"\r\n\
         \r\n\
         This is a MIME-encapsulated message.\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         This is the mail system at host {host}.\r\n\
         \r\n\
         Your message could not be delivered to one or more recipients. It was\r\n\
         retried repeatedly without success and is being returned.\r\n\
         \r\n\
         {reason}\r\n\
         \r\n\
         The following recipient(s) failed:\r\n\
         {failed}\r\n\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; {host}\r\n\
         \r\n\
         {per_recipient}\
         --{boundary}\r\n\
         Content-Type: message/rfc822\r\n\
         \r\n\
         {original_raw}\r\n\
         --{boundary}--\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn bounce_has_report_structure_and_recipients() {
        let now = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
        let dsn = build_bounce(
            now,
            "mail.example.com",
            "sender@remote.org",
            &["user@backup.test".to_string()],
            "primary unreachable",
            "Subject: hi\r\n\r\nbody\r\n",
        );

        // Envelope / report headers.
        assert!(dsn.contains("From: Mail Delivery System <MAILER-DAEMON@mail.example.com>"));
        assert!(dsn.contains("To: <sender@remote.org>"));
        assert!(dsn.contains("Content-Type: multipart/report; report-type=delivery-status"));
        // Machine-readable delivery status per recipient.
        assert!(dsn.contains("Content-Type: message/delivery-status"));
        assert!(dsn.contains("Final-Recipient: rfc822; user@backup.test"));
        assert!(dsn.contains("Action: failed"));
        assert!(dsn.contains("Reporting-MTA: dns; mail.example.com"));
        // The original message is returned.
        assert!(dsn.contains("Content-Type: message/rfc822"));
        assert!(dsn.contains("Subject: hi"));
        // The multipart is terminated.
        assert!(dsn.trim_end().ends_with("--"));
    }

    #[test]
    fn empty_hostname_falls_back() {
        let now = Utc.with_ymd_and_hms(2026, 8, 2, 12, 0, 0).unwrap();
        let dsn = build_bounce(now, "  ", "s@x.test", &["r@y.test".into()], "boom", "raw");
        assert!(dsn.contains("MAILER-DAEMON@localhost"));
        assert!(dsn.contains("Reporting-MTA: dns; localhost"));
    }
}
