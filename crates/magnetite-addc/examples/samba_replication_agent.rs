//! Run the periodic replication **agent** against a live Samba AD DC: it pulls +
//! applies changes into a fresh `magnetite-db` on a fixed interval (a full sync, then
//! deltas), exactly as a running server would schedule it. Here it runs a few cycles,
//! then is signalled to stop and the store is inspected.
//!
//! Run (with the samba-dc container up):
//! `KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local
//!  USERK=Administrator cargo run -p magnetite-addc --example samba_replication_agent`

use std::time::Duration;

use magnetite_addc::{spawn_replication_thread, ReplicationConfig};
use magnetite_db::Db;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Emit the agent's per-cycle tracing so the interval behaviour is visible.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let cfg = ReplicationConfig {
        kdc: std::env::var("KDC")
            .unwrap_or_else(|_| "127.0.0.1:8088".into())
            .parse()?,
        drs: std::env::var("DRS")
            .unwrap_or_else(|_| "127.0.0.1:49152".into())
            .parse()?,
        realm: "MAGTEST.LOCAL".into(),
        user: std::env::var("USERK").unwrap_or_else(|_| "Administrator".into()),
        password: std::env::var("PASS").unwrap_or_else(|_| "Passw0rd!23".into()),
        keytab: std::env::var("KEYTAB").ok().map(std::path::PathBuf::from),
        spn: std::env::var("SPN").unwrap_or_else(|_| "ldap/dc1.magtest.local".into()),
        nc_dn: "DC=magtest,DC=local".into(),
        extra_ncs: std::env::var("EXTRA_NCS")
            .map(|s| s.split(';').map(str::to_string).collect())
            .unwrap_or_default(),
        interval: Duration::from_secs(2),
    };

    let dir = tempfile::tempdir()?;
    let db = Db::connect(dir.path().join("db")).await?;

    // Host the agent as a background thread — the pattern a multi-thread server uses,
    // since the agent future is not `Send`. `spawn_replication_thread` runs it on a
    // dedicated current-thread runtime + LocalSet, so this `#[tokio::main]` (a
    // multi-thread runtime) can drive it without the `Send` requirement.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    eprintln!("[agent] running ~3 cycles at a 2s interval (on a background thread) ...");
    let handle = spawn_replication_thread(cfg, db.clone(), stop_rx, None, None, None);

    tokio::time::sleep(Duration::from_millis(5000)).await;
    eprintln!("[agent] signalling shutdown ...");
    stop_tx.send(true).ok();
    handle.join().expect("replication thread");

    let principals = db.list_ad_principals().await?;
    eprintln!(
        "[agent] the store now holds {} replicated principals:",
        principals.len()
    );
    for p in &principals {
        eprintln!(
            "        {:<16} rid={} aes256={} bytes",
            p.sam_account_name,
            p.rid,
            p.kerberos_key.len()
        );
    }
    Ok(())
}
