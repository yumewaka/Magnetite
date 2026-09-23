//! End-to-end DC-promotion orchestrator: one command turns magnetite into a replica
//! DC of an existing AD domain — computer, server, serverReference, nTDSDSA (DsAddEntry),
//! nTDSConnection, DNS, and (optionally) FSMO role transfers + a RID pool.
//!
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  REALM=MAGTEST.LOCAL KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local \
//!  DC_NAME=MAGNETITE IP=10.69.134.20 ROLES=infrastructure,rid RID_POOL=1 \
//!  cargo run -p magnetite-addc --example promote_dc`
//!
//! Transport / safety flags (all off by default):
//! * `STARTTLS=1` upgrade the bind with StartTLS · `LDAPS=1` connect over implicit TLS (636).
//!   Both take a truthy value (`1`/`true`/`yes`/`on`); `STARTTLS=0` means off.
//! * `TLS_CA=/path/ca.pem` verify the server cert against this CA. If set but unreadable
//!   the run **fails** (it never silently downgrades to accepting any certificate).
//! * `SKIP_DNS=1` do not register any DC-locator DNS (manage this DC's DNS out of band).
//! * `INVOCATION_ID=<32 hex>` pin the nTDSDSA invocationId (align it with the daemon's
//!   persistent `dsa_invocation_id`; use a **fresh** value on a rollback+rejoin).

use anyhow::Context;
use magnetite_addc::promote::{promote, PromoteParams};
use magnetite_ldap::dc_join::JoinTarget;
use magnetite_rpc::FsmoRole;

fn role_of(name: &str) -> Option<FsmoRole> {
    match name.trim().to_lowercase().as_str() {
        "schema" => Some(FsmoRole::Schema),
        "naming" | "domainnaming" => Some(FsmoRole::DomainNaming),
        "pdc" => Some(FsmoRole::PdcEmulator),
        "rid" => Some(FsmoRole::RidMaster),
        "infrastructure" | "infra" => Some(FsmoRole::Infrastructure),
        _ => None,
    }
}

/// A boolean env flag: true only for an explicit truthy value, so `FLAG=0` is off.
fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Parse 16 bytes of hex (32 hex chars, `:`/`-`/whitespace separators allowed).
fn parse_hex16(s: &str) -> anyhow::Result<Vec<u8>> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(
        hex.len() == 32,
        "INVOCATION_ID must be 16 bytes (32 hex chars), got {}",
        hex.len()
    );
    (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).context("INVOCATION_ID hex"))
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
    // Read the CA up front so a bad path fails now, not silently as "accept any cert".
    let tls_ca_pem = match std::env::var("TLS_CA") {
        Ok(path) => Some(
            std::fs::read_to_string(&path).with_context(|| format!("read TLS_CA from {path}"))?,
        ),
        Err(_) => None,
    };
    let invocation_id = match std::env::var("INVOCATION_ID") {
        Ok(h) => Some(parse_hex16(&h)?),
        Err(_) => None,
    };
    let params = PromoteParams {
        target: JoinTarget {
            host_port: env("TARGET", "127.0.0.1:1389"),
            bind_dn: env("BIND_DN", "Administrator@MAGTEST.LOCAL"),
            bind_password: env("BIND_PW", "Passw0rd!23"),
            use_starttls: env_flag("STARTTLS"),
            use_ldaps: env_flag("LDAPS"),
            tls_ca_pem,
        },
        dc_name: env("DC_NAME", "MAGNETITE"),
        realm: env("REALM", "MAGTEST.LOCAL"),
        kdc: env("KDC", "127.0.0.1:8088").parse()?,
        drs: env("DRS", "127.0.0.1:49152").parse()?,
        admin_user: env("USERK", "Administrator"),
        admin_pass: env("BIND_PW", "Passw0rd!23"),
        source_spn: env("SPN", "ldap/dc1.magtest.local"),
        ip: env("IP", "10.69.134.20").parse()?,
        roles: env("ROLES", "").split(',').filter_map(role_of).collect(),
        request_rid_pool: env("RID_POOL", "0") == "1",
        skip_dns: env_flag("SKIP_DNS"),
        invocation_id,
    };

    // Echo the safety-relevant parameters so the operator can confirm before any write.
    let tls_mode = if params.target.use_ldaps {
        "LDAPS(636)"
    } else if params.target.use_starttls {
        "StartTLS"
    } else {
        "PLAINTEXT"
    };
    let ca = if params.target.tls_ca_pem.is_some() {
        "CA-verified"
    } else {
        "no-cert-verify"
    };
    eprintln!(
        "[promote] promoting {} into {} ...",
        params.dc_name, params.realm
    );
    eprintln!(
        "[promote] SAFETY  roles={:?}  request_rid_pool={}  skip_dns={}  transport={tls_mode} ({ca})",
        params.roles, params.request_rid_pool, params.skip_dns
    );
    let out = promote(&params).await?;
    eprintln!("[promote] computer        : {}", out.computer_dn);
    eprintln!("[promote] server          : {}", out.server_dn);
    eprintln!("[promote] nTDSDSA         : {}", out.ntds_dn);
    eprintln!("[promote] nTDSConnection  : {}", out.connection_dn);
    for n in &out.dns_nodes {
        eprintln!("[promote] dns             : {n}");
    }
    for (role, res) in &out.roles {
        eprintln!("[promote] FSMO {role:?} -> {res:?}");
    }
    if let Some(res) = out.rid_pool {
        eprintln!("[promote] RID pool        : {res:?}");
    }
    eprintln!("[promote] DONE");
    Ok(())
}
