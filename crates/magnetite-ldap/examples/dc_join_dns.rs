//! DC promotion, slice 6 (DNS): register the records that make a promoted DC
//! locatable — the host A record, the `<nTDSDSA-GUID>._msdcs` CNAME that DRS
//! resolves partners by, and the `_ldap`/`_kerberos` SRV locator records — as
//! dnsNode objects in the AD-integrated DNS partition.
//!
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  DC_NAME=magnetite IP=10.69.134.20 NTDS_GUID=<guid> \
//!  cargo run -p magnetite-ldap --example dc_join_dns`

use magnetite_ldap::dc_join::{register_dns_a, register_dns_cname, register_dns_srv, JoinTarget};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let target = JoinTarget {
        host_port: std::env::var("TARGET").unwrap_or_else(|_| "127.0.0.1:1389".into()),
        bind_dn: std::env::var("BIND_DN").unwrap_or_else(|_| "Administrator@MAGTEST.LOCAL".into()),
        bind_password: std::env::var("BIND_PW").unwrap_or_else(|_| "Passw0rd!23".into()),
        use_starttls: std::env::var("STARTTLS").is_ok(),
        use_ldaps: false,
        tls_ca_pem: std::env::var("TLS_CA")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok()),
    };
    let dc = std::env::var("DC_NAME").unwrap_or_else(|_| "magnetite".into());
    let ip: std::net::Ipv4Addr = std::env::var("IP")
        .unwrap_or_else(|_| "10.69.134.20".into())
        .parse()?;
    let ntds_guid = std::env::var("NTDS_GUID")
        .unwrap_or_else(|_| "4e47414d-3133-8130-92a3-b4c5d6e7f809".into());
    let domain = std::env::var("DOMAIN").unwrap_or_else(|_| "magtest.local".into());

    // Zone DNs: the domain-forward zone (host A) and the forest `_msdcs` zone.
    let domain_zone = format!(
        "DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        domain
            .split('.')
            .map(|l| format!("DC={l}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let msdcs_zone = format!(
        "DC=_msdcs.{domain},CN=MicrosoftDNS,DC=ForestDnsZones,{}",
        domain
            .split('.')
            .map(|l| format!("DC={l}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let host_fqdn = format!("{dc}.{domain}");

    let a = register_dns_a(&target, &domain_zone, &dc, ip).await?;
    eprintln!("[dns] A     {a}  -> {ip}");
    let cn = register_dns_cname(&target, &msdcs_zone, &ntds_guid, &host_fqdn).await?;
    eprintln!("[dns] CNAME {cn}  -> {host_fqdn}");
    let srv_ldap = register_dns_srv(
        &target,
        &msdcs_zone,
        "_ldap._tcp.dc",
        0,
        100,
        389,
        &host_fqdn,
    )
    .await?;
    eprintln!("[dns] SRV   {srv_ldap}  -> {host_fqdn}:389");
    let srv_krb = register_dns_srv(
        &target,
        &msdcs_zone,
        "_kerberos._tcp.dc",
        0,
        100,
        88,
        &host_fqdn,
    )
    .await?;
    eprintln!("[dns] SRV   {srv_krb}  -> {host_fqdn}:88");
    Ok(())
}
