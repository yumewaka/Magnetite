//! DC-join **discovery** — the read-only first phase of promoting magnetite to a
//! replica DC of an existing AD domain (Tier C, ② DC promotion).
//!
//! Before a DC can create its own `server` / `nTDSDSA` / computer objects in the
//! target domain, it must learn *where* they go: the naming contexts, the site to
//! join, and the existing DCs already in the replication topology. This module binds
//! to a source DC over LDAP and reads exactly that. A production DC rejects plaintext
//! binds (`StrongerAuthRequired`), so [`JoinTarget::use_starttls`] upgrades the
//! connection with StartTLS before binding — verifying the DC's certificate against a
//! supplied CA ([`JoinTarget::tls_ca_pem`]) or, without one, encrypting without peer
//! authentication (test only). Both the read (discovery) and write phases run over the
//! same negotiated transport.

use anyhow::{bail, Context, Result};
use futures::{SinkExt, StreamExt};
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapAddRequest, LdapAttribute, LdapBindCred, LdapBindRequest, LdapDerefAliases,
    LdapExtendedRequest, LdapFilter, LdapModify, LdapModifyRequest, LdapModifyType, LdapMsg,
    LdapOp, LdapPartialAttribute, LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope,
};
use ldap3_proto::{LdapCodec, LdapResultCode};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;

/// The StartTLS extended-operation OID (RFC 4511 §4.14.1).
const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// A framed-LDAP transport that is either plaintext TCP or a StartTLS-upgraded TLS
/// stream. Letting the write path be generic over "plain or TLS" keeps every helper
/// from having to name the concrete stream type.
pub enum LdapStream {
    /// An un-upgraded plaintext TCP connection.
    Plain(TcpStream),
    /// A TLS stream established by StartTLS over the original TCP connection.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for LdapStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LdapStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            LdapStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LdapStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            LdapStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            LdapStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LdapStream::Plain(s) => Pin::new(s).poll_flush(cx),
            LdapStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            LdapStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            LdapStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Build a rustls client connector for the join. With a CA PEM the server certificate
/// is verified against it (production); without one, any certificate is accepted —
/// the channel is encrypted but the peer is unauthenticated (test / PoC only).
fn tls_connector(ca_pem: Option<&str>) -> Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = if let Some(pem) = ca_pem {
        let mut roots = rustls::RootCertStore::empty();
        let mut rd = pem.as_bytes();
        for cert in rustls_pemfile::certs(&mut rd) {
            roots
                .add(cert.context("parse CA certificate")?)
                .context("add CA to root store")?;
        }
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth()
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

/// A `ServerCertVerifier` that accepts any certificate — encryption without peer
/// authentication. Used only when the caller supplies no CA (test / PoC); production
/// joins pass the DC's CA so the certificate is actually verified.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Where and how to reach the source DC's LDAP for the join.
#[derive(Debug, Clone)]
pub struct JoinTarget {
    /// `host:port` of the source DC's LDAP (e.g. `dc1.magtest.local:389`).
    pub host_port: String,
    /// The bind DN — a domain admin, e.g. `CN=Administrator,CN=Users,DC=magtest,DC=local`
    /// or the UPN `Administrator@MAGTEST.LOCAL`.
    pub bind_dn: String,
    /// The bind password.
    pub bind_password: String,
    /// Negotiate StartTLS before binding. A production DC rejects plaintext writes
    /// (`StrongerAuthRequired`); this upgrades the channel first. `false` binds in the
    /// clear (only usable against a DC configured to allow it). Ignored when
    /// [`use_ldaps`](Self::use_ldaps) is set.
    pub use_starttls: bool,
    /// Use **LDAPS** — implicit TLS for the whole connection (usually on `:636`), with
    /// no StartTLS negotiation. Takes precedence over [`use_starttls`](Self::use_starttls).
    pub use_ldaps: bool,
    /// PEM of the DC's issuing CA, used to verify the server certificate when TLS is
    /// used (StartTLS or LDAPS). `None` accepts any certificate — encryption without
    /// peer authentication (test / PoC only).
    pub tls_ca_pem: Option<String>,
}

impl JoinTarget {
    /// A plaintext (no-TLS) target — convenience for tests and DCs that allow
    /// unencrypted binds.
    #[must_use]
    pub fn plaintext(host_port: String, bind_dn: String, bind_password: String) -> Self {
        Self {
            host_port,
            bind_dn,
            bind_password,
            use_starttls: false,
            use_ldaps: false,
            tls_ca_pem: None,
        }
    }

    /// A StartTLS target. `ca_pem` verifies the server certificate; `None` accepts any
    /// certificate (encryption only — not for production against untrusted networks).
    #[must_use]
    pub fn starttls(
        host_port: String,
        bind_dn: String,
        bind_password: String,
        ca_pem: Option<String>,
    ) -> Self {
        Self {
            host_port,
            bind_dn,
            bind_password,
            use_starttls: true,
            use_ldaps: false,
            tls_ca_pem: ca_pem,
        }
    }
}

/// One existing DC discovered in the domain's replication topology.
#[derive(Debug, Clone)]
pub struct DcInfo {
    /// The `server` object DN (under `CN=Servers,CN=<site>,CN=Sites,CN=Configuration,…`).
    pub server_dn: String,
    /// The DC's DNS host name (`dNSHostName`), if published.
    pub dns_host_name: Option<String>,
    /// The `nTDSDSA` (NTDS Settings) object DN — the DC's directory-service identity.
    pub ntds_dn: Option<String>,
}

/// The domain layout a DC promotion needs, read from the source DC.
#[derive(Debug, Clone)]
pub struct JoinContext {
    /// The Configuration NC DN (`CN=Configuration,…`).
    pub config_nc: String,
    /// The domain NC DN (`DC=…`).
    pub domain_nc: String,
    /// The forest root domain NC DN.
    pub root_domain_nc: String,
    /// The bound server's own `nTDSDSA` DN (`dsServiceName`).
    pub ds_service_name: String,
    /// The Sites container DN (`CN=Sites,CN=Configuration,…`).
    pub sites_dn: String,
    /// The DCs already in the topology (their server / nTDSDSA objects).
    pub existing_dcs: Vec<DcInfo>,
}

/// The first UTF-8 value of `name` on `entry`, if present.
fn attr(entry: &LdapSearchResultEntry, name: &str) -> Option<String> {
    entry
        .attributes
        .iter()
        .find(|a| a.atype.eq_ignore_ascii_case(name))
        .and_then(|a| a.vals.first())
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// Run one search and collect its result entries.
async fn search<S: AsyncRead + AsyncWrite + Unpin>(
    framed: &mut Framed<S, LdapCodec>,
    msgid: i32,
    base: &str,
    scope: LdapSearchScope,
    filter: LdapFilter,
    attrs: Vec<String>,
) -> Result<Vec<LdapSearchResultEntry>> {
    let req = LdapSearchRequest {
        base: base.to_string(),
        scope,
        aliases: LdapDerefAliases::Never,
        sizelimit: 0,
        timelimit: 0,
        typesonly: false,
        filter,
        attrs,
    };
    framed
        .send(LdapMsg::new(msgid, LdapOp::SearchRequest(req)))
        .await?;
    let mut out = Vec::new();
    while let Some(item) = framed.next().await {
        match item?.op {
            LdapOp::SearchResultEntry(e) => out.push(e),
            LdapOp::SearchResultDone(res) => {
                if res.code != LdapResultCode::Success {
                    bail!(
                        "search under {base:?} failed: {:?} {}",
                        res.code,
                        res.message
                    );
                }
                break;
            }
            _ => {}
        }
    }
    Ok(out)
}

/// What to create when promoting this host to a DC.
#[derive(Debug, Clone)]
pub struct PromotionPlan {
    /// The DC's computer name (the CN, e.g. `MAGNETITE`; the machine account is
    /// `<name>$`).
    pub dc_name: String,
    /// The DC's DNS host name (e.g. `magnetite.magtest.local`).
    pub dns_host_name: String,
    /// The site DN to place the server object under (e.g.
    /// `CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=…`).
    pub site_dn: String,
}

/// The DNs created by [`promote_dc`].
#[derive(Debug, Clone)]
pub struct PromotionResult {
    pub server_dn: String,
    pub ntds_dn: String,
    pub computer_dn: String,
}

/// `userAccountControl` for a domain controller's computer account:
/// `SERVER_TRUST_ACCOUNT (0x2000) | TRUSTED_FOR_DELEGATION (0x80000)` = 0x82000.
pub const UAC_DC: u32 = 0x0008_0000 | 0x0000_2000;

/// Create the DC's **computer account** (`CN=<dc_name>,OU=Domain Controllers,<domainNC>`)
/// — a `computer` object with `SERVER_TRUST_ACCOUNT`. This is LDAP-addable (unlike the
/// system-only nTDSDSA) and gives the DC its machine identity. Returns the computer DN.
///
/// # Errors
/// A connection/bind failure, or a rejected add.
pub async fn add_dc_computer(
    target: &JoinTarget,
    ctx: &JoinContext,
    dc_name: &str,
    dns_host_name: &str,
) -> Result<String> {
    let computer_dn = format!("CN={dc_name},OU=Domain Controllers,{}", ctx.domain_nc);
    add_entry(
        target,
        &computer_dn,
        vec![
            ("objectClass".into(), vec![b"computer".to_vec()]),
            (
                "sAMAccountName".into(),
                vec![format!("{dc_name}$").into_bytes()],
            ),
            (
                "userAccountControl".into(),
                vec![UAC_DC.to_string().into_bytes()],
            ),
            (
                "dNSHostName".into(),
                vec![dns_host_name.as_bytes().to_vec()],
            ),
        ],
    )
    .await
    .context("create DC computer account")?;
    Ok(computer_dn)
}

/// Create this host's replica-DC objects in the target domain: the `server` object
/// under the site, its `nTDSDSA` (NTDS Settings) directory-service object naming the
/// NCs it will hold, and the DC's `computer` account (SERVER_TRUST_ACCOUNT) under
/// `OU=Domain Controllers`. The steps are attempted in order and each failure is
/// surfaced (Samba validates DC objects strictly).
///
/// # Errors
/// A connection/bind failure, or a rejected add (with the LDAP result code).
pub async fn promote_dc(
    target: &JoinTarget,
    ctx: &JoinContext,
    plan: &PromotionPlan,
) -> Result<PromotionResult> {
    let schema_nc = format!("CN=Schema,{}", ctx.config_nc);
    let server_dn = format!("CN={},CN=Servers,{}", plan.dc_name, plan.site_dn);
    let ntds_dn = format!("CN=NTDS Settings,{server_dn}");
    let computer_dn = format!(
        "CN={},OU=Domain Controllers,{}",
        plan.dc_name, ctx.domain_nc
    );

    // 1. The `server` object (topology node under the site).
    add_entry(
        target,
        &server_dn,
        vec![
            ("objectClass".into(), vec![b"server".to_vec()]),
            (
                "dNSHostName".into(),
                vec![plan.dns_host_name.as_bytes().to_vec()],
            ),
        ],
    )
    .await
    .context("create server object")?;

    // 2. The `nTDSDSA` — the DC's directory-service identity. It names the NCs this DC
    // holds (schema, config, domain). Samba assigns the invocationId / objectGUID.
    add_entry(
        target,
        &ntds_dn,
        vec![
            ("objectClass".into(), vec![b"nTDSDSA".to_vec()]),
            (
                "hasMasterNCs".into(),
                vec![
                    schema_nc.as_bytes().to_vec(),
                    ctx.config_nc.as_bytes().to_vec(),
                    ctx.domain_nc.as_bytes().to_vec(),
                ],
            ),
            // DS_BEHAVIOR_WIN2008R2 (3) — a reasonable functional level.
            ("msDS-Behavior-Version".into(), vec![b"3".to_vec()]),
            ("systemFlags".into(), vec![b"33554432".to_vec()]), // 0x2000000 = disallow move/delete
        ],
    )
    .await
    .context("create nTDSDSA object")?;

    // 3. The DC's computer account (SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION).
    add_entry(
        target,
        &computer_dn,
        vec![
            ("objectClass".into(), vec![b"computer".to_vec()]),
            (
                "sAMAccountName".into(),
                vec![format!("{}$", plan.dc_name).into_bytes()],
            ),
            ("userAccountControl".into(), vec![b"532480".to_vec()]), // 0x82000
            (
                "dNSHostName".into(),
                vec![plan.dns_host_name.as_bytes().to_vec()],
            ),
        ],
    )
    .await
    .context("create computer account")?;

    Ok(PromotionResult {
        server_dn,
        ntds_dn,
        computer_dn,
    })
}

/// Open a transport to `target`, upgrading to TLS via StartTLS first when requested.
async fn connect_stream(target: &JoinTarget) -> Result<LdapStream> {
    let tcp = TcpStream::connect(&target.host_port)
        .await
        .with_context(|| format!("connect {}", target.host_port))?;
    // LDAPS: the whole connection is TLS from the first byte (implicit TLS, usually on
    // :636) — no StartTLS negotiation. Wrap the socket immediately.
    if target.use_ldaps {
        let tls = tls_upgrade(target, tcp).await.context("LDAPS handshake")?;
        return Ok(LdapStream::Tls(Box::new(tls)));
    }
    if !target.use_starttls {
        return Ok(LdapStream::Plain(tcp));
    }
    // StartTLS: negotiate the extended operation on the raw TCP, then hand the socket
    // to rustls. The pre-upgrade dialog uses its own frame; the real bind follows on
    // the encrypted stream.
    let mut framed = Framed::new(tcp, LdapCodec::default());
    framed
        .send(LdapMsg::new(
            1,
            LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: STARTTLS_OID.into(),
                value: None,
            }),
        ))
        .await?;
    match framed.next().await {
        Some(Ok(m)) => match m.op {
            LdapOp::ExtendedResponse(r) if r.res.code == LdapResultCode::Success => {}
            LdapOp::ExtendedResponse(r) => {
                bail!("StartTLS rejected: {:?} {}", r.res.code, r.res.message)
            }
            other => bail!("expected StartTLS response, got {other:?}"),
        },
        Some(Err(e)) => return Err(e.into()),
        None => bail!("connection closed before StartTLS response"),
    }
    let tcp = framed.into_inner();
    let tls = tls_upgrade(target, tcp)
        .await
        .context("StartTLS handshake")?;
    Ok(LdapStream::Tls(Box::new(tls)))
}

/// Wrap a connected TCP socket in TLS, verifying the peer certificate against
/// `target.tls_ca_pem` when present (proper peer authentication) or accepting any
/// certificate when absent (encryption only — test/PoC). Shared by LDAPS and StartTLS.
async fn tls_upgrade(
    target: &JoinTarget,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let host = target
        .host_port
        .rsplit_once(':')
        .map_or(target.host_port.as_str(), |(h, _)| h);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid TLS server name {host}"))?;
    tls_connector(target.tls_ca_pem.as_deref())?
        .connect(server_name, tcp)
        .await
        .map_err(Into::into)
}

/// Connect to `target` (StartTLS-upgrading if configured) and perform an
/// authenticated simple bind, returning the framed connection.
async fn connect_bind(target: &JoinTarget) -> Result<Framed<LdapStream, LdapCodec>> {
    let mut framed = Framed::new(connect_stream(target).await?, LdapCodec::default());
    framed
        .send(LdapMsg::new(
            1,
            LdapOp::BindRequest(LdapBindRequest {
                dn: target.bind_dn.clone(),
                cred: LdapBindCred::Simple(target.bind_password.clone()),
            }),
        ))
        .await?;
    match framed.next().await {
        Some(Ok(m)) => match m.op {
            LdapOp::BindResponse(r) if r.res.code == LdapResultCode::Success => Ok(framed),
            LdapOp::BindResponse(r) => bail!("bind rejected: {:?} {}", r.res.code, r.res.message),
            other => bail!("expected bind response, got {other:?}"),
        },
        Some(Err(e)) => Err(e.into()),
        None => bail!("connection closed before bind response"),
    }
}

/// Add one directory entry to the target (bind, then `AddRequest`). `attributes` is
/// `(attributeName, values)` per attribute. Used by the promotion write phase to
/// create the DC's `server`/`nTDSDSA`/computer objects. Returns the LDAP result code
/// string on failure.
///
/// # Errors
/// A connection/bind failure, or an `AddResponse` whose code is not `Success`
/// (e.g. `EntryAlreadyExists`, `InsufficientAccessRights`, `StrongerAuthRequired`).
pub async fn add_entry(
    target: &JoinTarget,
    dn: &str,
    attributes: Vec<(String, Vec<Vec<u8>>)>,
) -> Result<()> {
    let mut framed = connect_bind(target).await?;
    let attributes = attributes
        .into_iter()
        .map(|(atype, vals)| LdapAttribute { atype, vals })
        .collect();
    framed
        .send(LdapMsg::new(
            2,
            LdapOp::AddRequest(LdapAddRequest {
                dn: dn.to_string(),
                attributes,
            }),
        ))
        .await?;
    let result = match framed.next().await {
        Some(Ok(m)) => match m.op {
            LdapOp::AddResponse(r) if r.code == LdapResultCode::Success => Ok(()),
            LdapOp::AddResponse(r) => bail!("add {dn} rejected: {:?} {}", r.code, r.message),
            other => bail!("expected add response, got {other:?}"),
        },
        Some(Err(e)) => Err(e.into()),
        None => bail!("connection closed before add response"),
    };
    let _ = framed.send(LdapMsg::new(3, LdapOp::UnbindRequest)).await;
    result
}

/// Delete the entry at `dn` (RFC 4511 §4.8 DelRequest). Used by the demotion
/// (leave) path to remove this DC's metadata objects from a surviving DC. The
/// entry must be a leaf; delete children first.
///
/// # Errors
/// A connection/bind failure, or a `DelResponse` whose code is not `Success`
/// (e.g. `NoSuchObject`, `NotAllowedOnNonLeaf`, `InsufficientAccessRights`).
pub async fn delete_entry(target: &JoinTarget, dn: &str) -> Result<()> {
    let mut framed = connect_bind(target).await?;
    framed
        .send(LdapMsg::new(2, LdapOp::DelRequest(dn.to_string())))
        .await?;
    let result = match framed.next().await {
        Some(Ok(m)) => match m.op {
            LdapOp::DelResponse(r) if r.code == LdapResultCode::Success => Ok(()),
            LdapOp::DelResponse(r) => bail!("delete {dn} rejected: {:?} {}", r.code, r.message),
            other => bail!("expected delete response, got {other:?}"),
        },
        Some(Err(e)) => Err(e.into()),
        None => bail!("connection closed before delete response"),
    };
    let _ = framed.send(LdapMsg::new(3, LdapOp::UnbindRequest)).await;
    result
}

/// Create the DC's `server` object under the site (`CN=<dc>,CN=Servers,<site_dn>`).
/// LDAP-addable (unlike the nTDSDSA that lives beneath it). Returns the server DN.
///
/// # Errors
/// A connection/bind failure, or a rejected add.
pub async fn add_dc_server(
    target: &JoinTarget,
    dc_name: &str,
    dns_host_name: &str,
    site_dn: &str,
) -> Result<String> {
    let server_dn = format!("CN={dc_name},CN=Servers,{site_dn}");
    add_entry(
        target,
        &server_dn,
        vec![
            ("objectClass".into(), vec![b"server".to_vec()]),
            (
                "dNSHostName".into(),
                vec![dns_host_name.as_bytes().to_vec()],
            ),
        ],
    )
    .await
    .context("create server object")?;
    Ok(server_dn)
}

/// Create an `nTDSConnection` topology object under the destination DC's NTDS
/// Settings, telling the KCC to pull from `from_server_ntds_dn` (the source DC's
/// `CN=NTDS Settings,...`). Real AD lets an admin add these directly (`repadmin
/// /add`); the KCC would otherwise generate them. Returns the connection DN.
///
/// `options=1` sets NTDSCONN_OPT_IS_GENERATED off / user-owned intent; the
/// connection is created enabled. Returns the created connection's DN.
///
/// # Errors
/// A connection/bind failure, or a rejected add.
pub async fn add_ntds_connection(
    target: &JoinTarget,
    dest_ntds_dn: &str,
    from_server_ntds_dn: &str,
    name: &str,
) -> Result<String> {
    let conn_dn = format!("CN={name},{dest_ntds_dn}");
    add_entry(
        target,
        &conn_dn,
        vec![
            ("objectClass".into(), vec![b"nTDSConnection".to_vec()]),
            (
                "fromServer".into(),
                vec![from_server_ntds_dn.as_bytes().to_vec()],
            ),
            ("enabledConnection".into(), vec![b"TRUE".to_vec()]),
            ("options".into(), vec![b"1".to_vec()]),
        ],
    )
    .await
    .context("create nTDSConnection")?;
    Ok(conn_dn)
}

/// Replace an attribute on an existing entry (bind, then `ModifyRequest`/replace).
/// Used to link the server object to the DC's computer account (`serverReference`).
///
/// # Errors
/// A connection/bind failure, or a `ModifyResponse` whose code is not `Success`.
pub async fn set_attribute(
    target: &JoinTarget,
    dn: &str,
    attr: &str,
    values: Vec<Vec<u8>>,
) -> Result<()> {
    modify(target, dn, LdapModifyType::Replace, attr, values).await
}

/// Set a machine (or user) account's password by writing `unicodePwd` — the value is
/// the password wrapped in double quotes, UTF-16LE encoded, per MS-ADTS §3.1.1.3.1.5.
/// AD only accepts this over an encrypted channel, so the target MUST use StartTLS.
/// Setting the promoted DC's machine password to a value magnetite knows is what lets
/// magnetite later derive its own Kerberos keys and authenticate inbound DRS binds
/// (the auth half of serving replication outbound).
///
/// # Errors
/// A non-StartTLS target, or a connection/bind/modify failure.
pub async fn set_machine_password(target: &JoinTarget, dn: &str, password: &str) -> Result<()> {
    if !target.use_starttls && !target.use_ldaps {
        bail!("setting unicodePwd requires an encrypted (StartTLS or LDAPS) connection");
    }
    let quoted = format!("\"{password}\"");
    let utf16: Vec<u8> = quoted.encode_utf16().flat_map(u16::to_le_bytes).collect();
    set_attribute(target, dn, "unicodePwd", vec![utf16]).await
}

/// Link the DC's `server` object to its computer account by setting the server's
/// `serverReference` to the computer DN — the linkage a promoted DC needs so the
/// server and machine account reference each other.
///
/// # Errors
/// A connection/bind/modify failure.
pub async fn set_server_reference(
    target: &JoinTarget,
    server_dn: &str,
    computer_dn: &str,
) -> Result<()> {
    set_attribute(
        target,
        server_dn,
        "serverReference",
        vec![computer_dn.as_bytes().to_vec()],
    )
    .await
}

// --- DNS registration (dnsNode objects in the AD-integrated DNS partition) ---
//
// AD stores DNS as `dnsNode` objects whose `dnsRecord` values are packed
// `DNS_RPC_RECORD` blobs (MS-DNSP §2.3.2.2). A promoted DC must register at
// least its host A record and the `<nTDSDSA-GUID>._msdcs.<domain>` CNAME that
// DRS resolves replication partners by, plus the `_ldap`/`_kerberos` SRV
// locator records. Writing them as directory objects avoids GSS-TSIG dynamic
// update while producing records Samba's internal DNS serves live.

const DNS_TYPE_A: u16 = 0x0001;
const DNS_TYPE_CNAME: u16 = 0x0005;
const DNS_TYPE_SRV: u16 = 0x0021;
const DNS_RANK_ZONE: u8 = 0xf0;
const DNS_DEFAULT_TTL: u32 = 900;

/// A DNS name in `DNS_RPC_NAME` form: total-length byte, label-count byte, then
/// each label length-prefixed, terminated by a zero length.
fn dns_rpc_name(fqdn: &str) -> Vec<u8> {
    let labels: Vec<&str> = fqdn.split('.').filter(|l| !l.is_empty()).collect();
    let mut name = Vec::new();
    for label in &labels {
        name.push(label.len() as u8);
        name.extend_from_slice(label.as_bytes());
    }
    name.push(0);
    let mut out = Vec::with_capacity(name.len() + 2);
    out.push(name.len() as u8);
    out.push(labels.len() as u8);
    out.extend_from_slice(&name);
    out
}

/// Pack a `DNS_RPC_RECORD` (fixed 24-byte header + type-specific data) as stored
/// in the `dnsRecord` attribute. `ttl` is written big-endian per MS-DNSP.
fn dns_record(wtype: u16, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(24 + data.len());
    r.extend_from_slice(&(data.len() as u16).to_le_bytes()); // wDataLength
    r.extend_from_slice(&wtype.to_le_bytes()); // wType
    r.push(5); // version
    r.push(DNS_RANK_ZONE); // rank
    r.extend_from_slice(&0u16.to_le_bytes()); // flags
    r.extend_from_slice(&1u32.to_le_bytes()); // dwSerial
    r.extend_from_slice(&DNS_DEFAULT_TTL.to_be_bytes()); // dwTtlSeconds (BE)
    r.extend_from_slice(&0u32.to_le_bytes()); // dwReserved
    r.extend_from_slice(&0u32.to_le_bytes()); // dwTimeStamp
    r.extend_from_slice(data);
    r
}

/// Add a value to a multi-valued attribute (bind, then `ModifyRequest`/add) —
/// non-destructive, unlike [`set_attribute`]'s replace.
///
/// # Errors
/// A connection/bind failure, or a `ModifyResponse` whose code is not `Success`.
pub async fn append_attribute(
    target: &JoinTarget,
    dn: &str,
    attr: &str,
    values: Vec<Vec<u8>>,
) -> Result<()> {
    modify(target, dn, LdapModifyType::Add, attr, values).await
}

/// Delete a specific value from a multi-valued attribute (used to deregister one
/// DC's record from a node shared with other DCs).
///
/// # Errors
/// A connection/bind failure, or a `ModifyResponse` whose code is not `Success`.
pub async fn delete_attribute_value(
    target: &JoinTarget,
    dn: &str,
    attr: &str,
    values: Vec<Vec<u8>>,
) -> Result<()> {
    modify(target, dn, LdapModifyType::Delete, attr, values).await
}

/// The LDAP relax-rules control OID (RFC-draft `ldap-relax`), which lets a privileged
/// admin write a `systemOnly` attribute (e.g. `rIDSetReferences` during dcpromo).
const RELAX_CONTROL_OID: &str = "1.3.6.1.4.1.4203.666.5.12";

/// Set an attribute with the LDAP **relax** control sent **critical**, so a `systemOnly`
/// attribute can be written by a privileged admin (a plain modify is refused with
/// `ConstraintViolation "can only be modified as system"`). Samba honours the relax
/// control only when it is marked critical, which `ldap3_proto` 0.5.2 cannot encode
/// (`LdapControl::Unknown` is always non-critical) — so the request PDU is hand-built
/// with `lber` and written to the socket, bypassing the codec (the same lber-level
/// workaround the SASL decode path uses). This makes dcpromo fully magnetite-driven.
///
/// # Errors
/// A connection/bind failure, a BER encode error, or a non-`Success` `ModifyResponse`.
pub async fn set_attribute_relax(
    target: &JoinTarget,
    dn: &str,
    attr: &str,
    values: Vec<Vec<u8>>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut framed = connect_bind(target).await?;
    let bytes = encode_modify_relax(2, dn, attr, values)?;
    // Write the hand-built PDU past the codec, then read the response through it.
    framed.get_mut().write_all(&bytes[..]).await?;
    framed.get_mut().flush().await?;
    let result = match framed.next().await {
        Some(Ok(m)) => match m.op {
            LdapOp::ModifyResponse(r) if r.code == LdapResultCode::Success => Ok(()),
            LdapOp::ModifyResponse(r) => {
                bail!("relax modify {dn} rejected: {:?} {}", r.code, r.message)
            }
            other => bail!("expected modify response, got {other:?}"),
        },
        Some(Err(e)) => Err(e.into()),
        None => bail!("connection closed before modify response"),
    };
    let _ = framed.send(LdapMsg::new(3, LdapOp::UnbindRequest)).await;
    result
}

/// Encode a single-change `ModifyRequest` (Replace) with a **critical** relax control,
/// returning the raw LDAP PDU. `ldap3_proto` 0.5.2 cannot emit a critical arbitrary
/// control, so the message is hand-built with `lber`: the control-less envelope is
/// produced by `ldap3_proto`, then a `[0]` controls element carrying
/// `SEQUENCE { OID, BOOLEAN TRUE }` is appended.
fn encode_modify_relax(
    msgid: i32,
    dn: &str,
    attr: &str,
    values: Vec<Vec<u8>>,
) -> Result<bytes::BytesMut> {
    use lber::common::TagClass;
    use lber::structure::PL;
    use lber::structures::{ASNTag, Boolean, OctetString, Sequence, Tag};

    let msg = LdapMsg::new(
        msgid,
        LdapOp::ModifyRequest(LdapModifyRequest {
            dn: dn.to_string(),
            changes: vec![LdapModify {
                operation: LdapModifyType::Replace,
                modification: LdapPartialAttribute {
                    atype: attr.to_string(),
                    vals: values,
                },
            }],
        }),
    );
    let mut envelope: lber::structure::StructureTag = msg.into();
    // Control ::= SEQUENCE { controlType OID, criticality BOOLEAN TRUE }.
    let relax = Tag::Sequence(Sequence {
        inner: vec![
            Tag::OctetString(OctetString {
                inner: RELAX_CONTROL_OID.as_bytes().to_vec(),
                ..Default::default()
            }),
            Tag::Boolean(Boolean {
                inner: true,
                ..Default::default()
            }),
        ],
        ..Default::default()
    });
    // Controls ::= [0] SEQUENCE OF Control — append it to the message envelope.
    let controls = Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: 0,
        inner: vec![relax],
    })
    .into_structure();
    if let PL::C(ref mut items) = envelope.payload {
        items.push(controls);
    }
    let mut bytes = bytes::BytesMut::new();
    lber::write::encode_into(&mut bytes, envelope)
        .map_err(|e| anyhow::anyhow!("encode relax modify: {e:?}"))?;
    Ok(bytes)
}

/// One `ModifyRequest` with a single change of the given type.
async fn modify(
    target: &JoinTarget,
    dn: &str,
    operation: LdapModifyType,
    attr: &str,
    values: Vec<Vec<u8>>,
) -> Result<()> {
    modify_ctrls(target, dn, operation, attr, values, Vec::new()).await
}

/// One `ModifyRequest` with a single change and optional request controls.
async fn modify_ctrls(
    target: &JoinTarget,
    dn: &str,
    operation: LdapModifyType,
    attr: &str,
    values: Vec<Vec<u8>>,
    controls: Vec<LdapControl>,
) -> Result<()> {
    let mut framed = connect_bind(target).await?;
    framed
        .send(LdapMsg::new_with_ctrls(
            2,
            LdapOp::ModifyRequest(LdapModifyRequest {
                dn: dn.to_string(),
                changes: vec![LdapModify {
                    operation,
                    modification: LdapPartialAttribute {
                        atype: attr.to_string(),
                        vals: values,
                    },
                }],
            }),
            controls,
        ))
        .await?;
    let result = match framed.next().await {
        Some(Ok(m)) => match m.op {
            LdapOp::ModifyResponse(r) if r.code == LdapResultCode::Success => Ok(()),
            LdapOp::ModifyResponse(r) => bail!("modify {dn} rejected: {:?} {}", r.code, r.message),
            other => bail!("expected modify response, got {other:?}"),
        },
        Some(Err(e)) => Err(e.into()),
        None => bail!("connection closed before modify response"),
    };
    let _ = framed.send(LdapMsg::new(3, LdapOp::UnbindRequest)).await;
    result
}

/// Create a `dnsNode` at `DC=<node>,<zone_dn>` carrying one packed record, or —
/// if the node already exists (shared SRV nodes hold every DC's value) — *append*
/// the record so no other DC's records are lost. Returns the node DN.
///
/// # Errors
/// A connection/bind failure, or a rejected add/modify.
pub async fn add_dns_node(
    target: &JoinTarget,
    zone_dn: &str,
    node: &str,
    record: Vec<u8>,
) -> Result<String> {
    let node_dn = format!("DC={node},{zone_dn}");
    let add = add_entry(
        target,
        &node_dn,
        vec![
            ("objectClass".into(), vec![b"dnsNode".to_vec()]),
            ("dnsRecord".into(), vec![record.clone()]),
        ],
    )
    .await;
    if add.is_err() {
        // Node already present — append this DC's record, never overwrite.
        append_attribute(target, &node_dn, "dnsRecord", vec![record]).await?;
    }
    Ok(node_dn)
}

/// Register the DC's host **A** record (`<host>` in the domain zone) → `ip`.
///
/// # Errors
/// A connection/bind/write failure.
pub async fn register_dns_a(
    target: &JoinTarget,
    zone_dn: &str,
    host_label: &str,
    ip: std::net::Ipv4Addr,
) -> Result<String> {
    add_dns_node(
        target,
        zone_dn,
        host_label,
        dns_record(DNS_TYPE_A, &ip.octets()),
    )
    .await
}

/// Register a **CNAME** node (e.g. `<nTDSDSA-GUID>._msdcs`) → `target_fqdn`.
///
/// # Errors
/// A connection/bind/write failure.
pub async fn register_dns_cname(
    target: &JoinTarget,
    zone_dn: &str,
    node: &str,
    target_fqdn: &str,
) -> Result<String> {
    add_dns_node(
        target,
        zone_dn,
        node,
        dns_record(DNS_TYPE_CNAME, &dns_rpc_name(target_fqdn)),
    )
    .await
}

/// Register an **SRV** node (e.g. `_ldap._tcp.dc`) → `target_fqdn:port`.
///
/// # Errors
/// A connection/bind/write failure.
pub async fn register_dns_srv(
    target: &JoinTarget,
    zone_dn: &str,
    node: &str,
    priority: u16,
    weight: u16,
    port: u16,
    target_fqdn: &str,
) -> Result<String> {
    let mut data = Vec::new();
    data.extend_from_slice(&priority.to_be_bytes());
    data.extend_from_slice(&weight.to_be_bytes());
    data.extend_from_slice(&port.to_be_bytes());
    data.extend_from_slice(&dns_rpc_name(target_fqdn));
    add_dns_node(target, zone_dn, node, dns_record(DNS_TYPE_SRV, &data)).await
}

/// Read one object's `objectGUID` as its raw 16 bytes (the DRS wire form) — the
/// destination-DSA / source-DSA identifier the FSMO and DsAddEntry calls need.
///
/// # Errors
/// A connection/bind failure, a missing entry, or an `objectGUID` that is not 16 bytes.
pub async fn read_object_guid(target: &JoinTarget, dn: &str) -> Result<[u8; 16]> {
    let mut framed = connect_bind(target).await?;
    let entries = search(
        &mut framed,
        2,
        dn,
        LdapSearchScope::Base,
        LdapFilter::Present("objectClass".into()),
        vec!["objectGUID".into()],
    )
    .await?;
    let _ = framed.send(LdapMsg::new(3, LdapOp::UnbindRequest)).await;
    let raw = entries
        .first()
        .and_then(|e| {
            e.attributes
                .iter()
                .find(|a| a.atype.eq_ignore_ascii_case("objectGUID"))
        })
        .and_then(|a| a.vals.first())
        .ok_or_else(|| anyhow::anyhow!("no objectGUID on {dn}"))?;
    raw.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("objectGUID on {dn} is not 16 bytes"))
}

/// List the immediate child DNs of `base` (one-level search). Used by the demotion
/// (leave) path to find the leaving DC's `nTDSConnection` objects (children of its
/// NTDS Settings) so they can be deleted before the parent. Returns an empty list if
/// `base` does not exist.
///
/// # Errors
/// A connection/bind failure, or a rejected search (other than a missing base).
pub async fn list_child_dns(target: &JoinTarget, base: &str) -> Result<Vec<String>> {
    let mut framed = connect_bind(target).await?;
    let entries = search(
        &mut framed,
        2,
        base,
        LdapSearchScope::OneLevel,
        LdapFilter::Present("objectClass".into()),
        vec!["1.1".into()], // no attributes, DNs only
    )
    .await;
    let _ = framed.send(LdapMsg::new(3, LdapOp::UnbindRequest)).await;
    match entries {
        Ok(entries) => Ok(entries.into_iter().map(|e| e.dn).collect()),
        // A missing base is not an error for the leave path — nothing to delete.
        Err(e) if e.to_string().contains("NoSuchObject") => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Bind to the source DC and discover the domain layout a promotion needs.
///
/// # Errors
/// A connection/bind failure, a rejected search, or a missing RootDSE naming context.
pub async fn discover(target: &JoinTarget) -> Result<JoinContext> {
    // Authenticated bind (StartTLS-upgraded when the target requests it).
    let mut framed = connect_bind(target).await?;

    // RootDSE: the naming contexts + this server's own DSA name.
    let root = search(
        &mut framed,
        2,
        "",
        LdapSearchScope::Base,
        LdapFilter::Present("objectClass".into()),
        vec![
            "configurationNamingContext".into(),
            "defaultNamingContext".into(),
            "rootDomainNamingContext".into(),
            "dsServiceName".into(),
        ],
    )
    .await?;
    let rootdse = root.first().context("no RootDSE entry")?;
    let config_nc = attr(rootdse, "configurationNamingContext")
        .context("RootDSE: no configurationNamingContext")?;
    let domain_nc =
        attr(rootdse, "defaultNamingContext").context("RootDSE: no defaultNamingContext")?;
    let root_domain_nc =
        attr(rootdse, "rootDomainNamingContext").unwrap_or_else(|| domain_nc.clone());
    let ds_service_name = attr(rootdse, "dsServiceName").unwrap_or_default();
    let sites_dn = format!("CN=Sites,{config_nc}");

    // Existing DCs: the `server` objects under the sites, with their nTDSDSA + host name.
    let servers = search(
        &mut framed,
        3,
        &sites_dn,
        LdapSearchScope::Subtree,
        LdapFilter::Equality("objectClass".into(), "server".into()),
        vec!["dNSHostName".into()],
    )
    .await?;
    let mut existing_dcs = Vec::with_capacity(servers.len());
    let mut msgid = 4;
    for s in &servers {
        // The DSA is the `nTDSDSA` (CN=NTDS Settings) directly under the server object.
        let ntds = search(
            &mut framed,
            msgid,
            &s.dn,
            LdapSearchScope::OneLevel,
            LdapFilter::Equality("objectClass".into(), "nTDSDSA".into()),
            vec![],
        )
        .await
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|e| e.dn);
        msgid += 1;
        existing_dcs.push(DcInfo {
            server_dn: s.dn.clone(),
            dns_host_name: attr(s, "dNSHostName"),
            ntds_dn: ntds,
        });
    }

    let _ = framed
        .send(LdapMsg::new(msgid, LdapOp::UnbindRequest))
        .await;
    Ok(JoinContext {
        config_nc,
        domain_nc,
        root_domain_nc,
        ds_service_name,
        sites_dn,
        existing_dcs,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        dns_record, dns_rpc_name, encode_modify_relax, DNS_TYPE_A, DNS_TYPE_CNAME,
        RELAX_CONTROL_OID,
    };
    use std::net::Ipv4Addr;

    #[test]
    fn relax_modify_pdu_carries_a_critical_control() {
        let pdu = encode_modify_relax(
            2,
            "CN=MAGNETITE,OU=Domain Controllers,DC=magtest,DC=local",
            "rIDSetReferences",
            vec![b"CN=RID Set,CN=MAGNETITE,OU=Domain Controllers,DC=magtest,DC=local".to_vec()],
        )
        .expect("encode");
        // The relax control OID is present as an ASCII OCTET STRING.
        let oid = RELAX_CONTROL_OID.as_bytes();
        assert!(
            pdu.windows(oid.len()).any(|w| w == oid),
            "relax OID present in the PDU"
        );
        // A criticality BOOLEAN TRUE (tag 0x01, len 0x01, value 0xff) is emitted — the
        // whole point (ldap3_proto omits criticality when false). Its DER form is 0xff.
        assert!(
            pdu.windows(3).any(|w| w == [0x01, 0x01, 0xff]),
            "critical BOOLEAN TRUE present"
        );
        // The modify target DN is in the request.
        let dn = b"CN=MAGNETITE,OU=Domain Controllers,DC=magtest,DC=local";
        assert!(pdu.windows(dn.len()).any(|w| w == dn), "modify DN present");
    }

    /// Ground truth: DC1's own host A record blob from Samba (172.17.0.2).
    #[test]
    fn a_record_matches_samba() {
        let got = dns_record(DNS_TYPE_A, &Ipv4Addr::new(172, 17, 0, 2).octets());
        let want: &[u8] = &[
            0x04, 0x00, 0x01, 0x00, 0x05, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x11, 0x00, 0x02,
        ];
        assert_eq!(got, want);
    }

    /// Ground truth: DC1's `<dsa-guid>._msdcs` CNAME blob (-> dc1.magtest.local).
    #[test]
    fn cname_record_matches_samba() {
        let got = dns_record(DNS_TYPE_CNAME, &dns_rpc_name("dc1.magtest.local"));
        let want: &[u8] = &[
            0x15, 0x00, 0x05, 0x00, 0x05, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x03, 0x03, 0x64,
            0x63, 0x31, 0x07, 0x6d, 0x61, 0x67, 0x74, 0x65, 0x73, 0x74, 0x05, 0x6c, 0x6f, 0x63,
            0x61, 0x6c, 0x00,
        ];
        assert_eq!(got, want);
    }
}
