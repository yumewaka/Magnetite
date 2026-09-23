//! Client GSS-SPNEGO (Kerberos) SASL bind to a live Samba DC over LDAP (Tier C item C).
//!
//! magnetite authenticates to the DC with **Kerberos** — an AP-REQ from a real service
//! ticket for `ldap/<host>`, SPNEGO-framed — instead of sending a cleartext password in a
//! simple bind. This is how DCs bind one another. Validated end to end against live Samba
//! (`SASL-BIND-INTEROP-OK`): the bind completes in ONE round.
//!
//! Two details make Samba complete in a single round (mirroring a real client):
//!   * a **non-DCE** AP-REQ ([`build_gss_ap_req_from_ticket`] — flags `0x3E`, without
//!     `GSS_C_DCE_STYLE`), so the acceptor does not wait for a DCE third leg;
//!   * a **two-mech** SPNEGO negTokenInit `[MS-KRB5, KRB5]`
//!     ([`wrap_ap_req_spnego_ldap`]), so no mechListMIC round is needed.
//!
//! `KDC=127.0.0.1:8088 LDAP=127.0.0.1:1389 SPN_HOST=dc1.magtest.local \
//!  USERK=Administrator cargo run -p magnetite-ldap --example sasl_bind`

use futures::{SinkExt, StreamExt};
use ldap3_proto::proto::{LdapBindCred, LdapBindRequest, LdapMsg, LdapOp, SaslCredentials};
use ldap3_proto::{LdapCodec, LdapResultCode};
use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::spnego::wrap_ap_req_spnego_ldap;
use magnetite_krb5::{build_gss_ap_req_from_ticket, obtain_service_ticket};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

/// The GSS per-message sequence base — the AP-REQ authenticator's seq-number.
const SEQ_BASE: u32 = 0x1234_5678;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let realm = "MAGTEST.LOCAL";
    let kdc = std::env::var("KDC")
        .unwrap_or_else(|_| "127.0.0.1:8088".into())
        .parse()?;
    let ldap = std::env::var("LDAP").unwrap_or_else(|_| "127.0.0.1:1389".into());
    let host = std::env::var("SPN_HOST").unwrap_or_else(|_| "dc1.magtest.local".into());
    let user = std::env::var("USERK").unwrap_or_else(|_| "Administrator".into());
    let pass = std::env::var("PASS").unwrap_or_else(|_| "Passw0rd!23".into());

    // A service ticket for ldap/<host>, then a NON-DCE AP-REQ from it, SPNEGO-wrapped
    // with the two-mech [MS-KRB5, KRB5] list.
    let key = derive_aes256_key(&pass, &default_salt(realm, std::slice::from_ref(&user)))
        .map_err(|e| format!("derive key: {e}"))?;
    let ticket = obtain_service_ticket(kdc, realm, &[user.as_str()], &key, &["ldap", &host])
        .await
        .map_err(|e| format!("ticket: {e}"))?;
    eprintln!("[1] got ldap/{host} ticket");
    let ap_req = build_gss_ap_req_from_ticket(
        &ticket.ticket_der,
        &ticket.session_key,
        realm,
        &[user.as_str()],
        SEQ_BASE,
    )
    .map_err(|e| format!("build AP-REQ: {e}"))?;
    let neg_token_init = wrap_ap_req_spnego_ldap(&ap_req);

    let mut framed = Framed::new(TcpStream::connect(&ldap).await?, LdapCodec::default());
    framed
        .send(LdapMsg::new(
            1,
            LdapOp::BindRequest(LdapBindRequest {
                dn: String::new(),
                cred: LdapBindCred::SASL(SaslCredentials {
                    mechanism: "GSS-SPNEGO".to_string(),
                    credentials: neg_token_init,
                }),
            }),
        ))
        .await?;
    eprintln!("[2] sent GSS-SPNEGO bindRequest (AP-REQ)");

    let msg = framed.next().await.ok_or("connection closed")??;
    let LdapOp::BindResponse(r) = msg.op else {
        return Err(format!("expected BindResponse, got {:?}", msg.op).into());
    };
    match r.res.code {
        LdapResultCode::Success => {
            eprintln!("[3] Kerberos GSS-SPNEGO SASL BIND SUCCESS  [SASL-BIND-INTEROP-OK]");
            Ok(())
        }
        other => Err(format!("bind failed: {other:?} {}", r.res.message).into()),
    }
}
