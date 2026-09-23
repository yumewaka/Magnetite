//! A minimal DCE/RPC (`ncacn_ip_tcp`) **client** — enough to drive a DRSUAPI
//! replication pull (Tier C C1): open the connection, BIND the interface, then
//! `DRSBind` + `IDL_DRSGetNCChanges` over REQUEST/RESPONSE, and hand the decoded
//! reply to the inbound-apply path. Unauthenticated for now (the source must allow
//! it, as our own server does); Kerberos DRS auth is a later step, and a full V8
//! request marshalling (NC DN, dest DSA) is needed for a real Samba source.

use crate::auth::{
    auth_token, SecTrailer, RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
};
use crate::drsuapi::{
    exop, parse_get_nc_changes_reply, ExOpErr, FsmoRole, ReplicatedChanges, ReplicatedObject,
    DRSUAPI_UUID,
};
use crate::error::{RpcError, RpcResult};
use crate::ndr::{NdrReader, NdrWriter};
use crate::pdu::{
    build_pdu, build_pdu_with_auth, build_pdu_with_auth_pfc, common_header, pfc, ptype,
    CommonHeader, HEADER_LEN, NDR32_UUID, NDR32_VERSION,
};
use magnetite_krb5::gss::{
    gss_mic, gss_unwrap_iov, gss_wrap_iov, KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL,
};
use magnetite_krb5::spnego::{extract_ap_rep, wrap_ap_req, wrap_ap_req_raw};
use magnetite_krb5::{build_ap_req, build_ap_req_from_ticket, dce_style_auth3};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Build an 8-byte `sec_trailer` (auth_type, auth_level, pad, reserved, ctx_id=1).
/// The auth_context_id is 1 to match what Samba's own DRSUAPI client presents.
fn sec_trailer(auth_type: u8, auth_level: u8, pad: u8) -> [u8; 8] {
    [auth_type, auth_level, pad, 0, 1, 0, 0, 0]
}

const OP_DRS_BIND: u16 = 0;
const OP_GET_NC_CHANGES: u16 = 3;
const OP_DRS_ADD_ENTRY: u16 = 17;

/// Marshal a `DRS_MSG_ADDENTRYREQ_V2` (MS-DRSR 4.1.5) that adds ONE object: the
/// `hDrs` handle, `dwInVersion` = 2, the inline union arm, and a single-element
/// `ENTINFLIST` = `{pNextEntInf(null), ENTINF{pName DSNAME, ulFlags, AttrBlock}}`.
/// `attrs` is `(ATTRTYP, values)` per attribute — the inverse of the ENTINF the
/// GetNCChanges reply decoder parses. `pmsgIn` is a top-level `[ref]` (no referent id;
/// union inline); the ENTINFLIST arm is u32-only so it needs no 8-alignment.
fn build_add_entry_stub(
    handle: &[u8; 20],
    dn: &str,
    guid: &[u8; 16],
    attrs: &[(u32, Vec<Vec<u8>>)],
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    let mut refid = 0x0002_0004u32;
    let mut next_ref = || {
        let r = refid;
        refid += 4;
        r
    };
    w.bytes(handle); // hDrs
    w.u32(2); // dwInVersion = 2
    w.u32(2); // union switch tag = 2
              // ENTINFLIST (inline): pNextEntInf(null) + ENTINF.
    w.u32(0); // pNextEntInf referent (null → a single entry)
    w.u32(next_ref()); // ENTINF.pName referent
    w.u32(0); // ENTINF.ulFlags
    w.u32(attrs.len() as u32); // AttrBlock.attrCount
    let p_attr = if attrs.is_empty() { 0 } else { next_ref() };
    w.u32(p_attr); // AttrBlock.pAttr referent
                   // Deferred: the pName DSNAME.
    encode_request_dsname(&mut w, guid, dn);
    // Deferred: the ATTR array (conformant), then per-attr the ATTRVAL array + values.
    if !attrs.is_empty() {
        w.u32(attrs.len() as u32); // ATTR array MaxCount
        for (attid, vals) in attrs {
            w.u32(*attid); // attrTyp
            w.u32(vals.len() as u32); // AttrVal.valCount
            w.u32(next_ref()); // AttrVal.pAVal referent
        }
        for (_, vals) in attrs {
            w.u32(vals.len() as u32); // ATTRVAL array MaxCount
            for v in vals {
                w.u32(v.len() as u32); // valLen
                w.u32(next_ref()); // pVal referent
            }
            for v in vals {
                w.u32(v.len() as u32); // pVal byte-array MaxCount
                w.bytes(v);
                w.align(4);
            }
        }
    }
    w.into_bytes()
}

/// The initiator's initial GSS per-message sequence number (AP-REQ authenticator
/// seq-number and the Wrap/MIC counter seed). Any value works as long as both
/// sides agree; a fixed non-zero base keeps the handshake deterministic.
const GSS_SEQ_BASE: u32 = 0x1234_5678;

/// The auth-trailer length of a PKT_PRIVACY CFX in-place Wrap token for AES256 as
/// Samba's C `gssapi_seal_packet` emits it: token header (16) + confounder (16) +
/// encrypted header-copy (16) + checksum (12). Independent of the stub length (the
/// stub ciphertext seals in place).
const SEAL_AUTH_LEN: u16 = 60;

/// Encode a hyphenated UUID string into DCE little-endian byte order (Data1–3
/// little-endian, Data4 as-is). Returns zeros on a malformed string.
fn guid_le(uuid: &str) -> [u8; 16] {
    let parts: Vec<&str> = uuid.split('-').collect();
    let mut out = [0u8; 16];
    if parts.len() != 5 {
        return out;
    }
    let hex = |s: &str| -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    };
    let mut p = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        let mut bytes = hex(part);
        if idx < 3 {
            bytes.reverse(); // Data1/2/3 are little-endian
        }
        for b in bytes {
            if p < 16 {
                out[p] = b;
                p += 1;
            }
        }
    }
    out
}

/// Build a BIND body proposing one presentation context: the `abstract` interface
/// (uuid + version) over NDR 2.0.
fn build_bind_body(context_id: u16, abstract_uuid: [u8; 16], abstract_version: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    b.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    b.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id (0 = new)
    b.push(1); // n_context_elem
    b.extend_from_slice(&[0u8; 3]); // reserved + reserved2
    b.extend_from_slice(&context_id.to_le_bytes());
    b.push(1); // n_transfer_syn
    b.push(0); // reserved
    b.extend_from_slice(&abstract_uuid); // abstract syntax interface uuid
    b.extend_from_slice(&abstract_version.to_le_bytes()); // interface version
    b.extend_from_slice(&NDR32_UUID); // transfer syntax
    b.extend_from_slice(&NDR32_VERSION.to_le_bytes());
    b
}

/// Build a REQUEST body: alloc_hint, context id, opnum, then the stub.
fn build_request_body(context_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + stub.len());
    b.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    b.extend_from_slice(&context_id.to_le_bytes());
    b.extend_from_slice(&opnum.to_le_bytes());
    b.extend_from_slice(stub);
    b
}

/// The well-known `NTDSAPI_CLIENT_GUID` a DRS client presents as `puuidClientDsa`
/// in `IDL_DRSBind` (MS-DRSR). Samba/Windows accept it from any replication client.
const DRS_BIND_CLIENT_GUID: &str = "e24d201a-4fd6-11d1-a3da-0000f875ae0d";

/// Build the `IDL_DRSBind` request stub: `puuidClientDsa` (a unique pointer to the
/// well-known client GUID) followed by a NULL `pextClient` — the minimal bind a
/// real Samba source accepts (it fills in its own extensions in the reply).
fn build_drs_bind_stub() -> Vec<u8> {
    let mut s = Vec::with_capacity(24);
    s.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // puuidClientDsa referent
    s.extend_from_slice(&guid_le(DRS_BIND_CLIENT_GUID)); // the GUID value
    s.extend_from_slice(&0u32.to_le_bytes()); // pextClient = NULL
    s
}

/// A `GetNCChanges` V8 request stub carrying the DRS handle plus the fields the
/// server reads: `dwInVersion`(8) at byte 20, `usnvecFrom.usnHighObjUpdate` at 72,
/// `cMaxObjects` at 104. (A real Samba source also needs the NC DN + dest DSA GUID,
/// a later refinement.)
fn build_get_nc_changes_stub(handle: &[u8; 20], from: i64, max_objects: u32) -> Vec<u8> {
    let mut s = vec![0u8; 108];
    s[0..20].copy_from_slice(handle);
    s[20..24].copy_from_slice(&8u32.to_le_bytes()); // dwInVersion = 8
    s[72..80].copy_from_slice(&from.to_le_bytes()); // usnvecFrom.usnHighObjUpdate
    s[104..108].copy_from_slice(&max_objects.to_le_bytes()); // cMaxObjects
    s
}

/// Parameters for a full V8 `IDL_DRSGetNCChanges` request — the complete
/// `DRS_MSG_GETCHGREQ_V8` a *real* source DC (Samba/Windows) requires, unlike the
/// minimal stub our own server accepts.
pub struct GetNcChangesRequest<'a> {
    /// The DRS handle from `DRSBind`.
    pub handle: [u8; 20],
    /// The destination DSA's objectGUID (this DC's identity).
    pub dest_dsa: [u8; 16],
    /// The source DSA's invocation ID we replicate from.
    pub src_invocation: [u8; 16],
    /// The naming context DN to replicate (e.g. `DC=example,DC=com`).
    pub nc_dn: &'a str,
    /// The naming context objectGUID (zeros if unknown — the DN resolves it).
    pub nc_guid: [u8; 16],
    /// `usnvecFrom.usnHighObjUpdate` — replicate changes newer than this.
    pub from: i64,
    /// `ulFlags` (e.g. `DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED`).
    pub flags: u32,
    /// `cMaxObjects` (0 = source's choice).
    pub max_objects: u32,
    /// `ulExtendedOp` (0 = normal replication; `EXOP_REPL_OBJ` = 6 targets the single
    /// object named by `pNC`/`nc_guid` — the primitive a DCSync of one account uses).
    pub ext_op: u32,
    /// The destination's up-to-dateness cursors (`pUpToDateVecDest`): `(dsa, high_usn)`
    /// per source DSA we already hold changes from. When non-empty the source sends
    /// only the objects newer than these cursors — a true wire-level delta. Empty ⇒ a
    /// null `pUpToDateVecDest` (the source re-enumerates everything).
    pub utdv: &'a [([u8; 16], i64)],
}

/// Encode a request `DSNAME` (the `pNC` naming-context pointer target): the hoisted
/// conformant `StringName` MaxCount, then structLen/SidLen/Guid/Sid/NameLen/name.
fn encode_request_dsname(w: &mut NdrWriter, guid: &[u8; 16], name: &str) {
    let chars: Vec<u16> = name.encode_utf16().collect();
    let max_count = chars.len() + 1;
    let struct_len = 4 + 4 + 4 + 16 + 28 + 4 + 2 * max_count;
    w.u32(max_count as u32);
    w.u32(struct_len as u32);
    w.u32(0); // SidLen
    w.bytes(guid);
    w.bytes(&[0u8; 28]); // Sid
    w.u32(chars.len() as u32); // NameLen
    for c in &chars {
        w.u16(*c);
    }
    w.u16(0); // NUL
    w.align(4);
}

impl GetNcChangesRequest<'_> {
    /// Marshal the full V8 request stub (the inverse of a source DC's request
    /// parser). Field offsets match what our server also reads (dwInVersion@20,
    /// usnvecFrom@72, cMaxObjects@104), but every field a real source needs — a
    /// non-null `pmsgIn`, `pNC` DSNAME, dest/src DSA GUIDs, flags — is present.
    pub fn marshal_v8(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.bytes(&self.handle); // hDrs
        w.u32(8); // dwInVersion
                  // `pmsgIn` is a top-level `[ref]` pointer in the IDL, so NDR emits *no*
                  // referent id for it — the union is marshalled inline. The non-encapsulated
                  // union then carries its own switch tag (a copy of dwInVersion), after which
                  // the arm is aligned to the union's maximum member alignment (8, for the
                  // USN_VECTOR / ULARGE_INTEGER hypers). Verified byte-for-byte against impacket.
        w.u32(8); // union switch tag = dwInVersion
        w.align(8); // align the V8 arm to 8
        w.bytes(&self.dest_dsa); // uuidDsaObjDest
        w.bytes(&self.src_invocation); // uuidInvocIdSrc
        w.u32(0x0002_0004); // pNC referent (non-null)
        w.align(8); // USN_VECTOR is 8-aligned (4 pad → usnvecFrom @72)
        w.bytes(&self.from.to_le_bytes()); // usnvecFrom.usnHighObjUpdate
        w.bytes(&[0u8; 16]); // usnReserved + usnHighPropUpdate
                             // pUpToDateVecDest referent: non-null when we carry cursors, so the source can
                             // send only the delta past them.
        w.u32(if self.utdv.is_empty() { 0 } else { 0x0002_0008 });
        w.u32(self.flags); // ulFlags
        w.u32(self.max_objects); // cMaxObjects (@104)
        w.u32(0); // cMaxBytes
        w.u32(self.ext_op); // ulExtendedOp (EXOP_REPL_OBJ = 6 for a single object)
        w.align(8); // liFsmoInfo (ULARGE_INTEGER) is 8-aligned
        w.bytes(&[0u8; 8]); // liFsmoInfo
        w.u32(0); // pPartialAttrSet (null)
        w.u32(0); // pPartialAttrSetEx (null)
        w.u32(0); // PrefixTableDest.PrefixCount
        w.u32(0); // PrefixTableDest.pPrefixEntry (null)
                  // Deferred referents, in struct-pointer order: pNC (field 3) then, if present,
                  // pUpToDateVecDest (field 5).
        encode_request_dsname(&mut w, &self.nc_guid, self.nc_dn);
        if !self.utdv.is_empty() {
            encode_request_utdv(&mut w, self.utdv);
        }
        w.into_bytes()
    }
}

/// Encode the deferred `pUpToDateVecDest` payload — an `UPTODATE_VECTOR_V1_EXT`: the
/// hoisted `rgCursors` MaxCount, the 8-aligned struct scalars, then the 8-aligned
/// `UPTODATE_CURSOR_V1` array (`uuidDsa`(16) + `usnHighPropUpdate`(8), 24 bytes each).
/// Byte-verified against impacket.
fn encode_request_utdv(w: &mut NdrWriter, cursors: &[([u8; 16], i64)]) {
    w.u32(cursors.len() as u32); // rgCursors conformant MaxCount (hoisted) = cNumCursors
    w.align(8); // the vector struct holds hypers → 8-aligned after the MaxCount
    w.u32(1); // dwVersion = 1
    w.u32(0); // dwReserved1
    w.u32(cursors.len() as u32); // cNumCursors
    w.u32(0); // dwReserved2
    w.align(8); // the cursor array is 8-aligned (each cursor leads with a GUID + hyper)
    for (dsa, high_usn) in cursors {
        w.bytes(dsa); // uuidDsa
        w.bytes(&high_usn.to_le_bytes()); // usnHighPropUpdate
    }
}

/// Read the naming-context DN back from a marshalled V8 request stub (the `pNC`
/// DSNAME deferred payload begins at byte 144). For round-trip validation.
#[cfg(test)]
fn parse_request_nc_dn(stub: &[u8]) -> Option<String> {
    let mut r = NdrReader::new(stub.get(144..)?);
    r.u32()?; // MaxCount
    r.u32()?; // structLen
    r.u32()?; // SidLen
    let _guid: [u8; 16] = r.array()?;
    r.take(28)?; // Sid
    let name_len = r.u32()? as usize;
    let mut units = Vec::with_capacity(name_len);
    for _ in 0..name_len {
        units.push(r.u16()?);
    }
    Some(String::from_utf16_lossy(&units))
}

/// Extract the stub from a RESPONSE PDU body (`alloc_hint`(4) + `context_id`(2) +
/// `cancel_count`(1) + reserved(1) + stub), or map a FAULT to an error.
fn response_stub(header: &CommonHeader, body: &[u8]) -> RpcResult<Vec<u8>> {
    match header.ptype {
        ptype::RESPONSE if body.len() >= 8 => Ok(body[8..].to_vec()),
        ptype::FAULT => Err(RpcError::Client("DRS request faulted".into())),
        _ => Err(RpcError::Client("unexpected reply PDU".into())),
    }
}

/// A connected DRS replication client.
pub struct DrsClient {
    stream: TcpStream,
    call_id: u32,
    context_id: u16,
    handle: [u8; 20],
    /// The GSS acceptor subkey once a Kerberos bind completes; `None` =
    /// unauthenticated. When set, every REQUEST is GSS-protected.
    gss: Option<Vec<u8>>,
    /// Negotiated auth level: PKT_INTEGRITY (sign) or PKT_PRIVACY (seal). Samba's
    /// DRSUAPI requires PRIVACY.
    auth_level: u8,
    /// Whether DCE/RPC header signing is negotiated — set for the sealed Samba path
    /// so each protected PDU folds its header + sec_trailer into the GSS checksum.
    header_signing: bool,
    /// DCE/RPC auth type: `RPC_C_AUTHN_GSS_NEGOTIATE` (SPNEGO) or, for the sealed
    /// Samba path, `RPC_C_AUTHN_GSS_KERBEROS` (bare Kerberos SSP).
    auth_type: u8,
    /// Per-message GSS sequence number.
    seq: u64,
}

impl DrsClient {
    /// Connect to `addr`, BIND the DRSUAPI interface, and `DRSBind` to obtain a DRS
    /// handle. Unauthenticated.
    ///
    /// # Errors
    /// A connection, BIND, or `DRSBind` failure.
    pub async fn connect(addr: SocketAddr) -> RpcResult<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| RpcError::Client(format!("connect: {e}")))?;
        let mut client = Self {
            stream,
            call_id: 1,
            context_id: 0,
            handle: [0u8; 20],
            gss: None,
            auth_level: RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            header_signing: false,
            auth_type: RPC_C_AUTHN_GSS_NEGOTIATE,
            seq: 0,
        };

        // DCE BIND the DRSUAPI interface (v4.0).
        let bind = build_pdu(
            ptype::BIND,
            client.call_id,
            &build_bind_body(client.context_id, guid_le(DRSUAPI_UUID), 4),
        );
        client.send(&bind).await?;
        let (h, _body) = client.recv().await?;
        if h.ptype != ptype::BIND_ACK {
            return Err(RpcError::Client("BIND rejected".into()));
        }
        client.drs_bind().await?;
        Ok(client)
    }

    /// Connect and **Kerberos-authenticate** the bind: present an AP-REQ for
    /// `service_spn` (built under the shared `service_key`), recover the acceptor
    /// subkey from the server's AP-REP, and thereafter GSS-sign every request
    /// (PKT_INTEGRITY) — the form a real DRS source (Samba/Windows) requires.
    ///
    /// # Errors
    /// A connection, AP-REQ/AP-REP, or `DRSBind` failure.
    pub async fn connect_kerberos(
        addr: SocketAddr,
        service_key: &[u8],
        realm: &str,
        service_spn: &[&str],
        client_principal: &[&str],
    ) -> RpcResult<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| RpcError::Client(format!("connect: {e}")))?;
        let mut client = Self {
            stream,
            call_id: 1,
            context_id: 0,
            handle: [0u8; 20],
            gss: None,
            auth_level: RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            header_signing: false,
            auth_type: RPC_C_AUTHN_GSS_NEGOTIATE,
            seq: 0,
        };

        // Self-mint an AP-REQ under the shared service key (our own server).
        let (ap_req, session_key) = build_ap_req(service_key, realm, service_spn, client_principal)
            .map_err(|e| RpcError::Client(format!("build AP-REQ: {e}")))?;
        client.kerberos_bind(&ap_req, &session_key).await?;
        client.drs_bind().await?;
        Ok(client)
    }

    /// Connect and Kerberos-authenticate using a ticket **already obtained from a
    /// (foreign) KDC** — [`obtain_service_ticket`](magnetite_krb5::obtain_service_ticket)
    /// against e.g. Samba's KDC. Unlike [`connect_kerberos`](Self::connect_kerberos),
    /// the ticket is opaque (we do not hold the service key), so it is presented
    /// as-is in the AP-REQ. Thereafter every request is GSS-signed (PKT_INTEGRITY).
    ///
    /// # Errors
    /// A connection, AP-REQ/AP-REP, or `DRSBind` failure.
    pub async fn connect_kerberos_ticket(
        addr: SocketAddr,
        ticket_der: &[u8],
        session_key: &[u8],
        realm: &str,
        client_principal: &[&str],
    ) -> RpcResult<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| RpcError::Client(format!("connect: {e}")))?;
        // The GSS per-message sequence base: it goes in the AP-REQ authenticator's
        // seq-number and seeds our Wrap/MIC counter, so the acceptor's expected
        // SND_SEQ matches the first sealed request (Heimdal enforces this).
        let seq_base = GSS_SEQ_BASE;
        let mut client = Self {
            stream,
            call_id: 1,
            context_id: 0,
            handle: [0u8; 20],
            gss: None,
            auth_level: RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            header_signing: false,
            auth_type: RPC_C_AUTHN_GSS_NEGOTIATE,
            seq: u64::from(seq_base),
        };
        // Samba's DRSUAPI requires the session to be sealed (encrypted), and folds
        // the PDU header + sec_trailer into each request's checksum (header signing).
        client.auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        client.header_signing = true;
        client.auth_type = RPC_C_AUTHN_GSS_KERBEROS;
        let ap_req =
            build_ap_req_from_ticket(ticket_der, session_key, realm, client_principal, seq_base)
                .map_err(|e| RpcError::Client(format!("build AP-REQ from ticket: {e}")))?;
        client.kerberos_bind(&ap_req, session_key).await?;
        client.drs_bind().await?;
        Ok(client)
    }

    /// Send an authenticated BIND carrying `ap_req` (GSS, PKT_INTEGRITY) and recover
    /// the GSS acceptor subkey from the mutual-auth AP-REP in the BIND_ACK.
    async fn kerberos_bind(&mut self, ap_req: &[u8], session_key: &[u8]) -> RpcResult<()> {
        // Raw Kerberos SSP presents a bare GSS-KRB5 token; SPNEGO wraps it.
        let token = if self.auth_type == RPC_C_AUTHN_GSS_KERBEROS {
            wrap_ap_req_raw(ap_req)
        } else {
            wrap_ap_req(ap_req)
        };
        let mut body = build_bind_body(self.context_id, guid_le(DRSUAPI_UUID), 4);
        body.extend_from_slice(&sec_trailer(self.auth_type, self.auth_level, 0));
        body.extend_from_slice(&token);
        // A sealed (Samba) session negotiates DCE/RPC header signing so the acceptor
        // includes the PDU header + sec_trailer in each request's checksum.
        let mut flags = pfc::FIRST_FRAG | pfc::LAST_FRAG;
        if self.header_signing {
            flags |= pfc::SUPPORT_HEADER_SIGN;
        }
        let pdu =
            build_pdu_with_auth_pfc(ptype::BIND, flags, self.call_id, &body, token.len() as u16);
        self.send(&pdu).await?;

        let (h, ack) = self.recv().await?;
        if h.ptype != ptype::BIND_ACK {
            return Err(RpcError::Client(format!(
                "Kerberos BIND rejected (ptype {})",
                h.ptype
            )));
        }
        let auth = auth_token(&ack, h.auth_length as usize)
            .ok_or_else(|| RpcError::Client("BIND_ACK has no auth token".into()))?;
        let ap_rep =
            extract_ap_rep(auth).ok_or_else(|| RpcError::Client("no AP-REP in BIND_ACK".into()))?;

        // Samba's `gensec_gssapi` DRSUAPI acceptor runs GSS in DCE style: after the
        // BIND_ACK / AP-REP it stays CONTINUE_NEEDED and expects a third leg. Complete
        // it — decrypt the acceptor's AP-REP for the GSS context (sealing) key and mint
        // the client AP-REP (the AUTH3 token). Without this the acceptor never reaches
        // COMPLETE and every sealed request faults RPC_S_SEC_PKG_ERROR (0x721).
        let (subkey, auth3_token) = dce_style_auth3(session_key, ap_rep)
            .map_err(|e| RpcError::Client(format!("DCE-style AUTH3: {e}")))?;
        self.gss = Some(subkey);

        // The rpc_auth3 PDU (C706 §12.6.4.2): common header, a 4-byte MBZ pad, then the
        // sec_trailer + the client AP-REP as the auth verifier. Same call_id as the
        // BIND; the acceptor consumes it to finish the context and sends no reply.
        let mut auth3_body = vec![0u8; 4];
        auth3_body.extend_from_slice(&sec_trailer(self.auth_type, self.auth_level, 0));
        auth3_body.extend_from_slice(&auth3_token);
        let auth3 = build_pdu_with_auth_pfc(
            ptype::AUTH3,
            pfc::FIRST_FRAG | pfc::LAST_FRAG,
            self.call_id,
            &auth3_body,
            auth3_token.len() as u16,
        );
        self.send(&auth3).await?;
        Ok(())
    }

    /// `DRSBind` (opnum 0): extract the 20-byte `DRS_HANDLE` that follows the
    /// server's `ppextServer` (`DRS_EXTENSIONS_INT`) out-parameter.
    ///
    /// The extensions blob is *variable length* — a real Samba/Windows source sizes
    /// it by its own supported-extension set (Samba returns 48 bytes, but this differs
    /// by version), so the handle offset cannot be hardcoded. Parse the conformant
    /// `DRS_EXTENSIONS` (`ppextServer` referent, hoisted `MaxCount`, `cb`, then
    /// `rgb[MaxCount]`) and read the context handle immediately after.
    async fn drs_bind(&mut self) -> RpcResult<()> {
        let reply = self.call(OP_DRS_BIND, &build_drs_bind_stub()).await?;
        let mut r = NdrReader::new(&reply);
        let referent = r.u32().ok_or(RpcError::Truncated)?;
        if referent != 0 {
            let max_count = r.u32().ok_or(RpcError::Truncated)? as usize; // rgb conformant size
            r.u32().ok_or(RpcError::Truncated)?; // DRS_EXTENSIONS.cb
            r.take(max_count).ok_or(RpcError::Truncated)?; // rgb[MaxCount]
            r.align(4); // NDR pads the conformant array up to 4
        }
        self.handle = r.array::<20>().ok_or(RpcError::Truncated)?;
        Ok(())
    }

    /// Pull changes newer than `from` (the source USN cursor), up to `max_objects`
    /// (0 = no client limit), and decode the reply.
    ///
    /// # Errors
    /// A transport failure, a FAULT, or an undecodable reply.
    pub async fn get_nc_changes(
        &mut self,
        from: i64,
        max_objects: u32,
    ) -> RpcResult<ReplicatedChanges> {
        let stub = build_get_nc_changes_stub(&self.handle, from, max_objects);
        let reply = self.call(OP_GET_NC_CHANGES, &stub).await?;
        parse_get_nc_changes_reply(&reply)
            .ok_or_else(|| RpcError::Client("undecodable GetNCChanges reply".into()))
    }

    /// Pull changes with a **full V8 request** naming a specific naming context —
    /// the form a real Samba/Windows source requires. `dest_dsa`/`src_invocation`
    /// identify the DCs; `from` is the source USN cursor.
    ///
    /// # Errors
    /// A transport failure, a FAULT, or an undecodable reply.
    pub async fn get_nc_changes_v8(
        &mut self,
        nc_dn: &str,
        dest_dsa: [u8; 16],
        src_invocation: [u8; 16],
        from: i64,
        flags: u32,
        max_objects: u32,
    ) -> RpcResult<ReplicatedChanges> {
        self.get_nc_changes_delta(
            nc_dn,
            dest_dsa,
            src_invocation,
            from,
            flags,
            max_objects,
            &[],
        )
        .await
    }

    /// Like [`Self::get_nc_changes_v8`], but carrying the destination's up-to-dateness
    /// cursors (`pUpToDateVecDest`) so the source returns only the objects newer than
    /// them — a true wire-level delta. `utdv` is `(source_dsa, high_usn)` per DSA we
    /// already hold changes from; empty behaves exactly like `get_nc_changes_v8`.
    ///
    /// # Errors
    /// A transport failure, a FAULT, or an undecodable reply.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_nc_changes_delta(
        &mut self,
        nc_dn: &str,
        dest_dsa: [u8; 16],
        src_invocation: [u8; 16],
        from: i64,
        flags: u32,
        max_objects: u32,
        utdv: &[([u8; 16], i64)],
    ) -> RpcResult<ReplicatedChanges> {
        let req = GetNcChangesRequest {
            handle: self.handle,
            dest_dsa,
            src_invocation,
            nc_dn,
            nc_guid: [0u8; 16],
            from,
            flags,
            max_objects,
            ext_op: 0,
            utdv,
        };
        let reply = self.call(OP_GET_NC_CHANGES, &req.marshal_v8()).await?;
        parse_get_nc_changes_reply(&reply)
            .ok_or_else(|| RpcError::Client("undecodable GetNCChanges reply".into()))
    }

    /// Replicate a **single object** by its `objectGUID` via the `EXOP_REPL_OBJ`
    /// extended operation — the targeted primitive a DCSync of one account uses
    /// (the equivalent of `secretsdump -just-dc-user`). With `DRS_WRIT_REP` the reply
    /// carries the object's secrets. Returns the object, or `None` if the source
    /// returned an empty reply.
    ///
    /// # Errors
    /// A transport failure, a FAULT, or an undecodable reply.
    pub async fn replicate_single_object(
        &mut self,
        object_guid: [u8; 16],
    ) -> RpcResult<Option<ReplicatedObject>> {
        const EXOP_REPL_OBJ: u32 = 6;
        const DRS_WRIT_REP: u32 = 0x0000_0010;
        let req = GetNcChangesRequest {
            handle: self.handle,
            dest_dsa: [0u8; 16],
            src_invocation: [0u8; 16],
            nc_dn: "", // the GUID identifies the object; no DN needed
            nc_guid: object_guid,
            from: 0,
            flags: DRS_WRIT_REP,
            max_objects: 1,
            ext_op: EXOP_REPL_OBJ,
            utdv: &[],
        };
        let reply = self.call(OP_GET_NC_CHANGES, &req.marshal_v8()).await?;
        let changes = parse_get_nc_changes_reply(&reply)
            .ok_or_else(|| RpcError::Client("undecodable GetNCChanges reply".into()))?;
        Ok(changes.objects.into_iter().next())
    }

    /// Request the transfer of an FSMO (operation-master) **role** from the source DC
    /// (the current owner) to `dest_ntds_guid` (the caller's `nTDSDSA`). This is the
    /// client half of a graceful `ntdsutil`-style role transfer: the source rewrites
    /// the role object's `fSMORoleOwner` to the caller and replicates the change back.
    /// `role_object_dn`/`role_object_guid` identify the role object (see
    /// [`FsmoRole::object_dn`]); a zero GUID lets the source resolve it by DN.
    ///
    /// Returns the extended-operation result and the replicated role object (if any).
    /// A non-[`ExOpErr::Success`] result means the source declined (e.g.
    /// [`ExOpErr::NotOwner`]).
    ///
    /// # Errors
    /// A transport failure, a FAULT, or an undecodable reply.
    pub async fn transfer_fsmo_role(
        &mut self,
        role: FsmoRole,
        role_object_dn: &str,
        role_object_guid: [u8; 16],
        dest_ntds_guid: [u8; 16],
    ) -> RpcResult<(ExOpErr, Option<ReplicatedObject>)> {
        self.extended_op(
            role.exop(),
            role_object_dn,
            role_object_guid,
            dest_ntds_guid,
        )
        .await
    }

    /// Request a **RID allocation pool** from the RID master (`EXOP_FSMO_RID_ALLOC`) so
    /// a freshly promoted DC can mint security principals. `rid_manager_dn` is
    /// `CN=RID Manager$,CN=System,<domain>`; `dest_ntds_guid` is the caller's `nTDSDSA`.
    /// On success the returned `(first_rid, count)` is the granted pool, decoded from the
    /// reply object's `rIDAllocationPool`.
    ///
    /// # Errors
    /// A transport failure, a FAULT, or an undecodable reply.
    pub async fn request_rid_pool(
        &mut self,
        rid_manager_dn: &str,
        rid_manager_guid: [u8; 16],
        dest_ntds_guid: [u8; 16],
    ) -> RpcResult<(ExOpErr, Option<(u32, u32)>)> {
        let (err, obj) = self
            .request_rid_pool_object(rid_manager_dn, rid_manager_guid, dest_ntds_guid)
            .await?;
        Ok((err, obj.and_then(|o| o.rid_allocation_pool())))
    }

    /// Like [`request_rid_pool`](Self::request_rid_pool) but returns the raw replicated
    /// object the RID master sends back (the caller's RID-Set object) rather than the
    /// decoded pool — for diagnostics / interop when the pool attribute's on-wire ATTID
    /// is not yet known.
    ///
    /// # Errors
    /// A transport failure, a FAULT, or an undecodable reply.
    pub async fn request_rid_pool_object(
        &mut self,
        rid_manager_dn: &str,
        rid_manager_guid: [u8; 16],
        dest_ntds_guid: [u8; 16],
    ) -> RpcResult<(ExOpErr, Option<ReplicatedObject>)> {
        self.extended_op(
            exop::FSMO_RID_ALLOC,
            rid_manager_dn,
            rid_manager_guid,
            dest_ntds_guid,
        )
        .await
    }

    /// Drive one `IDL_DRSGetNCChanges` extended operation (`ext_op` != 0) against the
    /// object named by `dn`/`guid`, on behalf of `dest_ntds_guid`. Shared by the FSMO
    /// role-transfer and RID-allocation calls. `DRS_WRIT_REP` marks the caller a
    /// writeable replica (required for a role transfer).
    async fn extended_op(
        &mut self,
        ext_op: u32,
        dn: &str,
        guid: [u8; 16],
        dest_ntds_guid: [u8; 16],
    ) -> RpcResult<(ExOpErr, Option<ReplicatedObject>)> {
        const DRS_WRIT_REP: u32 = 0x0000_0010;
        let req = GetNcChangesRequest {
            handle: self.handle,
            dest_dsa: dest_ntds_guid,
            src_invocation: [0u8; 16],
            nc_dn: dn,
            nc_guid: guid,
            from: 0,
            flags: DRS_WRIT_REP,
            max_objects: 1,
            ext_op,
            utdv: &[],
        };
        let reply = self.call(OP_GET_NC_CHANGES, &req.marshal_v8()).await?;
        let changes = parse_get_nc_changes_reply(&reply).ok_or_else(|| {
            RpcError::Client("undecodable GetNCChanges (extended op) reply".into())
        })?;
        Ok((
            ExOpErr::from_raw(changes.ext_op_err),
            changes.objects.into_iter().next(),
        ))
    }

    /// `IDL_DRSAddEntry` (opnum 17): add one object to the directory over the sealed
    /// DRS bind. `attrs` is `(ATTRTYP, values)` per attribute. This is how a replica DC
    /// creates its `nTDSDSA` (which LDAP refuses as a system-only class). Returns the
    /// raw reply stub (a `DRS_MSG_ADDENTRYREPLY`); the caller inspects it. Faults (e.g.
    /// access denied) surface as an error.
    ///
    /// # Errors
    /// A transport failure or a FAULT (with the RPC status).
    pub async fn ds_add_entry(
        &mut self,
        dn: &str,
        guid: [u8; 16],
        attrs: &[(u32, Vec<Vec<u8>>)],
    ) -> RpcResult<Vec<u8>> {
        let stub = build_add_entry_stub(&self.handle, dn, &guid, attrs);
        self.call(OP_DRS_ADD_ENTRY, &stub).await
    }

    /// The GSS session key of the established security context — the key MS-DRSR
    /// §5.16.4 uses to unwrap replicated secrets (`unicodePwd` etc.). For our
    /// DCE-style Kerberos bind this is the acceptor subkey recovered from the AP-REP.
    /// `None` until the Kerberos bind completes.
    pub fn session_key(&self) -> Option<&[u8]> {
        self.gss.as_deref()
    }

    /// Replicate a whole NC by paging: repeatedly call [`Self::get_nc_changes_v8`],
    /// advancing the `usnvecFrom` cursor to each reply's `usnvecTo`, until the source
    /// reports no more data or `max_pages` is reached. Objects are returned in wire
    /// order across all pages. `flags` is applied to every page (e.g. `DRS_WRIT_REP`
    /// to request secrets); the first page also drives the from-scratch sync.
    ///
    /// # Errors
    /// Any per-page transport failure, FAULT, or undecodable reply.
    pub async fn replicate_nc(
        &mut self,
        nc_dn: &str,
        flags: u32,
        page_size: u32,
        max_pages: usize,
    ) -> RpcResult<Vec<ReplicatedObject>> {
        let mut all = Vec::new();
        let mut from = 0i64;
        for _ in 0..max_pages {
            let page = self
                .get_nc_changes_v8(nc_dn, [0u8; 16], [0u8; 16], from, flags, page_size)
                .await?;
            all.extend(page.objects);
            if !page.more_data || page.usn_to <= from {
                break;
            }
            from = page.usn_to;
        }
        Ok(all)
    }

    /// Send one REQUEST for `opnum`/`stub` and return the RESPONSE stub. When a GSS
    /// context is established the request is signed (PKT_INTEGRITY) and the signed
    /// response's stub is extracted.
    async fn call(&mut self, opnum: u16, stub: &[u8]) -> RpcResult<Vec<u8>> {
        self.call_id += 1;
        if let Some(subkey) = self.gss.clone() {
            return self.signed_call(opnum, stub, &subkey).await;
        }
        let pdu = build_pdu(
            ptype::REQUEST,
            self.call_id,
            &build_request_body(self.context_id, opnum, stub),
        );
        self.send(&pdu).await?;
        let (header, body) = self.recv().await?;
        response_stub(&header, &body)
    }

    /// A GSS-protected REQUEST. PKT_INTEGRITY signs the padded stub with a MIC;
    /// PKT_PRIVACY seals it with a Wrap token (the stub travels encrypted). Then
    /// recover the protected response's stub.
    async fn signed_call(&mut self, opnum: u16, stub: &[u8], subkey: &[u8]) -> RpcResult<Vec<u8>> {
        // PKT_PRIVACY seals the stub in place, so it must be aligned to the 16-byte
        // AES block (the acceptor decrypts whole blocks); PKT_INTEGRITY only needs
        // the 4-byte MIC alignment.
        let block = if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
            16
        } else {
            4
        };
        let pad = (block - stub.len() % block) % block;
        let mut padded = stub.to_vec();
        padded.resize(padded.len() + pad, 0);
        let seq = self.seq;
        self.seq += 1;
        let sec_tr = sec_trailer(self.auth_type, self.auth_level, pad as u8);

        let pdu = if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
            // The in-place seal's auth trailer is a fixed 76 bytes (token header 16 +
            // confounder 16 + filler 16 + header-copy 16 + checksum 12), so the PDU
            // header — and thus the header-signing AAD — is known before sealing.
            let auth_length = SEAL_AUTH_LEN;
            let frag_length = (HEADER_LEN + 8 + padded.len() + 8 + auth_length as usize) as u16;
            let header = common_header(
                ptype::REQUEST,
                pfc::FIRST_FRAG | pfc::LAST_FRAG,
                frag_length,
                auth_length,
                self.call_id,
            );
            // The request header (alloc_hint, context id, opnum) follows the PDU header.
            let mut req_hdr = Vec::with_capacity(8);
            req_hdr.extend_from_slice(&(padded.len() as u32).to_le_bytes());
            req_hdr.extend_from_slice(&self.context_id.to_le_bytes());
            req_hdr.extend_from_slice(&opnum.to_le_bytes());
            // Header signing splits SIGN_ONLY around the stub (Samba's
            // `gssapi_seal_packet`): `pre` = PDU header + request header (before the
            // stub), `post` = sec_trailer (after it). Empty when it is not negotiated.
            let (pre, post): (Vec<u8>, Vec<u8>) = if self.header_signing {
                ([header.as_slice(), &req_hdr].concat(), sec_tr.to_vec())
            } else {
                (Vec::new(), Vec::new())
            };
            let (pdu_stub, auth) =
                gss_wrap_iov(subkey, KG_USAGE_INITIATOR_SEAL, seq, &pre, &post, &padded)
                    .map_err(|e| RpcError::Client(format!("gss_wrap_iov: {e}")))?;
            let mut out = header.to_vec();
            out.extend_from_slice(&req_hdr);
            out.extend_from_slice(&pdu_stub);
            out.extend_from_slice(&sec_tr);
            out.extend_from_slice(&auth);
            out
        } else {
            let mic = gss_mic(subkey, seq, &padded)
                .map_err(|e| RpcError::Client(format!("gss_mic: {e}")))?;
            let mut body = Vec::with_capacity(8 + padded.len() + 8 + mic.len());
            body.extend_from_slice(&(padded.len() as u32).to_le_bytes()); // alloc_hint
            body.extend_from_slice(&self.context_id.to_le_bytes());
            body.extend_from_slice(&opnum.to_le_bytes());
            body.extend_from_slice(&padded);
            body.extend_from_slice(&sec_tr);
            body.extend_from_slice(&mic);
            build_pdu_with_auth(ptype::REQUEST, self.call_id, &body, mic.len() as u16)
        };
        self.send(&pdu).await?;

        // A large reply (e.g. a full DRS page) is fragmented across many RESPONSE
        // PDUs, each independently PKT_PRIVACY-sealed with its own auth trailer and
        // GSS sequence number (the Wrap token is self-describing). Reassemble by
        // unsealing each fragment's stub chunk and concatenating until LAST_FRAG.
        let mut full = Vec::new();
        loop {
            let (header, body) = self.recv().await?;
            let last = header.pfc_flags & pfc::LAST_FRAG != 0;
            full.extend_from_slice(&self.protected_response_stub(&header, &body, subkey)?);
            if last {
                break;
            }
        }
        Ok(full)
    }

    /// Recover the stub from a GSS-protected RESPONSE: strip the 8-byte header and
    /// the trailing `sec_trailer`(8) + auth token, then for PKT_PRIVACY unseal the
    /// stub (acceptor usage) and drop the pad.
    fn protected_response_stub(
        &self,
        header: &CommonHeader,
        body: &[u8],
        subkey: &[u8],
    ) -> RpcResult<Vec<u8>> {
        if header.ptype == ptype::FAULT {
            let status = body
                .get(8..12)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            return Err(RpcError::Client(format!(
                "DRS request faulted (status 0x{status:08x})"
            )));
        }
        if header.ptype != ptype::RESPONSE {
            return Err(RpcError::Client("unexpected reply PDU".into()));
        }
        let auth_len = header.auth_length as usize;
        let trailer_start = body
            .len()
            .checked_sub(auth_len + 8)
            .ok_or_else(|| RpcError::Client("protected response too short".into()))?;
        let pad = SecTrailer::parse(&body[trailer_start..])
            .map(|t| t.auth_pad_len as usize)
            .unwrap_or(0);
        let sec_tr = &body[trailer_start..trailer_start + 8];
        let auth = &body[trailer_start + 8..trailer_start + 8 + auth_len];
        let payload = body
            .get(8..trailer_start)
            .ok_or_else(|| RpcError::Client("bad body".into()))?;

        if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
            // The acceptor's response is header-signed too, with SIGN_ONLY split
            // around the stub: `pre` = PDU header + the 8-byte response header (the
            // bytes before the stub), `post` = sec_trailer. The on-wire header is
            // reconstructed from the parsed fields (standard little-endian DREP).
            let (pre, post): (Vec<u8>, Vec<u8>) = if self.header_signing {
                let rh = common_header(
                    ptype::RESPONSE,
                    header.pfc_flags,
                    header.frag_length,
                    header.auth_length,
                    header.call_id,
                );
                ([rh.as_slice(), &body[..8]].concat(), sec_tr.to_vec())
            } else {
                (Vec::new(), Vec::new())
            };
            let plain = gss_unwrap_iov(subkey, KG_USAGE_ACCEPTOR_SEAL, &pre, &post, payload, auth)
                .ok_or_else(|| RpcError::Client("response unseal failed".into()))?;
            let end = plain
                .len()
                .checked_sub(pad)
                .ok_or_else(|| RpcError::Client("bad pad".into()))?;
            Ok(plain[..end].to_vec())
        } else {
            let end = payload
                .len()
                .checked_sub(pad)
                .ok_or_else(|| RpcError::Client("bad pad".into()))?;
            Ok(payload[..end].to_vec())
        }
    }

    async fn send(&mut self, pdu: &[u8]) -> RpcResult<()> {
        self.stream
            .write_all(pdu)
            .await
            .map_err(|e| RpcError::Client(format!("send: {e}")))
    }

    /// Read one PDU: the 16-byte common header, then `frag_length - 16` body bytes.
    async fn recv(&mut self) -> RpcResult<(CommonHeader, Vec<u8>)> {
        let mut head = [0u8; HEADER_LEN];
        self.read_exact(&mut head).await?;
        let header = CommonHeader::parse(&head)?;
        let frag_length = u16::from_le_bytes([head[8], head[9]]) as usize;
        let body_len = frag_length.saturating_sub(HEADER_LEN);
        let mut body = vec![0u8; body_len];
        self.read_exact(&mut body).await?;
        Ok((header, body))
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> RpcResult<()> {
        self.stream
            .read_exact(buf)
            .await
            .map(|_| ())
            .map_err(|e| RpcError::Client(format!("recv: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::Directory;
    use crate::drsuapi::DrsuapiInterface;
    use crate::interface::RpcInterface;
    use crate::server::{serve, serve_with_kerberos};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn kerberos_authenticated_pull_over_tcp() {
        // Our own DRSUAPI server, Kerberos-protected with a shared service key.
        let mut dir = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        dir.add_user("alice", 1000, "password12").unwrap();
        dir.add_user("bob", 1001, "bobpass123").unwrap();
        // The authenticating principal (`alice`) must hold replication rights for the
        // DCSync pull to be authorized (H-3a): put her in Domain Admins.
        dir.add_group_with_members("Domain Admins", 512, vec![1000]);
        let iface: Arc<dyn RpcInterface> = Arc::new(DrsuapiInterface::new(Arc::new(dir)));
        let service_key = vec![0x11u8; 32];

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let sk = service_key.clone();
        tokio::spawn(async move {
            let _ = serve_with_kerberos(addr, iface, sk).await;
        });

        // Kerberos-authenticate the bind (AP-REQ → AP-REP → GSS subkey), then pull —
        // every request is GSS-signed (PKT_INTEGRITY).
        let mut client = None;
        for _ in 0..40 {
            if let Ok(c) = DrsClient::connect_kerberos(
                addr,
                &service_key,
                "EXAMPLE.COM",
                &["host", "magnetite"],
                &["alice"],
            )
            .await
            {
                client = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut client = client.expect("kerberos-authenticated connect");

        let changes = client
            .get_nc_changes(0, 0)
            .await
            .expect("signed GetNCChanges pull");
        assert_eq!(
            changes.objects.len(),
            3,
            "the two users AND the Domain Admins group replicate over the signed session"
        );
        assert_eq!(
            changes.objects[0].sam_account_name().as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn full_v8_request_marshals_the_server_visible_fields_and_nc_dn() {
        let req = GetNcChangesRequest {
            handle: [0u8; 20],
            dest_dsa: [1u8; 16],
            src_invocation: [2u8; 16],
            nc_dn: "DC=example,DC=com",
            nc_guid: [3u8; 16],
            from: 5,
            flags: 0x0000_0021,
            max_objects: 100,
            ext_op: 0,
            utdv: &[],
        };
        let stub = req.marshal_v8();
        // The fields a source parses at fixed offsets.
        assert_eq!(
            u32::from_le_bytes(stub[20..24].try_into().unwrap()),
            8,
            "dwInVersion"
        );
        assert_eq!(
            i64::from_le_bytes(stub[72..80].try_into().unwrap()),
            5,
            "usnvecFrom"
        );
        assert_eq!(
            u32::from_le_bytes(stub[100..104].try_into().unwrap()),
            0x21,
            "ulFlags"
        );
        assert_eq!(
            u32::from_le_bytes(stub[104..108].try_into().unwrap()),
            100,
            "cMaxObjects"
        );
        // pmsgIn + pNC referents are non-null (a real source rejects nulls).
        assert_ne!(&stub[24..28], &[0u8; 4], "pmsgIn referent non-null");
        assert_ne!(&stub[64..68], &[0u8; 4], "pNC referent non-null");
        // The naming context DN round-trips out of the deferred DSNAME.
        assert_eq!(
            parse_request_nc_dn(&stub).as_deref(),
            Some("DC=example,DC=com")
        );
        // A normal request carries ulExtendedOp = 0.
        assert_eq!(
            u32::from_le_bytes(stub[112..116].try_into().unwrap()),
            0,
            "ulExtendedOp"
        );
    }

    #[test]
    fn exop_repl_obj_targets_a_single_object_by_guid() {
        // The EXOP_REPL_OBJ form (single-object DCSync) sets ulExtendedOp = 6 and
        // carries the target objectGUID in the deferred pNC DSNAME.
        let guid = [0xABu8; 16];
        let req = GetNcChangesRequest {
            handle: [0u8; 20],
            dest_dsa: [0u8; 16],
            src_invocation: [0u8; 16],
            nc_dn: "",
            nc_guid: guid,
            from: 0,
            flags: 0x0000_0010,
            max_objects: 1,
            ext_op: 6,
            utdv: &[],
        };
        let stub = req.marshal_v8();
        assert_eq!(
            u32::from_le_bytes(stub[112..116].try_into().unwrap()),
            6,
            "ulExtendedOp = EXOP_REPL_OBJ"
        );
        assert!(
            stub.windows(16).any(|w| w == guid),
            "target objectGUID present in pNC"
        );
    }

    #[test]
    fn fsmo_roles_map_to_exop_and_object() {
        use crate::drsuapi::{exop, FsmoRole};
        let domain = "DC=magtest,DC=local";
        let config = "CN=Configuration,DC=magtest,DC=local";
        assert_eq!(FsmoRole::Schema.exop(), exop::FSMO_REQ_ROLE);
        assert_eq!(FsmoRole::DomainNaming.exop(), exop::FSMO_REQ_ROLE);
        assert_eq!(FsmoRole::Infrastructure.exop(), exop::FSMO_REQ_ROLE);
        assert_eq!(FsmoRole::RidMaster.exop(), exop::FSMO_RID_REQ_ROLE);
        assert_eq!(FsmoRole::PdcEmulator.exop(), exop::FSMO_REQ_PDC);
        assert_eq!(
            FsmoRole::Schema.object_dn(domain, config),
            "CN=Schema,CN=Configuration,DC=magtest,DC=local"
        );
        assert_eq!(
            FsmoRole::DomainNaming.object_dn(domain, config),
            "CN=Partitions,CN=Configuration,DC=magtest,DC=local"
        );
        assert_eq!(FsmoRole::PdcEmulator.object_dn(domain, config), domain);
        assert_eq!(
            FsmoRole::RidMaster.object_dn(domain, config),
            "CN=RID Manager$,CN=System,DC=magtest,DC=local"
        );
        assert_eq!(
            FsmoRole::Infrastructure.object_dn(domain, config),
            "CN=Infrastructure,DC=magtest,DC=local"
        );
    }

    #[test]
    fn fsmo_transfer_request_sets_exop_and_dest_dsa() {
        use crate::drsuapi::FsmoRole;
        // A role-transfer request names the role object and the destination nTDSDSA.
        let dest = [0x5Au8; 16];
        let req = GetNcChangesRequest {
            handle: [0u8; 20],
            dest_dsa: dest,
            src_invocation: [0u8; 16],
            nc_dn: "CN=RID Manager$,CN=System,DC=magtest,DC=local",
            nc_guid: [0u8; 16],
            from: 0,
            flags: 0x0000_0010,
            max_objects: 1,
            ext_op: FsmoRole::RidMaster.exop(),
            utdv: &[],
        };
        let stub = req.marshal_v8();
        // ulExtendedOp = FSMO_RID_REQ_ROLE (3) at offset 112; dest nTDSDSA at 32..48.
        assert_eq!(
            u32::from_le_bytes(stub[112..116].try_into().unwrap()),
            3,
            "ulExtendedOp"
        );
        assert_eq!(&stub[32..48], &dest, "uuidDsaObjDest = destination nTDSDSA");
        assert_eq!(
            parse_request_nc_dn(&stub).as_deref(),
            Some("CN=RID Manager$,CN=System,DC=magtest,DC=local")
        );
    }

    #[test]
    fn ex_op_err_maps_success_and_not_owner() {
        use crate::drsuapi::ExOpErr;
        assert!(ExOpErr::from_raw(1).is_success());
        assert_eq!(ExOpErr::from_raw(3), ExOpErr::NotOwner);
        assert_eq!(ExOpErr::from_raw(0x0C), ExOpErr::RefusingRoles);
        assert!(!ExOpErr::from_raw(5).is_success());
    }

    #[test]
    fn delta_request_carries_the_uptodate_vector() {
        // A request with a destination up-to-dateness cursor: the pUpToDateVecDest
        // referent is non-null and the deferred UPTODATE_VECTOR_V1_EXT (after the pNC
        // DSNAME) carries the cursor. Offsets/length verified byte-for-byte vs impacket.
        let dsa = [0x44u8; 16];
        let req = GetNcChangesRequest {
            handle: [0x11u8; 20],
            dest_dsa: [0x22u8; 16],
            src_invocation: [0x33u8; 16],
            nc_dn: "DC=magtest,DC=local",
            nc_guid: [0u8; 16],
            from: 0,
            flags: 0x0000_0010,
            max_objects: 100,
            ext_op: 0,
            utdv: &[(dsa, 0x1234)],
        };
        let stub = req.marshal_v8();
        assert_eq!(stub.len(), 288, "matches impacket's length");
        assert_ne!(
            &stub[96..100],
            &[0u8; 4],
            "pUpToDateVecDest referent non-null"
        );
        assert_eq!(
            u32::from_le_bytes(stub[244..248].try_into().unwrap()),
            1,
            "cursor MaxCount"
        );
        assert_eq!(
            u32::from_le_bytes(stub[248..252].try_into().unwrap()),
            1,
            "dwVersion"
        );
        assert_eq!(
            u32::from_le_bytes(stub[256..260].try_into().unwrap()),
            1,
            "cNumCursors"
        );
        assert_eq!(&stub[264..280], &dsa, "cursor uuidDsa");
        assert_eq!(
            i64::from_le_bytes(stub[280..288].try_into().unwrap()),
            0x1234,
            "usnHighPropUpdate"
        );
    }

    #[test]
    fn guid_le_encodes_drsuapi_uuid() {
        // E3514235-4B06-11D1-AB04-00C04FC2DCD2 → Data1/2/3 little-endian, Data4 as-is.
        assert_eq!(
            guid_le(DRSUAPI_UUID),
            [
                0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2,
                0xdc, 0xd2
            ]
        );
    }

    #[tokio::test]
    async fn unauthenticated_get_nc_changes_is_refused_over_tcp() {
        // A source DC (our own DRSUAPI server) with two users, served WITHOUT auth
        // configured, so a client that binds unauthenticated has no principal.
        let mut dir = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        dir.add_user("alice", 1000, "password12").unwrap();
        dir.add_user("bob", 1001, "bobpass123").unwrap();
        let iface: Arc<dyn RpcInterface> = Arc::new(DrsuapiInterface::new(Arc::new(dir)));

        // Bind an ephemeral port, release it, and serve there.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        tokio::spawn(async move {
            let _ = serve(addr, iface).await;
        });

        // Connect (retry until the server is bound) and BIND + DRSBind unauthenticated.
        let mut client = None;
        for _ in 0..40 {
            if let Ok(c) = DrsClient::connect(addr).await {
                client = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut client = client.expect("client connects to the DRS server");

        // DCSync replicates credentials, so an unauthenticated pull is REFUSED
        // (nca_s_fault_access_denied) — the H-3 guard. The authenticated wire flow and
        // reply decoding are covered by `kerberos_authenticated_pull_over_tcp`.
        assert!(
            client.get_nc_changes(0, 0).await.is_err(),
            "an unauthenticated GetNCChanges (DCSync) must be refused"
        );
    }
}
