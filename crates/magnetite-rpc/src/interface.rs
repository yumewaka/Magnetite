//! The RPC interface abstraction and a demo interface used to exercise the
//! transport. A real DC would implement Netlogon/SAMR/LSA here; the machinery
//! (BIND, opnum dispatch, NDR stub in/out) is identical.

use crate::request::fault;

/// An RPC interface: a set of operations dispatched by opnum. The stub bytes are
/// the NDR-marshalled `[in]` arguments; the returned bytes are the marshalled
/// `[out]` values. Return `Err(status)` to fault the call.
pub trait RpcInterface: Send + Sync {
    /// Handle operation `opnum` with NDR `stub` input, returning NDR output.
    fn call(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, u32>;

    /// Handle `opnum` with access to the connection's negotiated auth session key
    /// (e.g. the NTLM exported session key), when the bind was authenticated. The
    /// default ignores the key and delegates to [`RpcInterface::call`]; interfaces
    /// that encrypt results under the session key (DRSUAPI DCSync) override this.
    fn call_with_session(
        &self,
        opnum: u16,
        stub: &[u8],
        _session_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, u32> {
        self.call(opnum, stub)
    }

    /// Handle `opnum` with both the session key AND the authenticated bind's principal
    /// (`domain\user` / UPN), when known. `principal` is `Some` only when the bind was
    /// authenticated (Kerberos AP-REQ or NTLM); an unauthenticated request passes `None`.
    /// The transport ALWAYS routes requests through this, so an interface that guards a
    /// sensitive operation (DRSUAPI DCSync replicates credentials) can refuse an
    /// unauthenticated caller and record who invoked it. The default ignores the
    /// principal and delegates to [`RpcInterface::call_with_session`].
    fn call_authenticated(
        &self,
        opnum: u16,
        stub: &[u8],
        session_key: Option<&[u8]>,
        _principal: Option<&str>,
    ) -> Result<Vec<u8>, u32> {
        self.call_with_session(opnum, stub, session_key)
    }

    /// The negotiated secure-channel session key, once one is established (used
    /// by the transport to sign/verify Netlogon-authenticated calls). Interfaces
    /// without a secure channel return `None`.
    fn session_key(&self) -> Option<[u8; 16]> {
        None
    }
}

/// A minimal demo interface proving the transport end to end:
/// * opnum 0 — `Add([in] u32 a, [in] u32 b) -> [out] u32` (a + b),
/// * opnum 1 — `Echo([in] bytes) -> [out] bytes` (returns the stub unchanged).
pub struct DemoInterface;

impl RpcInterface for DemoInterface {
    fn call(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, u32> {
        match opnum {
            0 => {
                if stub.len() < 8 {
                    return Err(fault::NDR);
                }
                let a = u32::from_le_bytes(stub[0..4].try_into().unwrap());
                let b = u32::from_le_bytes(stub[4..8].try_into().unwrap());
                Ok(a.wrapping_add(b).to_le_bytes().to_vec())
            }
            1 => Ok(stub.to_vec()),
            _ => Err(fault::OP_RNG_ERROR),
        }
    }
}
