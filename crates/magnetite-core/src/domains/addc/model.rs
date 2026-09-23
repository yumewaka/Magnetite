//! AD DC control-plane DTOs shared between the web layer and the store — the
//! browser-safe projections used by the AD DC management server functions (GPO,
//! logon scripts, domain join/leave). No secret/key material is ever carried here.

use serde::{Deserialize, Serialize};

/// A Group Policy Object, as listed/managed from the web UI. `guid` is the braced
/// `{....}` form; `gpc_path` is the `gPCFileSysPath` a member reads to fetch the GPT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpoSummary {
    /// The GPO GUID in braced form, e.g. `{31B2F340-016D-11D2-945F-00C04FB984F9}`.
    pub guid: String,
    /// The policy's display name.
    pub display_name: String,
    /// The GPO version number (machine in the high word, user in the low word).
    pub version: u32,
    /// `gPCFileSysPath` — the SYSVOL UNC path holding this GPO's GPT files.
    pub gpc_path: String,
}

/// The registry data type of a machine-side GPO setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpoRegKind {
    /// `REG_DWORD` — a 32-bit number (`data` parsed as a decimal `u32`).
    Dword,
    /// `REG_SZ` — a string (`data` used verbatim).
    Sz,
}

/// A logon script served over the NETLOGON share, referenced by a user's
/// `scriptPath`. Stored in the replicated SYSVOL store under `<domain>\scripts\`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogonScript {
    /// The script file name (e.g. `logon.bat`), the value a user's `scriptPath`
    /// carries. No path separators.
    pub name: String,
    /// The script size in bytes.
    pub size: u64,
}

/// One FSMO (operations-master) role and its current holder, for the Web view. The
/// `role` key is stable (`schema`/`domain_naming`/`rid`/`infrastructure`/`pdc`); the
/// `owner` is the holder's `nTDSDSA` DN as recorded in `fSMORoleOwner`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsmoRoleInfo {
    pub role: String,
    /// Human-readable role name.
    pub label: String,
    /// The current owner's `nTDSDSA` DN, if the role object exists.
    pub owner: Option<String>,
    /// Whether this magnetite DC currently holds the role.
    pub held_locally: bool,
}

/// One machine-side registry policy setting to provision into a GPO. Mirrors the
/// `magnetite-gpo` registry model but with a browser-safe string `data`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpoSettingInput {
    /// The registry key path (e.g. `Software\Policies\Microsoft\Windows\…`).
    pub key: String,
    /// The value name under the key.
    pub value_name: String,
    /// The value's registry type.
    pub kind: GpoRegKind,
    /// The value data: a decimal string for `Dword`, or the literal string for `Sz`.
    pub data: String,
}
