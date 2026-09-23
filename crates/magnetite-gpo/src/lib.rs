//! `magnetite-gpo` — Group Policy Object provisioning.
//!
//! A GPO has two consistent halves: the **GPT** (Group Policy Template) files on
//! SYSVOL (`GPT.INI` carrying a version, `Machine/Registry.pol` and
//! `User/Registry.pol` in the MS-GPREG binary format) and the **GPC** (Group
//! Policy Container) LDAP object (`groupPolicyContainer` with `gPCFileSysPath`
//! pointing at the GPT and a matching `versionNumber`). [`provision`] emits both
//! from one [`GpoSpec`], keeping the GUID and version in lock-step — exactly what
//! a domain member correlates when it discovers a GPO in LDAP and fetches its
//! policy over SMB.

#![forbid(unsafe_code)]

/// A registry policy value.
pub enum RegValue {
    /// `REG_DWORD` (a 32-bit number).
    Dword(u32),
    /// `REG_SZ` (a string).
    Sz(String),
}

impl RegValue {
    /// The `REG_*` type code and the little-endian data bytes (MS-DTYP).
    fn encode(&self) -> (u32, Vec<u8>) {
        match self {
            RegValue::Dword(v) => (4, v.to_le_bytes().to_vec()), // REG_DWORD
            RegValue::Sz(s) => (1, utf16z(s)),                   // REG_SZ (NUL-terminated)
        }
    }
}

/// One registry policy entry (a value under a key).
pub struct RegistrySetting {
    pub key: String,
    pub value: String,
    pub data: RegValue,
}

/// A request to provision a GPO.
pub struct GpoSpec {
    /// The policy's display name.
    pub display_name: String,
    /// The GPO GUID (`{....}`).
    pub guid: String,
    /// The AD domain (e.g. `example.com`).
    pub domain: String,
    /// Machine-side registry policy entries.
    pub machine_settings: Vec<RegistrySetting>,
}

/// A provisioned GPO: the GPT files and the GPC LDAP attributes.
pub struct ProvisionedGpo {
    pub guid: String,
    /// The combined version (machine in the high word, user in the low word).
    pub version: u32,
    /// `GPT.INI` contents.
    pub gpt_ini: String,
    /// The machine `Registry.pol` (MS-GPREG).
    pub registry_pol: Vec<u8>,
    /// The `groupPolicyContainer` LDAP attributes (name, value), objectClass
    /// repeated. Ready to seed into the directory.
    pub gpc_attributes: Vec<(String, String)>,
    /// SYSVOL files as `(path-under-share, bytes)`, `\`-separated relative to the
    /// SysVol share root (e.g. `example.com\Policies\{GUID}\GPT.INI`).
    pub sysvol_files: Vec<(String, Vec<u8>)>,
}

/// UTF-16LE bytes of `s`.
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
/// UTF-16LE bytes of `s` with a terminating NUL.
fn utf16z(s: &str) -> Vec<u8> {
    let mut v = utf16(s);
    v.extend_from_slice(&[0, 0]);
    v
}

/// Encode machine `Registry.pol` bytes (MS-GPREG §2.2.1): `PReg` + version 1,
/// then `[ Key ; Value ; Type ; Size ; Data ]` per entry, where the brackets and
/// semicolons are literal UTF-16LE characters.
pub fn registry_pol(settings: &[RegistrySetting]) -> Vec<u8> {
    let mut out = b"PReg".to_vec();
    out.extend_from_slice(&1u32.to_le_bytes()); // Version

    for s in settings {
        let (reg_type, data) = s.data.encode();
        out.extend_from_slice(&utf16("[")); // 5B 00
        out.extend_from_slice(&utf16z(&s.key));
        out.extend_from_slice(&utf16(";"));
        out.extend_from_slice(&utf16z(&s.value));
        out.extend_from_slice(&utf16(";"));
        out.extend_from_slice(&reg_type.to_le_bytes());
        out.extend_from_slice(&utf16(";"));
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&utf16(";"));
        out.extend_from_slice(&data);
        out.extend_from_slice(&utf16("]")); // 5D 00
    }
    out
}

/// Provision a GPO from `spec`.
pub fn provision(spec: &GpoSpec) -> ProvisionedGpo {
    // A freshly provisioned GPO with machine settings starts at machine version 1
    // (high word); no user settings ⇒ user version 0 (low word).
    let machine_version: u32 = 1;
    let version = machine_version << 16;

    let gpt_ini = format!(
        "[General]\r\nVersion={version}\r\ndisplayName={}\r\n",
        spec.display_name
    );
    let machine_pol = registry_pol(&spec.machine_settings);
    let empty_pol = registry_pol(&[]);

    let policies = format!("{}\\Policies\\{}", spec.domain, spec.guid);
    let sysvol_files = vec![
        (format!("{policies}\\GPT.INI"), gpt_ini.clone().into_bytes()),
        (
            format!("{policies}\\Machine\\Registry.pol"),
            machine_pol.clone(),
        ),
        (format!("{policies}\\User\\Registry.pol"), empty_pol),
    ];

    let gpc_path = format!(
        "\\\\{}\\SysVol\\{}\\Policies\\{}",
        spec.domain, spec.domain, spec.guid
    );
    let gpc_attributes = vec![
        ("objectClass".into(), "top".into()),
        ("objectClass".into(), "container".into()),
        ("objectClass".into(), "groupPolicyContainer".into()),
        ("cn".into(), spec.guid.clone()),
        ("displayName".into(), spec.display_name.clone()),
        ("gPCFileSysPath".into(), gpc_path),
        ("gPCFunctionalityVersion".into(), "2".into()),
        ("versionNumber".into(), version.to_string()),
        ("flags".into(), "0".into()),
        // The Registry client-side + tool extension GUIDs (well-known).
        (
            "gPCMachineExtensionNames".into(),
            "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]".into(),
        ),
    ];

    ProvisionedGpo {
        guid: spec.guid.clone(),
        version,
        gpt_ini,
        registry_pol: machine_pol,
        gpc_attributes,
        sysvol_files,
    }
}

/// The Default Domain Policy for `example.com`: a couple of machine registry
/// settings under the well-known GUID.
pub fn default_domain_policy() -> ProvisionedGpo {
    provision(&GpoSpec {
        display_name: "Magnetite Default Domain Policy".into(),
        guid: "{31B2F340-016D-11D2-945F-00C04FB984F9}".into(),
        domain: "example.com".into(),
        machine_settings: vec![
            RegistrySetting {
                key: "Software\\Policies\\Microsoft\\Windows\\System".into(),
                value: "EnableSmartScreen".into(),
                data: RegValue::Dword(1),
            },
            RegistrySetting {
                key: "Software\\Policies\\Microsoft\\Windows\\Personalization".into(),
                value: "NoLockScreen".into(),
                data: RegValue::Dword(1),
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spec-faithful Registry.pol parser used only for the round-trip test.
    fn parse_registry_pol(bytes: &[u8]) -> Vec<(String, String, u32)> {
        assert_eq!(&bytes[0..4], b"PReg");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
        let mut entries = Vec::new();
        let mut i = 8;
        let read_wchar = |b: &[u8], p: usize| u16::from_le_bytes([b[p], b[p + 1]]);
        let read_str = |b: &[u8], p: &mut usize| -> String {
            let mut s = String::new();
            loop {
                let c = read_wchar(b, *p);
                *p += 2;
                if c == 0 {
                    break;
                }
                s.push(char::from_u32(c as u32).unwrap());
            }
            s
        };
        while i < bytes.len() {
            assert_eq!(read_wchar(bytes, i), '[' as u16);
            i += 2;
            let key = read_str(bytes, &mut i);
            assert_eq!(read_wchar(bytes, i), ';' as u16);
            i += 2;
            let value = read_str(bytes, &mut i);
            assert_eq!(read_wchar(bytes, i), ';' as u16);
            i += 2;
            let reg_type = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
            i += 4;
            assert_eq!(read_wchar(bytes, i), ';' as u16);
            i += 2;
            let size = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            assert_eq!(read_wchar(bytes, i), ';' as u16);
            i += 2;
            i += size; // skip data
            assert_eq!(read_wchar(bytes, i), ']' as u16);
            i += 2;
            entries.push((key, value, reg_type));
        }
        entries
    }

    #[test]
    fn registry_pol_round_trips() {
        let gpo = default_domain_policy();
        let entries = parse_registry_pol(&gpo.registry_pol);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1, "EnableSmartScreen");
        assert_eq!(entries[0].2, 4); // REG_DWORD
        assert_eq!(entries[1].1, "NoLockScreen");
    }

    #[test]
    fn gpt_ini_and_gpc_version_agree() {
        let gpo = default_domain_policy();
        assert!(gpo.gpt_ini.contains(&format!("Version={}", gpo.version)));
        let version_attr = gpo
            .gpc_attributes
            .iter()
            .find(|(k, _)| k == "versionNumber")
            .unwrap();
        assert_eq!(version_attr.1, gpo.version.to_string());
        // gPCFileSysPath references the same GUID.
        let path = gpo
            .gpc_attributes
            .iter()
            .find(|(k, _)| k == "gPCFileSysPath")
            .unwrap();
        assert!(path.1.contains(&gpo.guid));
    }

    #[test]
    fn sysvol_layout_has_gpt_and_registry_pol() {
        let gpo = default_domain_policy();
        let paths: Vec<&str> = gpo.sysvol_files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("GPT.INI")));
        assert!(paths.iter().any(|p| p.ends_with("Machine\\Registry.pol")));
        assert!(paths.iter().any(|p| p.ends_with("User\\Registry.pol")));
    }
}
