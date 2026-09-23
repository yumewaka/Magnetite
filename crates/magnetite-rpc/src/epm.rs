//! The RPC Endpoint Mapper (MS-RPCE / DCE 1.1 `ept`) on port 135 — how a Windows
//! client discovers the dynamic TCP port of an RPC service (DRSUAPI, SAMR, …)
//! before connecting. It is itself a connection-oriented RPC interface (UUID
//! `e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0) served over the same transport.
//!
//! Only `ept_map` (opnum 3) is implemented: the client sends a *map tower*
//! describing the interface it wants over `ncacn_ip_tcp`; the mapper reads the
//! interface UUID from the tower's first floor, looks it up in its registration
//! table, and returns a tower whose port floor holds the service's real port.
//!
//! Wire formats (both confirmed against impacket `epm`): a **protocol tower** is
//! `num_floors(u16 LE)` then floors of `lhs_len(u16) ‖ lhs ‖ rhs_len(u16) ‖ rhs`
//! (interface/data-representation floors use identifier `0x0d`; the RPC floor
//! `0x0b`; the TCP-port floor `0x07` with the port **big-endian**; the host floor
//! `0x09` with the IPv4 address). `ept_map` marshals the tower as a `twr_t`
//! (`tower_length ‖ octet-string`) behind a referent pointer.

use crate::interface::RpcInterface;
use crate::ndr::{NdrReader, NdrWriter};
use crate::request::fault;

/// The Endpoint Mapper interface UUID (`e1af8308-5d1f-11c9-91a4-08002b14a0fa`).
pub const EPM_UUID: &str = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";

const OP_EPT_MAP: u16 = 3;

/// `EPT_S_NOT_REGISTERED` — no endpoint is registered for the requested interface.
const EPT_S_NOT_REGISTERED: u32 = 0x16c9_a0d6;

/// Tower floor identifiers (DCE 1.1 / MS-RPCE §2.2.1.2.5).
const FLOOR_UUID: u8 = 0x0d;
const FLOOR_RPC_CO: u8 = 0x0b;
const FLOOR_TCP_PORT: u8 = 0x07;
const FLOOR_IP_HOST: u8 = 0x09;

/// The NDR transfer-syntax UUID (`8a885d04-1ceb-11c9-9fe8-08002b104860`) as the
/// 16 GUID bytes that appear in a tower's data-representation floor.
const NDR_TRANSFER_SYNTAX: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

/// One registered endpoint: an interface (by its GUID bytes + major version) and
/// the TCP port it listens on.
#[derive(Clone, Copy)]
pub struct Registration {
    /// The interface UUID as 16 GUID bytes (little-endian mixed, tower order).
    pub uuid: [u8; 16],
    /// The interface's major version (echoed in the returned tower).
    pub major_version: u16,
    /// The TCP port the interface's `ncacn_ip_tcp` endpoint listens on.
    pub port: u16,
}

/// The Endpoint Mapper: resolves interface UUIDs to their registered TCP ports and
/// returns a tower a client can connect with.
pub struct EpmInterface {
    registrations: Vec<Registration>,
    /// The DC's IPv4 address returned in the tower's host floor.
    dc_ipv4: [u8; 4],
}

impl EpmInterface {
    /// A mapper over `registrations`, returning `dc_ipv4` as the endpoint host.
    #[must_use]
    pub fn new(registrations: Vec<Registration>, dc_ipv4: [u8; 4]) -> Self {
        Self {
            registrations,
            dc_ipv4,
        }
    }

    fn lookup(&self, uuid: &[u8; 16]) -> Option<Registration> {
        self.registrations.iter().find(|r| &r.uuid == uuid).copied()
    }

    /// Handle `ept_map` (opnum 3): resolve the requested interface to a tower.
    fn ept_map(&self, stub: &[u8]) -> Result<Vec<u8>, u32> {
        let tower = parse_request_tower(stub).ok_or(fault::NDR)?;
        let found = tower_interface_uuid(&tower).and_then(|u| self.lookup(&u));

        let mut w = NdrWriter::new();
        // entry_handle (ept_lookup_handle_t): a null context handle ends the lookup.
        w.bytes(&[0u8; 20]);
        match found {
            Some(reg) => {
                let reply_tower = build_tower(&reg.uuid, reg.major_version, reg.port, self.dc_ipv4);
                w.u32(1); // num_towers
                          // ITowers: a conformant+varying array of one twr_p_t.
                w.u32(1); // MaxCount
                w.u32(0); // Offset
                w.u32(1); // ActualCount
                w.u32(0x0002_0000); // referent id for towers[0]
                                    // Deferred twr_t: conformant MaxCount, tower_length, octet string.
                w.u32(reply_tower.len() as u32);
                w.u32(reply_tower.len() as u32);
                w.bytes(&reply_tower);
                w.align(4);
                w.u32(0); // status = success
            }
            None => {
                w.u32(0); // num_towers
                w.u32(0); // MaxCount
                w.u32(0); // Offset
                w.u32(0); // ActualCount
                w.u32(EPT_S_NOT_REGISTERED);
            }
        }
        Ok(w.into_bytes())
    }
}

impl RpcInterface for EpmInterface {
    fn call(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, u32> {
        match opnum {
            OP_EPT_MAP => self.ept_map(stub),
            _ => Err(fault::OP_RNG_ERROR),
        }
    }
}

/// Extract the `map_tower` octet string from an `ept_map` request stub: skip the
/// object UUID pointer, then read the tower behind its referent pointer.
fn parse_request_tower(stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    // obj: PUUID — a referent id, then (if non-null) the 16-byte object UUID.
    if r.u32()? != 0 {
        r.take(16)?;
    }
    // map_tower: twr_p_t — referent id, then twr_t { MaxCount, tower_length, bytes }.
    let _tower_ref = r.u32()?;
    let _max_count = r.u32()?;
    let tower_len = r.u32()? as usize;
    Some(r.take(tower_len)?.to_vec())
}

/// Read the interface UUID from a tower's first (interface-identifier) floor.
fn tower_interface_uuid(tower: &[u8]) -> Option<[u8; 16]> {
    // num_floors(2) ‖ floor1{ lhs_len(2), ident(1)=0x0d, uuid(16), major(2), … }.
    if tower.len() < 21 {
        return None;
    }
    let lhs_len = u16::from_le_bytes([tower[2], tower[3]]);
    if lhs_len < 17 || tower[4] != FLOOR_UUID {
        return None;
    }
    tower[5..21].try_into().ok()
}

/// Build a 5-floor `ncacn_ip_tcp` tower for `iface_uuid` v`major` at `port`/`ip`.
fn build_tower(iface_uuid: &[u8; 16], major: u16, port: u16, ip: [u8; 4]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&5u16.to_le_bytes()); // number of floors
    push_uuid_floor(&mut t, iface_uuid, major); // 1: interface
    push_uuid_floor(&mut t, &NDR_TRANSFER_SYNTAX, 2); // 2: NDR data representation
                                                      // 3: RPC connection-oriented protocol.
    t.extend_from_slice(&1u16.to_le_bytes());
    t.push(FLOOR_RPC_CO);
    t.extend_from_slice(&2u16.to_le_bytes());
    t.extend_from_slice(&0u16.to_le_bytes());
    // 4: TCP port (the port is big-endian in the tower).
    t.extend_from_slice(&1u16.to_le_bytes());
    t.push(FLOOR_TCP_PORT);
    t.extend_from_slice(&2u16.to_le_bytes());
    t.extend_from_slice(&port.to_be_bytes());
    // 5: IPv4 host address.
    t.extend_from_slice(&1u16.to_le_bytes());
    t.push(FLOOR_IP_HOST);
    t.extend_from_slice(&4u16.to_le_bytes());
    t.extend_from_slice(&ip);
    t
}

/// Append a UUID floor: `lhs = 0x0d ‖ uuid(16) ‖ major(2)`, `rhs = minor(2)=0`.
fn push_uuid_floor(t: &mut Vec<u8>, uuid: &[u8; 16], major: u16) {
    t.extend_from_slice(&19u16.to_le_bytes()); // lhs_len = 1 + 16 + 2
    t.push(FLOOR_UUID);
    t.extend_from_slice(uuid);
    t.extend_from_slice(&major.to_le_bytes());
    t.extend_from_slice(&2u16.to_le_bytes()); // rhs_len = 2
    t.extend_from_slice(&0u16.to_le_bytes()); // minor version
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DRSUAPI interface UUID as tower GUID bytes (`E3514235-4B06-11D1-…`).
    const DRSUAPI_UUID: [u8; 16] = [
        0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc,
        0xd2,
    ];

    fn drsuapi_reg(port: u16) -> Registration {
        Registration {
            uuid: DRSUAPI_UUID,
            major_version: 4,
            port,
        }
    }

    #[test]
    fn tower_round_trips_interface_uuid_and_port() {
        let tower = build_tower(&DRSUAPI_UUID, 4, 1027, [127, 0, 0, 1]);
        // Five floors, interface UUID recoverable from floor 1.
        assert_eq!(&tower[0..2], &5u16.to_le_bytes());
        assert_eq!(tower_interface_uuid(&tower), Some(DRSUAPI_UUID));
        // The TCP-port floor is `id(0x07) ‖ rhs_len(2) ‖ port(2 big-endian)`.
        assert!(
            tower
                .windows(5)
                .any(|w| w == [FLOOR_TCP_PORT, 0x02, 0x00, 0x04, 0x03]),
            "port 1027 = 0x0403 big-endian in the TCP floor"
        );
    }

    #[test]
    fn ept_map_resolves_a_registered_interface() {
        let epm = EpmInterface::new(vec![drsuapi_reg(1027)], [127, 0, 0, 1]);
        // A minimal ept_map request: null obj, a map_tower asking for DRSUAPI.
        let request_tower = build_tower(&DRSUAPI_UUID, 4, 0, [0, 0, 0, 0]);
        let stub = ept_map_request(&request_tower);

        let resp = epm.call(OP_EPT_MAP, &stub).expect("ept_map");
        // entry_handle(20) ‖ num_towers=1 ‖ array header ‖ referent ‖ twr_t.
        assert_eq!(&resp[20..24], &1u32.to_le_bytes(), "one tower returned");
        // The returned tower resolves DRSUAPI to port 1027 (0x0403 big-endian).
        assert!(
            resp.windows(5)
                .any(|w| w == [FLOOR_TCP_PORT, 0x02, 0x00, 0x04, 0x03]),
            "resolved tower carries port 1027"
        );
        // Trailing status is success.
        assert_eq!(&resp[resp.len() - 4..], &0u32.to_le_bytes());
    }

    #[test]
    fn ept_map_reports_unregistered_interface() {
        let epm = EpmInterface::new(vec![drsuapi_reg(1027)], [127, 0, 0, 1]);
        let unknown = [0xaau8; 16];
        let stub = ept_map_request(&build_tower(&unknown, 1, 0, [0, 0, 0, 0]));
        let resp = epm.call(OP_EPT_MAP, &stub).unwrap();
        assert_eq!(&resp[20..24], &0u32.to_le_bytes(), "no towers");
        assert_eq!(
            &resp[resp.len() - 4..],
            &EPT_S_NOT_REGISTERED.to_le_bytes(),
            "status = EPT_S_NOT_REGISTERED"
        );
    }

    /// Marshal a minimal `ept_map` request stub around `tower` (null object UUID).
    fn ept_map_request(tower: &[u8]) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.u32(0); // obj: null referent
        w.u32(0x0002_0000); // map_tower referent id
        w.u32(tower.len() as u32); // MaxCount
        w.u32(tower.len() as u32); // tower_length
        w.bytes(tower);
        w.align(4);
        w.bytes(&[0u8; 20]); // entry_handle (null)
        w.u32(1); // max_towers
        w.into_bytes()
    }
}
