//! DHCPv4 wire helpers built on `dhcproto` (the codec; Magnetite decides the
//! policy). Decoding, option extraction and OFFER/ACK/NAK construction.

use dhcproto::v4::{self, DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Decodable, Encodable};
use magnetite_core::domains::dhcp::model::{DhcpConfig, Pool};
use std::net::{Ipv4Addr, SocketAddr};

/// Decode a client BOOTREQUEST message. Returns `None` for replies / garbage.
pub fn decode(bytes: &[u8]) -> Option<Message> {
    Message::from_bytes(bytes)
        .ok()
        .filter(|m| m.opcode() == Opcode::BootRequest)
}

pub fn msg_type(msg: &Message) -> Option<MessageType> {
    msg.opts().msg_type()
}

/// Client hardware address as a lowercase colon-separated MAC.
pub fn client_mac(msg: &Message) -> String {
    let c = msg.chaddr();
    if c.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            c[0], c[1], c[2], c[3], c[4], c[5]
        )
    } else {
        "unknown".to_string()
    }
}

pub fn requested_ip(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(v4::OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    }
}

pub fn hostname(msg: &Message) -> Option<String> {
    match msg.opts().get(v4::OptionCode::Hostname) {
        Some(DhcpOption::Hostname(name)) => Some(name.clone()),
        _ => None,
    }
}

/// Where to send the reply (RFC 2131 §4.1): relay → giaddr:67, otherwise
/// broadcast, or unicast to a renewing client's ciaddr.
pub fn reply_destination(msg: &Message) -> SocketAddr {
    let giaddr = msg.giaddr();
    if giaddr != Ipv4Addr::UNSPECIFIED {
        return SocketAddr::from((giaddr, 67));
    }
    if msg.flags().broadcast() || msg.ciaddr() == Ipv4Addr::UNSPECIFIED {
        SocketAddr::from(([255, 255, 255, 255], 68))
    } else {
        SocketAddr::from((msg.ciaddr(), 68))
    }
}

/// IPv4 subnet mask derived from `pool.subnet_v4` (`a.b.c.d/prefix`).
fn subnet_mask(pool: &Pool) -> Option<Ipv4Addr> {
    let prefix: u32 = pool.subnet_v4.as_ref()?.split('/').nth(1)?.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some(Ipv4Addr::from(mask))
}

fn parse_all(values: &[String]) -> Vec<Ipv4Addr> {
    values.iter().filter_map(|s| s.parse().ok()).collect()
}

/// Build an OFFER or ACK carrying the pool's network parameters.
pub fn build_reply(
    request: &Message,
    mtype: MessageType,
    yiaddr: Ipv4Addr,
    pool: &Pool,
    config: &DhcpConfig,
    server_ip: Ipv4Addr,
    lease_secs: u32,
) -> Option<Vec<u8>> {
    let mut reply = Message::default();
    reply.set_opcode(Opcode::BootReply);
    reply.set_xid(request.xid());
    reply.set_yiaddr(yiaddr);
    reply.set_siaddr(server_ip);
    reply.set_chaddr(request.chaddr());
    reply.set_flags(request.flags());
    reply.set_giaddr(request.giaddr());

    let opts = reply.opts_mut();
    opts.insert(DhcpOption::MessageType(mtype));
    opts.insert(DhcpOption::ServerIdentifier(server_ip));
    opts.insert(DhcpOption::AddressLeaseTime(lease_secs));
    opts.insert(DhcpOption::Renewal(lease_secs / 2));
    opts.insert(DhcpOption::Rebinding(lease_secs * 7 / 8));
    if let Some(mask) = subnet_mask(pool) {
        opts.insert(DhcpOption::SubnetMask(mask));
    }
    if let Some(gw) = pool.gateway.as_ref().and_then(|g| g.parse().ok()) {
        opts.insert(DhcpOption::Router(vec![gw]));
    }
    let dns = if pool.dns_servers.is_empty() {
        parse_all(&config.default_dns_servers)
    } else {
        parse_all(&pool.dns_servers)
    };
    if !dns.is_empty() {
        opts.insert(DhcpOption::DomainNameServer(dns));
    }
    if let Some(domain) = pool
        .domain_name
        .clone()
        .or(config.default_domain_name.clone())
    {
        opts.insert(DhcpOption::DomainName(domain));
    }
    reply.to_vec().ok()
}

/// Build a DHCPNAK (request could not be satisfied).
pub fn build_nak(request: &Message, server_ip: Ipv4Addr) -> Option<Vec<u8>> {
    let mut reply = Message::default();
    reply.set_opcode(Opcode::BootReply);
    reply.set_xid(request.xid());
    reply.set_chaddr(request.chaddr());
    reply.set_flags(request.flags());
    reply.set_giaddr(request.giaddr());
    let opts = reply.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Nak));
    opts.insert(DhcpOption::ServerIdentifier(server_ip));
    reply.to_vec().ok()
}
