//! DHCP domain: data model (07_data_dhcp) and write-time validation
//! (08_dhcp_logic §5). Pure and shared by the UI and the DB layer.

pub mod model;
pub mod validate;

pub use model::{DhcpConfig, Lease, LeaseState, Pool, ProtoVer, Reservation};
