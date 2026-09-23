//! DHCP management screens (S-DHCP). Dashboard, pools, reservations, leases and
//! config. The DHCP audit view (S-DHCP-06) is served by the cross-cutting audit
//! screen and is added with that feature.

pub mod config;
pub mod dashboard;
pub mod leases;
pub mod nav;
pub mod pools;
pub mod reservations;

pub use config::ConfigPage;
pub use dashboard::DhcpDashboard;
pub use leases::LeasesPage;
pub use pools::PoolsPage;
pub use reservations::ReservationsPage;
