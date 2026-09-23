//! DNS management screens (S-DNS): dashboard, zones, records, RPZ, and — backed
//! by the embedded DNS server — query-test (AC-13) and query-logs. Templates and
//! backup are handled by the cross-cutting Template/S-Backup features.

pub mod dashboard;
pub mod ddns;
pub mod dnssec;
pub mod forwarders;
pub mod geo;
pub mod nav;
pub mod query_logs;
pub mod query_test;
pub mod records;
pub mod replication;
pub mod rpz;
pub mod zones;

pub use dashboard::DnsDashboard;
pub use ddns::DdnsPage;
pub use dnssec::DnssecPage;
pub use forwarders::ForwardersPage;
pub use geo::GeoPage;
pub use query_logs::QueryLogsPage;
pub use query_test::QueryTestPage;
pub use records::RecordsPage;
pub use replication::ReplicationPage;
pub use rpz::RpzPage;
pub use zones::ZonesPage;
