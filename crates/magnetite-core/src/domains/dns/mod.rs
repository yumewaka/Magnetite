//! DNS domain: data model (07_data_dns) and write-time validation
//! (08_dns_logic §5). Both are pure and shared by the UI and the DB layer.

pub mod model;
pub mod validate;

pub use model::{Record, RecordType, RpzAction, RpzRule, Soa, Zone};
