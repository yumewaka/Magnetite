//! Watch (monitoring) domain: data model (07_data_watch) and write-time
//! validation (screen_watch §3/§5). Pure and shared by the UI and DB.

pub mod model;
pub mod validate;

pub use model::{
    HostGroup, MaintenanceStatus, MaintenanceWindow, Metric, MonitorRule, MonitoredHost,
};
