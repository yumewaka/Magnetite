//! `magnetite-watch` — the embedded monitoring collector (09b §-1). Unlike the
//! other embedded servers this one binds no socket: it periodically probes each
//! monitored host's TCP reachability, records `reachable`/`latency_ms` metrics,
//! refreshes host status, and evaluates monitor rules to raise alerts (via the
//! shared S-Alerts `raise_alert` seam), suppressing hosts under maintenance.
//!
//! Reachability probing is real (a TCP connect with latency). CPU/memory/disk
//! and other agent-sourced metrics still arrive out-of-band; the rule engine
//! evaluates whatever has been recorded (higher-is-worse thresholds). Deferred:
//! SSH/SNMP collection, metric retention/pruning, alert auto-resolution on
//! recovery, and notification delivery.

mod collector;
pub mod service;

pub use service::WatchService;
