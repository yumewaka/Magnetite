//! Proxy domain: data model (07_data_proxy) and write-time validation
//! (screen_proxy §5). Pure and shared by the UI and the DB layer.

pub mod model;
pub mod validate;

pub use model::{
    AclAction, AclRule, AclScope, CertStatus, Certificate, ForwardRule, ForwardRuleKind,
    ForwardUser, IpBlock, LbStrategy, ProxyMode, Upstream, UpstreamScheme, VirtualHost,
};
