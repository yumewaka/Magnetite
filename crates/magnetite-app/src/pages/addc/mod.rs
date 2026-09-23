//! AD DC control-plane screens: the read-only dashboard (serving status + AD
//! principals) and the Group Policy (GPO) management screen.

pub mod dashboard;
pub mod domain;
pub mod fsmo;
pub mod gpo;
pub mod logon;
pub mod nav;

pub use dashboard::AddcDashboard;
pub use domain::DomainJoinPage;
pub use fsmo::FsmoPage;
pub use gpo::GpoPage;
pub use logon::LogonScriptsPage;
