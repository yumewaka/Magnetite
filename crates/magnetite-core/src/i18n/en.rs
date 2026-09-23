//! English dictionary. Keep keys in sync with [`super::ja`] (the canonical
//! source); `super::tests::ja_and_en_cover_the_same_keys` enforces it.

macro_rules! dict {
    ($($key:literal => $value:literal),* $(,)?) => {
        /// All keys defined in this dictionary.
        pub const KEYS: &[&str] = &[$($key),*];

        /// Look up a translation for `key`.
        pub fn lookup(key: &str) -> Option<&'static str> {
            match key {
                $($key => Some($value),)*
                _ => None,
            }
        }
    };
}

dict! {
    "app.title" => "Magnetite",
    "app.tagline" => "Integrated service platform",

    // Sidebar groups and cross-cutting nav
    "nav.group.cross" => "Cross-cutting",
    "nav.group.domains" => "Domains",
    "nav.group.admin" => "Administration",
    "nav.dashboard" => "Dashboard",
    "nav.audit" => "Audit log",
    "nav.alerts" => "Alerts",
    "nav.backup" => "Backups",
    "nav.logs" => "Logs",
    "nav.settings" => "Settings",
    "nav.account" => "Account",

    // Domains
    "domain.dns" => "DNS",
    "domain.dhcp" => "DHCP",
    "domain.ldap" => "LDAP",
    "domain.mail" => "Mail",
    "domain.proxy" => "Proxy",
    "domain.k8s" => "Container / K8s",
    "domain.sso" => "SSO",
    "domain.watch" => "Watch",
    "domain.addc" => "AD Domain",
    "domain.portal" => "Portal",

    // Roles
    "rbac.viewer" => "Viewer",
    "rbac.operator" => "Operator",
    "rbac.admin" => "Admin",

    // Actions
    "action.add" => "Add",
    "action.edit" => "Edit",
    "action.delete" => "Delete",
    "action.save" => "Save",
    "action.cancel" => "Cancel",
    "action.retry" => "Retry",
    "action.search" => "Search",
    "action.confirm" => "Confirm",
    "action.close" => "Close",
    "action.login" => "Log in",
    "action.logout" => "Log out",

    // Generic states
    "state.empty" => "No data.",
    "state.loading" => "Loading…",
    "state.error" => "Failed to load data.",
    "state.forbidden" => "You do not have permission to perform this operation.",

    // Pagination / counts
    "common.count" => "Count",
    "common.page" => "Page",
    "common.of" => "/",
    "common.prev" => "Prev",
    "common.next" => "Next",

    // Toasts
    "toast.saved" => "Saved.",
    "toast.deleted" => "Deleted.",

    // Confirm dialog
    "confirm.delete.title" => "Confirm deletion",
    "confirm.delete.body" => "This item will be deleted. Are you sure?",

    // Errors (mirror CoreError)
    "error.forbidden" => "You do not have permission to perform this operation.",
    "error.unauthenticated" => "Authentication is required.",
    "error.validation" => "Please check your input.",
    "error.referenced" => "Cannot delete: it is referenced by other settings.",
    "error.duplicate" => "An item with the same name already exists.",
    "error.not_found" => "The target was not found.",
    "error.backend" => "An error occurred while processing the request.",

    // Login
    "login.title" => "Log in",
    "login.username" => "Username",
    "login.password" => "Password",
    "login.submit" => "Log in",
    "login.sso" => "Log in with SSO",
    "login.error" => "Incorrect username or password.",

    // First-run setup
    "setup.title" => "Initial setup",
    "setup.desc" => "Create the first administrator account.",
    "setup.username" => "Admin username",
    "setup.password" => "Password",
    "setup.password_confirm" => "Password (confirm)",
    "setup.submit" => "Create admin",
    "setup.password_policy" => "Password must be at least 8 characters and include letters and digits.",
    "setup.error.mismatch" => "Passwords do not match.",
    "setup.error.policy" => "Password must be at least 8 characters and include letters and digits.",

    // Dashboard
    "dashboard.title" => "Integrated dashboard",
    "dashboard.subtitle" => "Status across all domains",
    "dashboard.refresh" => "Refresh",

    // Theme / language
    "theme.light" => "Light",
    "theme.dark" => "Dark",
    "theme.toggle" => "Toggle theme",
    "lang.toggle" => "Toggle language",

    // Health states
    "health.healthy" => "Healthy",
    "health.warning" => "Warning",
    "health.error" => "Error",
    "health.unknown" => "Unknown",
    "health.disabled" => "Not configured",

    // Alert states
    "alert.open" => "Open",
    "alert.acknowledged" => "Acknowledged",
    "alert.resolved" => "Resolved",
    "alert.suppressed" => "In maintenance",

    // User menu
    "user.menu" => "User menu",
    "user.role" => "Role",
}
