//! LDAP sub-navigation (screen_ldap §6).

use leptos::prelude::*;
use leptos_router::components::A;

/// Horizontal tab bar linking the LDAP sub-screens.
#[component]
pub fn LdapNav() -> impl IntoView {
    let links = [
        ("/ldap", "ダッシュボード"),
        ("/ldap/tree", "ツリー"),
        ("/ldap/users", "ユーザ"),
        ("/ldap/groups", "グループ"),
        ("/ldap/computers", "コンピュータ"),
        ("/ldap/ous", "OU"),
        ("/ldap/acl", "アクセス制御"),
        ("/ldap/replication", "レプリケーション"),
    ];
    view! {
        <nav class="sub-nav" aria-label="LDAP">
            {links
                .into_iter()
                .map(|(href, label)| view! {
                    <A href=href attr:class="sub-nav-link" exact=true>{label}</A>
                })
                .collect_view()}
        </nav>
    }
}
