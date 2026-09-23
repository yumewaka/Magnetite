//! Mail sub-navigation (screen_mail §6).

use leptos::prelude::*;
use leptos_router::components::A;

/// Horizontal tab bar linking the Mail sub-screens.
#[component]
pub fn MailNav() -> impl IntoView {
    let links = [
        ("/mail", "ダッシュボード"),
        ("/mail/users", "ユーザ"),
        ("/mail/domains", "ドメイン"),
        ("/mail/aliases", "エイリアス"),
        ("/mail/mailing-lists", "メーリングリスト"),
        ("/mail/messages", "受信箱"),
        ("/mail/protocols", "プロトコル"),
        ("/mail/dkim", "DKIM"),
        ("/mail/backup-mx", "バックアップMX"),
        ("/mail/replication", "レプリケーション"),
        ("/mail/relay", "SMTPリレー"),
        ("/mail/settings", "サーバ設定"),
    ];
    view! {
        <nav class="sub-nav" aria-label="Mail">
            {links
                .into_iter()
                .map(|(href, label)| view! {
                    <A href=href attr:class="sub-nav-link" exact=true>{label}</A>
                })
                .collect_view()}
        </nav>
    }
}
