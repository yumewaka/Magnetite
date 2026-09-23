//! Top header (S-00 §0 / 10 §1.1): alert badge, language & theme toggles and
//! the user menu with logout.

use crate::components::theme::ThemeToggle;
use crate::server_fns::auth::Logout;
use leptos::prelude::*;
use leptos_router::components::A;
use magnetite_core::i18n::use_i18n;
use magnetite_core::models::CurrentUser;

#[component]
pub fn Header(user: CurrentUser, open_alert_count: u32) -> impl IntoView {
    let i18n = use_i18n();
    let logout = ServerAction::<Logout>::new();

    let toggle_lang = move |_| i18n.locale.update(|l| *l = l.toggle());
    let role_key = user.role.label_key();
    let display_name = user.display_name.clone();
    let has_alerts = open_alert_count > 0;

    view! {
        <header class="app-header">
            <div class="header-left"></div>
            <div class="header-right">
                <A href="/alerts" attr:class="icon-button alert-bell" attr:aria-label="alerts">
                    <span>{"\u{1F514}"}</span>
                    <Show when=move || has_alerts fallback=|| ()>
                        <span class="alert-badge">{open_alert_count}</span>
                    </Show>
                </A>
                <button
                    class="icon-button"
                    title=move || i18n.t("lang.toggle")
                    on:click=toggle_lang
                >
                    {move || i18n.locale.get().toggle().label()}
                </button>
                <ThemeToggle/>
                <div class="user-menu">
                    <span class="user-name">{display_name}</span>
                    <span class="user-role">{move || i18n.t(role_key)}</span>
                    <ActionForm action=logout>
                        <button class="btn btn-secondary btn-sm" type="submit">
                            {move || i18n.t("action.logout")}
                        </button>
                    </ActionForm>
                </div>
            </div>
        </header>
    }
}
