//! Authenticated shell (10 §1.1): guards authentication, then frames every
//! page with the sidebar, header and toast container.

use super::header::Header;
use super::sidebar::Sidebar;
use crate::components::theme::{use_theme, ThemeContext};
use crate::components::toast::ToastContainer;
use crate::components::ui::LoadingState;
use crate::server_fns::shell::get_shell_info;
use leptos::prelude::*;
use leptos_router::components::Outlet;
use magnetite_core::i18n::{use_i18n, I18nContext, Locale};

const PREF_LOCALE: &str = "mag.locale";
const PREF_THEME: &str = "mag.theme";

fn local_storage() -> Option<web_sys::Storage> {
    window().local_storage().ok().flatten()
}

/// Restore persisted personal settings once, then keep localStorage in sync
/// with the language/theme signals (screen_settings E-01/E-02, client-only —
/// the effect bodies never run during SSR).
fn install_pref_persistence(i18n: I18nContext, theme: ThemeContext) {
    // Restore once (no signal reads -> runs a single time on hydration).
    Effect::new(move |_| {
        let Some(store) = local_storage() else { return };
        if let Ok(Some(code)) = store.get_item(PREF_LOCALE) {
            i18n.locale.set(Locale::from_code(&code));
        }
        if let Ok(Some(mode)) = store.get_item(PREF_THEME) {
            theme.dark_mode.set(mode == "dark");
        }
    });
    // Persist on change.
    Effect::new(move |_| {
        let code = i18n.locale.get().code();
        if let Some(store) = local_storage() {
            let _ = store.set_item(PREF_LOCALE, code);
        }
    });
    Effect::new(move |_| {
        let mode = if theme.dark_mode.get() {
            "dark"
        } else {
            "light"
        };
        if let Some(store) = local_storage() {
            let _ = store.set_item(PREF_THEME, mode);
        }
    });
}

/// Redirect an unauthenticated visitor to the login page (SSR redirect on the
/// server, client navigation after hydration).
#[component]
fn RedirectToLogin() -> impl IntoView {
    #[cfg(feature = "ssr")]
    {
        leptos_axum::redirect("/auth/login");
    }
    Effect::new(move |_| {
        let navigate = leptos_router::hooks::use_navigate();
        navigate("/auth/login", Default::default());
    });
    view! { <p class="redirect-note">"Redirecting…"</p> }
}

#[component]
pub fn AuthenticatedShell() -> impl IntoView {
    let theme = use_theme();
    install_pref_persistence(use_i18n(), theme);
    let info = Resource::new(|| (), |_| get_shell_info());

    view! {
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                info.get().map(|result| match result {
                    Ok(shell) => {
                        let role = shell.user.role;
                        let domains = shell.domains.clone();
                        let user = shell.user.clone();
                        let alerts = shell.open_alert_count;
                        view! {
                            <div class="app-layout" class:dark=move || theme.dark_mode.get()>
                                <Sidebar role=role domains=domains/>
                                <div class="app-main">
                                    <Header user=user open_alert_count=alerts/>
                                    <main class="app-content">
                                        <Outlet/>
                                    </main>
                                </div>
                                <ToastContainer/>
                            </div>
                        }
                        .into_any()
                    }
                    Err(_) => view! { <RedirectToLogin/> }.into_any(),
                })
            }}
        </Suspense>
    }
}
