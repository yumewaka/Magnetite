//! Login and first-run setup (S-Login / AC-01/02/03). One page handles both:
//! when no account exists it shows the admin-setup form, otherwise the login
//! form (plus an SSO option when SSO is configured — the OIDC flow itself is a
//! later phase).

use crate::server_fns::auth::{
    list_login_providers, needs_setup, LocalLogin, LoginProvider, SetupFirstAdmin,
};
use leptos::prelude::*;
use magnetite_core::i18n::use_i18n;

#[component]
pub fn LoginPage() -> impl IntoView {
    let setup_needed = Resource::new(|| (), |_| needs_setup());

    view! {
        <div class="auth-shell">
            <div class="auth-card">
                <Suspense fallback=|| view! { <p class="auth-loading">"…"</p> }>
                    {move || {
                        setup_needed
                            .get()
                            .map(|res| match res {
                                Ok(true) => view! { <SetupForm/> }.into_any(),
                                _ => view! { <LoginForm/> }.into_any(),
                            })
                    }}
                </Suspense>
            </div>
        </div>
    }
}

#[component]
fn LoginForm() -> impl IntoView {
    let i18n = use_i18n();
    let login = ServerAction::<LocalLogin>::new();
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());

    let error = move || {
        login
            .value()
            .get()
            .and_then(|r| r.err())
            .map(|e| i18n.t(&e.to_string()).to_string())
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        login.dispatch(LocalLogin {
            username: username.get(),
            password: password.get(),
        });
    };

    view! {
        <h1 class="auth-title">{move || i18n.t("login.title")}</h1>
        <form class="auth-form" on:submit=submit>
            <label class="field">
                <span class="field-label">{move || i18n.t("login.username")}</span>
                <input
                    class="input"
                    type="text"
                    autocomplete="username"
                    prop:value=move || username.get()
                    on:input=move |ev| username.set(event_target_value(&ev))
                    required
                />
            </label>
            <label class="field">
                <span class="field-label">{move || i18n.t("login.password")}</span>
                <input
                    class="input"
                    type="password"
                    autocomplete="current-password"
                    prop:value=move || password.get()
                    on:input=move |ev| password.set(event_target_value(&ev))
                    required
                />
            </label>
            {move || error().map(|msg| view! { <p class="field-error" role="alert">{msg}</p> })}
            <button class="btn btn-primary btn-block" type="submit" prop:disabled=move || login.pending().get()>
                {move || i18n.t("login.submit")}
            </button>
        </form>
        <SsoLoginOptions/>
    }
}

/// "Log in with …" buttons for each enabled upstream SSO provider. Rendered only when
/// at least one provider is configured. Each button is a full-page link to the axum
/// federation start endpoint (not client-side routing).
#[component]
fn SsoLoginOptions() -> impl IntoView {
    let providers = Resource::new(|| (), |_| list_login_providers());
    view! {
        <Suspense fallback=|| ()>
            {move || providers.get().map(|res| match res {
                Ok(list) if !list.is_empty() => {
                    let buttons = list.into_iter().map(|p: LoginProvider| {
                        let href = format!("/auth/sso/{}/start", p.name);
                        view! { <a class="btn btn-secondary btn-block" href=href>{format!("{} でログイン", p.name)}</a> }
                    }).collect_view();
                    view! {
                        <div class="sso-divider"><span>"または"</span></div>
                        <div class="sso-options">{buttons}</div>
                    }.into_any()
                }
                _ => ().into_any(),
            })}
        </Suspense>
    }
}

#[component]
fn SetupForm() -> impl IntoView {
    let i18n = use_i18n();
    let setup = ServerAction::<SetupFirstAdmin>::new();
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let local_error = RwSignal::new(Option::<&'static str>::None);

    let server_error = move || {
        setup
            .value()
            .get()
            .and_then(|r| r.err())
            .map(|e| i18n.t(&e.to_string()).to_string())
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if password.get() != confirm.get() {
            local_error.set(Some("setup.error.mismatch"));
            return;
        }
        local_error.set(None);
        setup.dispatch(SetupFirstAdmin {
            username: username.get(),
            password: password.get(),
        });
    };

    view! {
        <h1 class="auth-title">{move || i18n.t("setup.title")}</h1>
        <p class="auth-desc">{move || i18n.t("setup.desc")}</p>
        <form class="auth-form" on:submit=submit>
            <label class="field">
                <span class="field-label">{move || i18n.t("setup.username")}</span>
                <input
                    class="input"
                    type="text"
                    prop:value=move || username.get()
                    on:input=move |ev| username.set(event_target_value(&ev))
                    required
                />
            </label>
            <label class="field">
                <span class="field-label">{move || i18n.t("setup.password")}</span>
                <input
                    class="input"
                    type="password"
                    prop:value=move || password.get()
                    on:input=move |ev| password.set(event_target_value(&ev))
                    required
                />
            </label>
            <label class="field">
                <span class="field-label">{move || i18n.t("setup.password_confirm")}</span>
                <input
                    class="input"
                    type="password"
                    prop:value=move || confirm.get()
                    on:input=move |ev| confirm.set(event_target_value(&ev))
                    required
                />
            </label>
            <p class="field-hint">{move || i18n.t("setup.password_policy")}</p>
            {move || local_error.get().map(|k| view! { <p class="field-error" role="alert">{i18n.t(k)}</p> })}
            {move || server_error().map(|msg| view! { <p class="field-error" role="alert">{msg}</p> })}
            <button class="btn btn-primary btn-block" type="submit" prop:disabled=move || setup.pending().get()>
                {move || i18n.t("setup.submit")}
            </button>
        </form>
    }
}
