//! Application settings (S-Settings / F-09). Personal settings (language,
//! theme) apply immediately and persist client-side for every user; the system
//! settings block is Admin-only (AC-04) and hot-reloads on save.

use crate::components::theme::use_theme;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::auth::get_current_user;
use crate::server_fns::settings::{get_system_settings, SaveSystemSettings};
use leptos::prelude::*;
use magnetite_core::authz::Role;
use magnetite_core::i18n::{use_i18n, Locale};
use magnetite_core::models::SystemSettings;

#[component]
pub fn SettingsPage() -> impl IntoView {
    let me = Resource::new(|| (), |_| get_current_user());
    let is_admin = move || matches!(me.get(), Some(Ok(Some(u))) if u.role == Role::Admin);

    view! {
        <PageHeader title=Signal::derive(|| "設定".to_string())/>
        <PersonalSettings/>
        <Suspense fallback=|| ()>
            {move || is_admin().then(|| view! { <SystemSettingsForm/> })}
        </Suspense>
    }
}

#[component]
fn PersonalSettings() -> impl IntoView {
    let i18n = use_i18n();
    let theme = use_theme();
    view! {
        <section class="settings-card">
            <h2 class="settings-card-title">"個人設定"</h2>
            <label class="field">
                <span class="field-label">"言語"</span>
                <select class="input" prop:value=move || i18n.locale.get().code()
                    on:change=move |ev| i18n.locale.set(Locale::from_code(&event_target_value(&ev)))>
                    <option value="ja">"日本語"</option>
                    <option value="en">"English"</option>
                </select>
            </label>
            <div class="field">
                <span class="field-label">"テーマ"</span>
                <div class="radio-row">
                    <label class="radio">
                        <input type="radio" name="theme" prop:checked=move || theme.dark_mode.get()
                            on:change=move |_| theme.dark_mode.set(true)/>
                        <span>"ダーク"</span>
                    </label>
                    <label class="radio">
                        <input type="radio" name="theme" prop:checked=move || !theme.dark_mode.get()
                            on:change=move |_| theme.dark_mode.set(false)/>
                        <span>"ライト"</span>
                    </label>
                </div>
            </div>
        </section>
    }
}

#[component]
fn SystemSettingsForm() -> impl IntoView {
    let toast = use_toast();
    let settings = Resource::new(|| (), |_| get_system_settings());

    view! {
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || settings.get().map(|res| match res {
                Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| settings.refetch())/> }.into_any(),
                Ok(s) => view! { <SystemSettingsFields settings=s toast=toast/> }.into_any(),
            })}
        </Suspense>
    }
}

#[component]
fn SystemSettingsFields(
    settings: SystemSettings,
    toast: crate::components::toast::ToastContext,
) -> impl IntoView {
    // Editable working state seeded from the loaded settings.
    let domains = RwSignal::new(settings.domains.clone());
    let refresh_secs = RwSignal::new(settings.dashboard_refresh_secs.to_string());
    let retention_days = RwSignal::new(settings.retention_days.to_string());
    let sso_enabled = RwSignal::new(settings.sso.enabled);
    let issuer = RwSignal::new(settings.sso.issuer_url.clone());
    let client_id = RwSignal::new(settings.sso.client_id.clone());
    let redirect = RwSignal::new(settings.sso.redirect_uri.clone());
    let secret = RwSignal::new(String::new());
    let has_secret = settings.sso.has_secret;
    let save_error = RwSignal::new(Option::<String>::None);

    let save = ServerAction::<SaveSystemSettings>::new();
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    toast.success("設定を反映しました。");
                    // Hot reload so the sidebar / refresh cadence pick up changes.
                    let _ = window().location().reload();
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let refresh = refresh_secs.get().trim().parse::<u64>().unwrap_or(0);
        let retention = retention_days.get().trim().parse::<u32>().unwrap_or(0);
        let enabled_domains = domains
            .get()
            .iter()
            .filter(|d| d.enabled)
            .map(|d| d.key.as_str().to_string())
            .collect::<Vec<_>>();
        save.dispatch(SaveSystemSettings {
            enabled_domains,
            dashboard_refresh_secs: refresh,
            retention_days: retention,
            sso_enabled: sso_enabled.get(),
            issuer_url: issuer.get(),
            client_id: client_id.get(),
            redirect_uri: redirect.get(),
            client_secret: secret.get(),
        });
    };

    let toggle_domain = move |key: magnetite_core::domain::DomainKey| {
        domains.update(|list| {
            if let Some(d) = list.iter_mut().find(|d| d.key == key) {
                d.enabled = !d.enabled;
            }
        });
    };

    let domain_rows = move || {
        domains
            .get()
            .into_iter()
            .map(|d| {
                let key = d.key;
                let checked = d.enabled;
                view! {
                    <label class="toggle-row">
                        <input type="checkbox" prop:checked=checked on:change=move |_| toggle_domain(key)/>
                        <span>{d.display_name}</span>
                    </label>
                }
            })
            .collect_view()
    };

    let secret_placeholder = if has_secret {
        "設定済み（変更する場合のみ入力）"
    } else {
        ""
    };

    view! {
        <form class="settings-card" on:submit=on_submit>
            <h2 class="settings-card-title">"システム設定（管理者）"</h2>

            <fieldset class="settings-group">
                <legend>"ドメイン有効化"</legend>
                <div class="toggle-grid">{domain_rows}</div>
            </fieldset>

            <fieldset class="settings-group">
                <legend>"動作ポリシー"</legend>
                <label class="field">
                    <span class="field-label">"ダッシュボード更新間隔（秒）"</span>
                    <input class="input" type="number" min="5" max="3600" prop:value=move || refresh_secs.get()
                        on:input=move |ev| refresh_secs.set(event_target_value(&ev))/>
                </label>
                <label class="field">
                    <span class="field-label">"監査/ログ保持日数"</span>
                    <input class="input" type="number" min="1" max="3650" prop:value=move || retention_days.get()
                        on:input=move |ev| retention_days.set(event_target_value(&ev))/>
                </label>
            </fieldset>

            <fieldset class="settings-group">
                <legend>"SSO 接続"</legend>
                <label class="toggle-row">
                    <input type="checkbox" prop:checked=move || sso_enabled.get()
                        on:change=move |ev| sso_enabled.set(event_target_checked(&ev))/>
                    <span>"SSO を有効化"</span>
                </label>
                <Show when=move || sso_enabled.get() fallback=|| ()>
                    <label class="field">
                        <span class="field-label">"issuer URL"</span>
                        <input class="input" prop:value=move || issuer.get() on:input=move |ev| issuer.set(event_target_value(&ev)) placeholder="https://idp.example.com"/>
                    </label>
                    <label class="field">
                        <span class="field-label">"client_id"</span>
                        <input class="input" prop:value=move || client_id.get() on:input=move |ev| client_id.set(event_target_value(&ev))/>
                    </label>
                    <label class="field">
                        <span class="field-label">"redirect URI"</span>
                        <input class="input" prop:value=move || redirect.get() on:input=move |ev| redirect.set(event_target_value(&ev)) placeholder="https://.../auth/callback"/>
                    </label>
                    <label class="field">
                        <span class="field-label">"client secret"</span>
                        <input class="input" type="password" prop:value=move || secret.get() on:input=move |ev| secret.set(event_target_value(&ev)) placeholder=secret_placeholder/>
                    </label>
                </Show>
            </fieldset>

            {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
            <div class="settings-actions">
                <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存してリロード"</button>
            </div>
        </form>
    }
}
