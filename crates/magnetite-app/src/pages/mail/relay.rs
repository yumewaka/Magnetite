//! Outbound SMTP relay / smarthost settings (S-MAIL). Editable here and applied
//! without a restart. The smarthost password is write-only: it is never shown, and
//! left blank on save it keeps the stored value.

use super::nav::MailNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::{get_mail_relay, SaveMailRelay};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::MailRelayConfig;

#[component]
pub fn MailRelayPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let relay = Resource::new(move || reload.get(), |_| get_mail_relay());

    let enabled = RwSignal::new(false);
    let host = RwSignal::new(String::new());
    let port = RwSignal::new("25".to_string());
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    // Whether a password is already stored (so we can show a "設定済み" hint).
    let has_password = RwSignal::new(false);
    let populated = RwSignal::new(false);

    Effect::new(move |_| {
        if let Some(Ok(cfg)) = relay.get() {
            if !populated.get() {
                enabled.set(cfg.enabled);
                host.set(cfg.host.clone());
                port.set(cfg.port.to_string());
                username.set(cfg.username.clone().unwrap_or_default());
                // GetMailRelay scrubs the secret: `Some("")` marks "a password is set".
                has_password.set(cfg.password.is_some());
                password.set(String::new());
                populated.set(true);
            }
        }
    });

    let save = ServerAction::<SaveMailRelay>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    toast.success("保存しました。数十秒以内に反映されます。");
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let pw = password.get();
        let config = MailRelayConfig {
            enabled: enabled.get(),
            host: host.get().trim().to_string(),
            port: port.get().trim().parse::<u16>().unwrap_or(0),
            username: {
                let u = username.get();
                if u.trim().is_empty() {
                    None
                } else {
                    Some(u)
                }
            },
            // Empty = keep the stored password (handled server-side).
            password: if pw.is_empty() { None } else { Some(pw) },
        };
        save.dispatch(SaveMailRelay { config });
    };

    view! {
        <PageHeader title=Signal::derive(|| "SMTP リレー（スマートホスト）".to_string())/>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                relay.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(_) => view! {
                        <form class="config-form" on:submit=submit>
                            <p class="hint">"外部宛メールを直接 MX 配送する代わりに、指定のスマートホスト（リレーサーバ）経由で送信します。無効時は直接配送します。"</p>
                            <label class="field field-inline"><input type="checkbox" prop:checked=move || enabled.get() on:change=move |ev| enabled.set(event_target_checked(&ev))/><span>"リレーを使用する"</span></label>
                            <label class="field"><span class="field-label">"スマートホスト（ホスト名）"</span>
                                <input class="input" placeholder="smtp.example.com" prop:value=move || host.get() prop:disabled=move || !enabled.get() on:input=move |ev| host.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"ポート"</span>
                                <input class="input" type="number" prop:value=move || port.get() prop:disabled=move || !enabled.get() on:input=move |ev| port.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"ユーザ名（SMTP AUTH・任意）"</span>
                                <input class="input" prop:value=move || username.get() prop:disabled=move || !enabled.get() on:input=move |ev| username.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">
                                {move || if has_password.get() { "パスワード（設定済み・変更する場合のみ入力）" } else { "パスワード（SMTP AUTH・任意）" }}
                            </span>
                                <input class="input" type="password" autocomplete="new-password" placeholder=move || if has_password.get() { "（変更しない）" } else { "" } prop:value=move || password.get() prop:disabled=move || !enabled.get() on:input=move |ev| password.set(event_target_value(&ev))/></label>
                            {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                            <div class="slideover-actions">
                                <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                            </div>
                        </form>
                    }.into_any(),
                })
            }}
        </Suspense>
    }
}
