//! Dynamic-DNS client settings (S-DNS): Magnetite pushes its current public IP to an
//! external DDNS provider (No-IP / DynDNS / DuckDNS …) daily at a set time and on demand.
//! DB-backed and applied without a restart (the scheduler re-reads the settings).

use super::nav::DnsNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::dns::{get_ddns_page, SaveDdnsConfig, TriggerDdnsUpdate};
use leptos::prelude::*;
use magnetite_core::domains::dns::model::{DdnsConfig, DdnsMode, DdnsStatus};

fn status_view(s: &DdnsStatus) -> impl IntoView {
    let (cls, label) = if s.last_run.is_none() {
        ("badge", "未実行")
    } else if s.last_ok {
        ("badge badge-success", "成功")
    } else {
        ("badge badge-danger", "失敗")
    };
    let when = s.last_run.clone().unwrap_or_else(|| "—".to_string());
    let ip = s.last_ip.clone().unwrap_or_else(|| "—".to_string());
    let msg = s.last_message.clone();
    view! {
        <div class="config-form" style="margin-bottom:1rem">
            <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap">
                <span class=cls><span class="badge-dot"></span>{label}</span>
                <span class="field-label">"最終実行: "{when}</span>
                <span class="field-label">"IP: "{ip}</span>
            </div>
            {(!msg.is_empty()).then(|| view! { <p class="hint" style="margin:.35rem 0 0">{msg}</p> })}
        </div>
    }
}

#[component]
pub fn DdnsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    // A single resource (config + status) — one SSR read, matching the forwarders page.
    let page = Resource::new(move || reload.get(), |_| get_ddns_page());

    let enabled = RwSignal::new(false);
    let mode = RwSignal::new("dyndns".to_string());
    let server = RwSignal::new(String::new());
    let hostname = RwSignal::new(String::new());
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let url_template = RwSignal::new(String::new());
    let ip_source = RwSignal::new(String::new());
    let update_time = RwSignal::new("03:00".to_string());
    let populated = RwSignal::new(false);
    Effect::new(move |_| {
        if let Some(Ok((c, _))) = page.get() {
            if !populated.get() {
                enabled.set(c.enabled);
                mode.set(match c.mode {
                    DdnsMode::Template => "template".into(),
                    DdnsMode::Dyndns => "dyndns".into(),
                });
                server.set(c.server);
                hostname.set(c.hostname);
                username.set(c.username);
                url_template.set(c.url_template);
                ip_source.set(c.public_ip_source.unwrap_or_default());
                update_time.set(c.update_time);
                populated.set(true);
            }
        }
    });

    let save = ServerAction::<SaveDdnsConfig>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    toast.success("保存しました。約1分以内に反映されます。");
                    password.set(String::new());
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let m = if mode.get() == "template" {
            DdnsMode::Template
        } else {
            DdnsMode::Dyndns
        };
        let src = ip_source.get();
        save.dispatch(SaveDdnsConfig {
            config: DdnsConfig {
                enabled: enabled.get(),
                mode: m,
                server: server.get(),
                hostname: hostname.get(),
                username: username.get(),
                password: password.get(),
                url_template: url_template.get(),
                public_ip_source: (!src.trim().is_empty()).then_some(src),
                update_time: update_time.get(),
            },
        });
    };

    // Manual "notify now" button.
    let trigger = ServerAction::<TriggerDdnsUpdate>::new();
    Effect::new(move |_| {
        if let Some(result) = trigger.value().get() {
            match result {
                Ok(s) => {
                    if s.last_ok {
                        toast.success("通知しました（成功）。");
                    } else {
                        toast.error(format!("通知は失敗しました: {}", s.last_message));
                    }
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });
    let notify_now = move |_| {
        trigger.dispatch(TriggerDdnsUpdate {});
    };

    view! {
        <PageHeader title=Signal::derive(|| "ダイナミックDNS".to_string())>
            <button class="btn btn-secondary" on:click=notify_now prop:disabled=move || trigger.pending().get()>"今すぐ通知"</button>
        </PageHeader>
        <DnsNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                page.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok((_, st)) => view! {
                        {status_view(&st)}
                        <form class="config-form" on:submit=submit>
                            <p class="hint">"外部のダイナミックDNSプロバイダに、設定した認証情報で現在の公開IPを通知します。既定では毎日 指定時刻に自動通知し、上の「今すぐ通知」で手動送信もできます。"</p>
                            <label class="field field-inline">
                                <input type="checkbox" prop:checked=move || enabled.get() on:change=move |ev| enabled.set(event_target_checked(&ev))/>
                                <span>"有効"</span>
                            </label>
                            <label class="field"><span class="field-label">"方式"</span>
                                <select class="input" prop:value=move || mode.get() on:change=move |ev| mode.set(event_target_value(&ev))>
                                    <option value="dyndns">"DynDNS標準 (/nic/update・Basic認証)"</option>
                                    <option value="template">"URLテンプレート ({host}/{ip}/{user}/{pass})"</option>
                                </select>
                            </label>

                            <Show when=move || mode.get() != "template" fallback=|| ()>
                                <label class="field"><span class="field-label">"サーバ（例: dynupdate.no-ip.com または https://.../nic/update）"</span>
                                    <input class="input" prop:value=move || server.get() on:input=move |ev| server.set(event_target_value(&ev))/></label>
                            </Show>
                            <Show when=move || mode.get() == "template" fallback=|| ()>
                                <label class="field"><span class="field-label">"URLテンプレート（{host}/{ip}/{user}/{pass} を展開。例: DuckDNS https://www.duckdns.org/update?domains={host}&token={pass} / MyDNS https://ipv4.mydns.jp/login.html）"</span>
                                    <input class="input" prop:value=move || url_template.get() on:input=move |ev| url_template.set(event_target_value(&ev))/></label>
                                <p class="hint">"ID/パスワードを入力すると Basic 認証として送信します（MyDNS 等）。URL に user:pass@host 形式で埋め込むことも可。成否は応答本文で判定します（MyDNS は login_status=1 で成功。認証失敗でも 200 を返すため本文で判定）。一時的な失敗（接続不可/5xx）は数回リトライします。"</p>
                            </Show>

                            <label class="field"><span class="field-label">"ホスト名"</span>
                                <input class="input" placeholder="home.example.com" prop:value=move || hostname.get() on:input=move |ev| hostname.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"ID / ユーザー名"</span>
                                <input class="input" prop:value=move || username.get() on:input=move |ev| username.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"パスワード / トークン（変更する場合のみ入力・保存済みは保持）"</span>
                                <input class="input" type="password" autocomplete="new-password" prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"通知時刻（毎日・HH:MM・サーバのローカル時刻）"</span>
                                <input class="input" type="time" prop:value=move || update_time.get() on:input=move |ev| update_time.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"公開IP取得URL（任意・空欄=プロバイダ自動検出）"</span>
                                <input class="input" placeholder="（空欄推奨）https://api.ipify.org" prop:value=move || ip_source.get() on:input=move |ev| ip_source.set(event_target_value(&ev))/></label>

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
