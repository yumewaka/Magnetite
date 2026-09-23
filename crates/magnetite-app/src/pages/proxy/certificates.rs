//! Proxy certificate management (S-PROXY-03). Expiry badge derived from
//! `not_after` (AC-17 / PX-04).

use super::nav::ProxyNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::proxy::{
    get_acme_config, list_certificates, CreateCertificate, DeleteCertificate, SaveAcmeConfig,
};
use leptos::prelude::*;
use magnetite_core::config::AcmeConfig;
use magnetite_core::domains::proxy::model::{CertStatus, Certificate};

fn badge(status: CertStatus) -> (&'static str, &'static str) {
    match status {
        CertStatus::Valid => ("badge badge-success", "有効"),
        CertStatus::ExpiringSoon => ("badge badge-warning", "まもなく期限切れ"),
        CertStatus::Expired => ("badge badge-danger", "期限切れ"),
    }
}

#[component]
pub fn CertificatesPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let certs = Resource::new(move || reload.get(), |_| list_certificates());

    let form_open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let subject = RwSignal::new(String::new());
    let issuer = RwSignal::new(String::new());
    let san = RwSignal::new(String::new());
    let not_after = RwSignal::new(String::new());
    let cert_pem = RwSignal::new(String::new());
    let key_pem = RwSignal::new(String::new());
    let chain_pem = RwSignal::new(String::new());

    let open_create = move |_| {
        name.set(String::new());
        subject.set(String::new());
        issuer.set(String::new());
        san.set(String::new());
        not_after.set(String::new());
        cert_pem.set(String::new());
        key_pem.set(String::new());
        chain_pem.set(String::new());
        form_open.set(true);
    };

    let create = ServerAction::<CreateCertificate>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    form_open.set(false);
                    toast.success("保存しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create.dispatch(CreateCertificate {
            name: name.get(),
            subject: subject.get(),
            issuer: issuer.get(),
            san: san.get(),
            not_after: not_after.get(),
            cert_pem: cert_pem.get(),
            key_pem: key_pem.get(),
            chain_pem: chain_pem.get(),
        });
    };

    let delete = ServerAction::<DeleteCertificate>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(result) = delete.value().get() {
            match result {
                Ok(()) => {
                    toast.success("削除しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            delete_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, n)) => format!("証明書「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, name)) = delete_target.get() {
            delete.dispatch(DeleteCertificate { id, name });
        }
    });

    // ---- ACME automatic-certificate settings (DB-backed, hot-reloaded) ----
    let acme = Resource::new(move || reload.get(), |_| get_acme_config());
    let acme_enabled = RwSignal::new(false);
    let acme_staging = RwSignal::new(false);
    let acme_domains = RwSignal::new(String::new());
    let acme_email = RwSignal::new(String::new());
    let acme_cert_name = RwSignal::new(String::new());
    let acme_renew_days = RwSignal::new("30".to_string());
    let acme_dir = RwSignal::new(String::new());
    // Populate the form when the stored config loads (or reloads after a save).
    Effect::new(move |_| {
        if let Some(Ok(cfg)) = acme.get() {
            acme_enabled.set(cfg.enabled);
            acme_staging.set(cfg.staging);
            acme_domains.set(cfg.domains.join("\n"));
            acme_email.set(cfg.contact_email.unwrap_or_default());
            acme_cert_name.set(cfg.certificate_name.unwrap_or_default());
            acme_renew_days.set(cfg.renew_before_days.unwrap_or(30).to_string());
            acme_dir.set(cfg.directory_url.unwrap_or_default());
        }
    });
    let save_acme = ServerAction::<SaveAcmeConfig>::new();
    let acme_err = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save_acme.value().get() {
            match result {
                Ok(()) => {
                    acme_err.set(None);
                    toast.success("ACME 設定を保存しました（数分以内に反映・必要なら再発行）。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => acme_err.set(Some(e.to_string())),
            }
        }
    });
    let submit_acme = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let domains: Vec<String> = acme_domains
            .get()
            .split(['\n', ','])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let email = acme_email.get();
        let cert = acme_cert_name.get();
        let dir = acme_dir.get();
        save_acme.dispatch(SaveAcmeConfig {
            config: AcmeConfig {
                enabled: acme_enabled.get(),
                staging: acme_staging.get(),
                directory_url: Some(dir).filter(|s| !s.trim().is_empty()),
                contact_email: Some(email).filter(|s| !s.trim().is_empty()),
                domains,
                certificate_name: Some(cert).filter(|s| !s.trim().is_empty()),
                renew_before_days: acme_renew_days.get().trim().parse::<i64>().ok(),
            },
        });
    };

    view! {
        <PageHeader title=Signal::derive(|| "証明書".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 登録"</button>
        </PageHeader>
        <ProxyNav/>

        <section class="card" style="margin-bottom:1.25rem">
            <h2 style="margin:0 0 .25rem">"ACME 自動証明書 (Let's Encrypt)"</h2>
            <p class="field-label" style="margin:0 0 .75rem">
                "設定は即時 DB 反映され、ACME マネージャが約1分以内に取り込みます。ドメインを追加すると共有 SAN 証明書が自動で再発行されます（再起動不要）。"
            </p>
            <form class="config-form" on:submit=submit_acme>
                <label class="field field-inline">
                    <input type="checkbox" prop:checked=move || acme_enabled.get() on:change=move |ev| acme_enabled.set(event_target_checked(&ev))/>
                    <span>"有効"</span>
                </label>
                <label class="field field-inline">
                    <input type="checkbox" prop:checked=move || acme_staging.get() on:change=move |ev| acme_staging.set(event_target_checked(&ev))/>
                    <span>"ステージング（テスト用・信頼されない証明書）"</span>
                </label>
                <label class="field">
                    <span class="field-label">"ドメイン（1行に1つ。最初がサブジェクトCN、全てがSANになる）"</span>
                    <textarea class="input" rows="4" placeholder="app.example.com&#10;www.example.com" prop:value=move || acme_domains.get() on:input=move |ev| acme_domains.set(event_target_value(&ev))></textarea>
                </label>
                <label class="field">
                    <span class="field-label">"証明書名（vhost の certificate_ref から参照。既定 acme）"</span>
                    <input class="input" placeholder="acme" prop:value=move || acme_cert_name.get() on:input=move |ev| acme_cert_name.set(event_target_value(&ev))/>
                </label>
                <label class="field">
                    <span class="field-label">"連絡先メール（任意・CA からの期限通知先）"</span>
                    <input class="input" type="email" prop:value=move || acme_email.get() on:input=move |ev| acme_email.set(event_target_value(&ev))/>
                </label>
                <label class="field">
                    <span class="field-label">"更新猶予日数（残り日数がこれ未満で更新。既定 30）"</span>
                    <input class="input" type="number" min="1" max="89" prop:value=move || acme_renew_days.get() on:input=move |ev| acme_renew_days.set(event_target_value(&ev))/>
                </label>
                <label class="field">
                    <span class="field-label">"ディレクトリURL（任意・空欄=Let's Encrypt。ローカル Pebble 等を指定可）"</span>
                    <input class="input" prop:value=move || acme_dir.get() on:input=move |ev| acme_dir.set(event_target_value(&ev))/>
                </label>
                {move || acme_err.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                <div>
                    <button type="submit" class="btn btn-primary" prop:disabled=move || save_acme.pending().get()>"ACME 設定を保存"</button>
                </div>
            </form>
        </section>

        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                certs.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "証明書がありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let now = chrono::Utc::now();
                        let rows = list.into_iter().map(|c: Certificate| {
                            let (cls, label) = badge(CertStatus::from_expiry(c.not_after, now, 30));
                            let id_d = c.id.clone();
                            let name_d = c.name.clone();
                            let not_after_s = c.not_after.format("%Y-%m-%d").to_string();
                            view! {
                                <tr>
                                    <td>{c.name.clone()}</td>
                                    <td class="mono">{c.subject.clone()}</td>
                                    <td>{not_after_s}</td>
                                    <td><span class=cls><span class="badge-dot"></span>{label}</span></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"証明書名"</th><th>"サブジェクト"</th><th>"有効終了"</th><th>"期限"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"証明書の登録"</h2>
                    <label class="field"><span class="field-label">"証明書名"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"サブジェクト"</span><input class="input" prop:value=move || subject.get() on:input=move |ev| subject.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"発行者"</span><input class="input" prop:value=move || issuer.get() on:input=move |ev| issuer.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"SAN（カンマ区切り）"</span><input class="input" prop:value=move || san.get() on:input=move |ev| san.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"有効終了日"</span><input class="input" type="date" prop:value=move || not_after.get() on:input=move |ev| not_after.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"証明書 PEM"</span><textarea class="input" rows="4" prop:value=move || cert_pem.get() on:input=move |ev| cert_pem.set(event_target_value(&ev))></textarea></label>
                    <label class="field"><span class="field-label">"秘密鍵 PEM"</span><textarea class="input" rows="3" prop:value=move || key_pem.get() on:input=move |ev| key_pem.set(event_target_value(&ev))></textarea></label>
                    <label class="field"><span class="field-label">"チェーン PEM（任意）"</span><textarea class="input" rows="3" prop:value=move || chain_pem.get() on:input=move |ev| chain_pem.set(event_target_value(&ev))></textarea></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || create.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
