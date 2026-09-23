//! Mail server settings (S-MAIL-07): hostname, max message size and ACME.

use super::nav::MailNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::{get_mail_config, SaveMailConfig};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::MailServerConfig;

#[component]
pub fn MailSettingsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let config = Resource::new(move || reload.get(), |_| get_mail_config());

    let hostname = RwSignal::new(String::new());
    let max_size = RwSignal::new(String::new());
    let acme_enabled = RwSignal::new(false);
    let acme_email = RwSignal::new(String::new());
    let acme_domains = RwSignal::new(String::new());
    let loaded_cfg = RwSignal::new(Option::<MailServerConfig>::None);
    let populated = RwSignal::new(false);

    Effect::new(move |_| {
        if let Some(Ok(cfg)) = config.get() {
            if !populated.get() {
                hostname.set(cfg.hostname.clone());
                max_size.set(cfg.max_message_size_bytes.to_string());
                acme_enabled.set(cfg.acme_enabled);
                acme_email.set(cfg.acme_email.clone().unwrap_or_default());
                acme_domains.set(cfg.acme_domains.join(", "));
                loaded_cfg.set(Some(cfg));
                populated.set(true);
            }
        }
    });

    let save = ServerAction::<SaveMailConfig>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
            match result {
                Ok(()) => {
                    save_error.set(None);
                    toast.success("保存しました。");
                }
                Err(e) => save_error.set(Some(e.to_string())),
            }
        }
    });
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some(mut cfg) = loaded_cfg.get() else {
            return;
        };
        cfg.hostname = hostname.get();
        cfg.max_message_size_bytes = max_size.get().trim().parse::<u64>().unwrap_or(0);
        cfg.acme_enabled = acme_enabled.get();
        cfg.acme_email = {
            let e = acme_email.get();
            if e.trim().is_empty() {
                None
            } else {
                Some(e)
            }
        };
        cfg.acme_domains = acme_domains
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        save.dispatch(SaveMailConfig { config: cfg });
    };

    view! {
        <PageHeader title=Signal::derive(|| "メールサーバ設定".to_string())/>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                config.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(_) => view! {
                        <form class="config-form" on:submit=submit>
                            <label class="field"><span class="field-label">"ホスト名"</span>
                                <input class="input" prop:value=move || hostname.get() on:input=move |ev| hostname.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"最大メッセージサイズ（バイト）"</span>
                                <input class="input" type="number" prop:value=move || max_size.get() on:input=move |ev| max_size.set(event_target_value(&ev))/></label>
                            <label class="field field-inline"><input type="checkbox" prop:checked=move || acme_enabled.get() on:change=move |ev| acme_enabled.set(event_target_checked(&ev))/><span>"ACME 有効"</span></label>
                            <label class="field"><span class="field-label">"ACME 連絡先メール"</span>
                                <input class="input" prop:value=move || acme_email.get() prop:disabled=move || !acme_enabled.get() on:input=move |ev| acme_email.set(event_target_value(&ev))/></label>
                            <label class="field"><span class="field-label">"ACME 対象ドメイン（カンマ区切り）"</span>
                                <input class="input" prop:value=move || acme_domains.get() prop:disabled=move || !acme_enabled.get() on:input=move |ev| acme_domains.set(event_target_value(&ev))/></label>
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
