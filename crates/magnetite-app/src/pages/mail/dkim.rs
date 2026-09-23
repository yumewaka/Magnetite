//! DKIM outbound-signing management (S-MAIL DKIM). Per hosted domain: generate a
//! signing key (private key held server-side), show the public DNS TXT record to
//! publish, and enable/disable signing.

use super::nav::MailNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::mail::{get_dkim, list_mail_domains, GenerateDkim, SetDkimEnabled};
use leptos::prelude::*;

#[component]
pub fn DkimPage() -> impl IntoView {
    let toast = use_toast();
    let domains = Resource::new(|| (), |_| list_mail_domains());

    let selected = RwSignal::new(String::new());
    let selector = RwSignal::new("default".to_string());
    let reload = RwSignal::new(0_u32);

    // DKIM status for the selected domain (None until one is chosen).
    let status = Resource::new(
        move || (selected.get(), reload.get()),
        |(domain, _)| async move {
            if domain.is_empty() {
                Ok(None)
            } else {
                get_dkim(domain).await
            }
        },
    );

    let generate = ServerAction::<GenerateDkim>::new();
    Effect::new(move |_| {
        if let Some(result) = generate.value().get() {
            match result {
                Ok(_) => {
                    toast.success("鍵を生成しました。TXT レコードを公開してください。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    let toggle = ServerAction::<SetDkimEnabled>::new();
    Effect::new(move |_| {
        if let Some(result) = toggle.value().get() {
            match result {
                Ok(()) => {
                    toast.success("DKIM 設定を更新しました。");
                    reload.update(|n| *n += 1);
                }
                Err(e) => toast.error(e.to_string()),
            }
        }
    });

    let on_generate = move |_| {
        let domain = selected.get();
        if domain.is_empty() {
            toast.error("ドメインを選択してください。");
            return;
        }
        generate.dispatch(GenerateDkim {
            domain,
            selector: selector.get(),
        });
    };

    view! {
        <PageHeader title=Signal::derive(|| "DKIM 署名".to_string())/>
        <MailNav/>
        <p class="page-hint">
            "送信メールに DKIM 署名を付与します。秘密鍵はサーバー側で保管され、公開鍵の TXT レコードのみ表示します。"
        </p>

        <div class="field-row">
            <label class="field">
                <span class="field-label">"ドメイン"</span>
                <select class="input" prop:value=move || selected.get()
                    on:change=move |ev| selected.set(event_target_value(&ev))>
                    <option value="">"（選択）"</option>
                    <Suspense fallback=|| ()>
                        {move || domains.get().map(|res| match res {
                            Ok(list) => list.into_iter().map(|d| view! {
                                <option value=d.name.clone()>{d.name.clone()}</option>
                            }).collect_view().into_any(),
                            Err(_) => ().into_any(),
                        })}
                    </Suspense>
                </select>
            </label>
            <label class="field">
                <span class="field-label">"セレクタ"</span>
                <input class="input" prop:value=move || selector.get()
                    on:input=move |ev| selector.set(event_target_value(&ev))/>
            </label>
            <button class="btn btn-primary" prop:disabled=move || generate.pending().get()
                on:click=on_generate>"鍵を生成 / 再生成"</button>
        </div>

        <Show when=move || !selected.get().is_empty() fallback=|| ()>
            <Suspense fallback=|| view! { <LoadingState/> }>
                {move || {
                    status.get().map(|res| match res {
                        Err(_) => view! {
                            <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                        }.into_any(),
                        Ok(None) => view! {
                            <p class="page-hint">"このドメインの DKIM 鍵はまだ生成されていません。"</p>
                        }.into_any(),
                        Ok(Some(st)) => {
                            let domain = selected.get();
                            let enabled = st.enabled;
                            let health = if enabled { "healthy" } else { "unknown" };
                            let txt = format!(
                                "{}._domainkey.{}  IN TXT  \"{}\"",
                                st.selector, domain, st.txt_record
                            );
                            view! {
                                <div class="card">
                                    <div class="field-inline">
                                        <StatusBadge health=Signal::derive(move || health.to_string())/>
                                        <span>{if enabled { "署名 有効" } else { "署名 無効" }}</span>
                                        <span class="muted">{format!("セレクタ: {}", st.selector)}</span>
                                        <button class="btn btn-secondary"
                                            prop:disabled=move || toggle.pending().get()
                                            on:click=move |_| {
                                                toggle.dispatch(SetDkimEnabled { domain: domain.clone(), enabled: !enabled });
                                            }>
                                            {if enabled { "無効化" } else { "有効化" }}
                                        </button>
                                    </div>
                                    <label class="field">
                                        <span class="field-label">"公開する DNS TXT レコード"</span>
                                        <textarea class="input" rows="4" readonly=true prop:value=txt></textarea>
                                    </label>
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>
        </Show>
    }
}
