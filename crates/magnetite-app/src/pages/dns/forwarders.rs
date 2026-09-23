//! DNS forwarders settings (S-DNS): the upstream resolvers used for out-of-zone
//! names. Editable here and applied without a restart (the server re-reads them).

use super::nav::DnsNav;
use crate::components::toast::use_toast;
use crate::components::ui::{ErrorState, LoadingState, PageHeader};
use crate::server_fns::dns::{get_dns_forwarders, SaveDnsForwarders};
use leptos::prelude::*;

#[component]
pub fn ForwardersPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let forwarders = Resource::new(move || reload.get(), |_| get_dns_forwarders());

    // One forwarder `host:port` per line.
    let text = RwSignal::new(String::new());
    let populated = RwSignal::new(false);
    Effect::new(move |_| {
        if let Some(Ok(list)) = forwarders.get() {
            if !populated.get() {
                text.set(list.join("\n"));
                populated.set(true);
            }
        }
    });

    let save = ServerAction::<SaveDnsForwarders>::new();
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
        let list: Vec<String> = text
            .get()
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        save.dispatch(SaveDnsForwarders { forwarders: list });
    };

    view! {
        <PageHeader title=Signal::derive(|| "フォワーダ".to_string())/>
        <DnsNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                forwarders.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(_) => view! {
                        <form class="config-form" on:submit=submit>
                            <p class="hint">"ゾーン外の名前解決に使う上流リゾルバを、1 行に 1 件 host:port 形式で入力します（例 8.8.8.8:53）。空にすると権威応答のみ（ゾーン外は REFUSED）になります。"</p>
                            <label class="field"><span class="field-label">"フォワーダ（1 行 1 件）"</span>
                                <textarea class="input" rows="6" placeholder="8.8.8.8:53&#10;1.1.1.1:53" prop:value=move || text.get() on:input=move |ev| text.set(event_target_value(&ev))></textarea></label>
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
