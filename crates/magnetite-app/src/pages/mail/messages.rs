//! Mailbox / received messages (E4). A read-only view of the messages the
//! embedded SMTP server has accepted; click a row to read the raw message
//! (webmail read, Admin-only server-side).

use super::nav::MailNav;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::mail::{get_mail_message, list_mail_messages};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::MailMessage;

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[component]
pub fn MessagesPage() -> impl IntoView {
    let reload = RwSignal::new(0_u32);
    let messages = Resource::new(move || reload.get(), |_| list_mail_messages());
    let selected = RwSignal::new(Option::<String>::None);
    let body = Resource::new(
        move || selected.get(),
        |id| async move {
            match id {
                Some(i) => get_mail_message(i).await.ok(),
                None => None,
            }
        },
    );

    view! {
        <PageHeader title=Signal::derive(|| "受信箱".to_string())/>
        <MailNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || messages.get().map(|res| match res {
                Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "受信メッセージはまだありません。".to_string())/> }.into_any(),
                Ok(list) => {
                    let rows = list.into_iter().map(|m: MailMessage| {
                        let id = m.id.clone();
                        let at = m.received_at.format("%Y-%m-%d %H:%M").to_string();
                        let size = human_size(m.size_bytes);
                        view! {
                            <tr class="mail-row" on:click=move |_| selected.set(Some(id.clone()))>
                                <td class="mono">{at}</td>
                                <td>{m.recipient}</td>
                                <td class="mono">{m.folder}</td>
                                <td class="mono">{m.sender}</td>
                                <td class="mono">{size}</td>
                            </tr>
                        }
                    }).collect_view();
                    view! {
                        <table class="data-table">
                            <thead><tr><th>"受信日時"</th><th>"宛先"</th><th>"フォルダ"</th><th>"差出人"</th><th>"サイズ"</th></tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                    }.into_any()
                }
            })}
        </Suspense>

        <Show when=move || selected.get().is_some() fallback=|| ()>
            <div class="mail-read">
                <div class="mail-read-head">
                    <span class="field-label">"メッセージ"</span>
                    <button class="btn btn-secondary btn-sm" on:click=move |_| selected.set(None)>"閉じる"</button>
                </div>
                <Suspense fallback=|| view! { <LoadingState/> }>
                    {move || match body.get() {
                        Some(Some(raw)) => view! { <pre class="mail-raw">{raw}</pre> }.into_any(),
                        _ => view! { <p class="field-hint">"本文を取得できませんでした。"</p> }.into_any(),
                    }}
                </Suspense>
            </div>
        </Show>
    }
}
