//! Watch host management (S-WATCH-02). Shows a maintenance badge for hosts in
//! an active window (AC-20) and links to the metrics view.

use super::nav::WatchNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::watch::{
    hosts_under_maintenance, list_watch_hosts, DeleteWatchHost, SaveWatchHost,
};
use leptos::prelude::*;
use leptos_router::components::A;
use magnetite_core::domains::watch::model::MonitoredHost;

fn status_health(status: &str) -> &'static str {
    match status {
        "online" => "healthy",
        "warning" => "warning",
        "offline" => "error",
        _ => "unknown",
    }
}

#[component]
pub fn WatchHostsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let hosts = Resource::new(move || reload.get(), |_| list_watch_hosts());
    let maint = Resource::new(move || reload.get(), |_| hosts_under_maintenance());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let ip = RwSignal::new(String::new());
    let hostname = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let host_type = RwSignal::new("server".to_string());
    let snmp = RwSignal::new(false);
    let tags = RwSignal::new(String::new());

    let open_create = move |_| {
        edit_id.set(String::new());
        name.set(String::new());
        ip.set(String::new());
        hostname.set(String::new());
        description.set(String::new());
        host_type.set("server".into());
        snmp.set(false);
        tags.set(String::new());
        form_open.set(true);
    };
    let open_edit = move |h: MonitoredHost| {
        edit_id.set(h.id.clone());
        name.set(h.name.clone());
        ip.set(h.ip_address.clone());
        hostname.set(h.hostname.clone().unwrap_or_default());
        description.set(h.description.clone().unwrap_or_default());
        host_type.set(h.host_type.clone());
        snmp.set(h.snmp_enabled);
        tags.set(h.tags.join(", "));
        form_open.set(true);
    };

    let save = ServerAction::<SaveWatchHost>::new();
    let save_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = save.value().get() {
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
    let opt = |s: String| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let now = chrono::Utc::now();
        let tag_list: Vec<String> = tags
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let host = MonitoredHost {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            ip_address: ip.get(),
            hostname: opt(hostname.get()),
            description: opt(description.get()),
            host_type: host_type.get(),
            status: "unknown".into(),
            os_type: None,
            agent_version: None,
            snmp_enabled: snmp.get(),
            last_seen: None,
            tags: tag_list,
        };
        save.dispatch(SaveWatchHost { host });
    };

    let delete = ServerAction::<DeleteWatchHost>::new();
    let confirm_open = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = delete.value().get() {
            toast.success("削除しました。");
            reload.update(|n| *n += 1);
        }
    });
    Effect::new(move |_| {
        if !confirm_open.get() {
            delete_target.set(None);
        }
    });
    let confirm_body = Signal::derive(move || match delete_target.get() {
        Some((_, n)) => format!("ホスト「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, name)) = delete_target.get() {
            delete.dispatch(DeleteWatchHost { id, name });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "監視ホスト".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <WatchNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                let under = maint.get().and_then(|r| r.ok()).unwrap_or_default();
                hosts.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "登録済みホストがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let under = under.clone();
                        let rows = list.into_iter().map(|h: MonitoredHost| {
                            let h_edit = h.clone();
                            let id_d = h.id.clone();
                            let name_d = h.name.clone();
                            let health = status_health(&h.status);
                            let in_maint = under.contains(&h.name);
                            let metrics_href = format!("/watch/hosts/{}/metrics", h.name);
                            view! {
                                <tr>
                                    <td>{h.name.clone()}</td>
                                    <td class="mono">{h.ip_address.clone()}</td>
                                    <td>
                                        <StatusBadge health=Signal::derive(move || health.to_string())/>
                                        <Show when=move || in_maint fallback=|| ()>
                                            <span class="badge badge-unknown"><span class="badge-dot"></span>"メンテナンス中"</span>
                                        </Show>
                                    </td>
                                    <td>{if h.snmp_enabled { "有" } else { "無" }}</td>
                                    <td>{h.tags.join(", ")}</td>
                                    <td class="row-actions">
                                        <A href=metrics_href attr:class="icon-button" attr:title="メトリクス">"\u{1F4C8}"</A>
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(h_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"名前"</th><th>"IP"</th><th>"状態"</th><th>"SNMP"</th><th>"タグ"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "ホストの追加" } else { "ホストの編集" }}</h2>
                    <label class="field"><span class="field-label">"名前"</span><input class="input" prop:value=move || name.get() prop:disabled=move || !edit_id.get().is_empty() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"IP アドレス"</span><input class="input" prop:value=move || ip.get() on:input=move |ev| ip.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"ホスト名 (FQDN・任意)"</span><input class="input" prop:value=move || hostname.get() on:input=move |ev| hostname.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"説明（任意）"</span><input class="input" prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"タグ（カンマ区切り）"</span><input class="input" prop:value=move || tags.get() on:input=move |ev| tags.set(event_target_value(&ev))/></label>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || snmp.get() on:change=move |ev| snmp.set(event_target_checked(&ev))/><span>"SNMP 有効"</span></label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog title=Signal::derive(|| "削除の確認".to_string()) body=confirm_body open=confirm_open on_confirm=on_confirm_delete/>
    }
}
