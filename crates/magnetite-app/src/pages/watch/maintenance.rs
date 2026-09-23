//! Watch maintenance window management (S-WATCH-05). Windows suppress alerts for
//! their target during the active period (AC-20).

use super::nav::WatchNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::watch::{
    list_watch_hosts, list_watch_maintenance, CreateWatchMaintenance, DeleteWatchMaintenance,
};
use leptos::prelude::*;
use magnetite_core::domains::watch::model::{MaintenanceStatus, MaintenanceWindow};

fn parse_dt(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%dT%H:%M")
        .ok()
        .map(|dt| dt.and_utc())
}

#[component]
pub fn WatchMaintenancePage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let windows = Resource::new(move || reload.get(), |_| list_watch_maintenance());
    let hosts = Resource::new(|| (), |_| list_watch_hosts());

    let form_open = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let target_host = RwSignal::new(String::new());
    let reason = RwSignal::new(String::new());
    let starts_at = RwSignal::new(String::new());
    let ends_at = RwSignal::new(String::new());

    let open_create = move |_| {
        name.set(String::new());
        target_host.set(String::new());
        reason.set(String::new());
        starts_at.set(String::new());
        ends_at.set(String::new());
        form_open.set(true);
    };

    let create = ServerAction::<CreateWatchMaintenance>::new();
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
        let now = chrono::Utc::now();
        let (Some(start), Some(end)) = (parse_dt(&starts_at.get()), parse_dt(&ends_at.get()))
        else {
            save_error.set(Some("開始・終了日時を入力してください。".into()));
            return;
        };
        let th = target_host.get();
        let window = MaintenanceWindow {
            id: String::new(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            name: name.get(),
            target_host: if th.trim().is_empty() { None } else { Some(th) },
            target_group: None,
            reason: {
                let r = reason.get();
                if r.trim().is_empty() {
                    None
                } else {
                    Some(r)
                }
            },
            starts_at: start,
            ends_at: end,
        };
        create.dispatch(CreateWatchMaintenance { window });
    };

    let delete = ServerAction::<DeleteWatchMaintenance>::new();
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
        Some((_, n)) => format!("メンテナンス窓「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteWatchMaintenance { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "メンテナンス窓".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <WatchNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                windows.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "メンテナンス窓がありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let now = chrono::Utc::now();
                        let rows = list.into_iter().map(|w: MaintenanceWindow| {
                            let id_d = w.id.clone();
                            let name_d = w.name.clone();
                            let target = w.target_host.clone().or(w.target_group.clone()).unwrap_or_else(|| "(全体)".into());
                            let (cls, label) = match w.status_at(now) {
                                MaintenanceStatus::Scheduled => ("badge badge-unknown", "予定"),
                                MaintenanceStatus::Active => ("badge badge-warning", "実施中"),
                                MaintenanceStatus::Ended => ("badge", "終了"),
                            };
                            let start = w.starts_at.format("%Y-%m-%d %H:%M").to_string();
                            let end = w.ends_at.format("%Y-%m-%d %H:%M").to_string();
                            view! {
                                <tr>
                                    <td>{w.name.clone()}</td>
                                    <td>{target}</td>
                                    <td class="mono">{start}</td>
                                    <td class="mono">{end}</td>
                                    <td><span class=cls>{label}</span></td>
                                    <td class="row-actions">
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), name_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"名前"</th><th>"対象"</th><th>"開始"</th><th>"終了"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">"メンテナンス窓の作成"</h2>
                    <label class="field"><span class="field-label">"名前"</span><input class="input" prop:value=move || name.get() on:input=move |ev| name.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"対象ホスト（未指定=全体）"</span>
                        <select class="input" prop:value=move || target_host.get() on:change=move |ev| target_host.set(event_target_value(&ev))>
                            <option value="">"(全体)"</option>
                            <Suspense fallback=|| ()>
                                {move || hosts.get().map(|res| res.unwrap_or_default().into_iter().map(|h| { let n = h.name.clone(); view! { <option value=h.name>{n}</option> } }).collect_view())}
                            </Suspense>
                        </select></label>
                    <label class="field"><span class="field-label">"理由（任意）"</span><input class="input" prop:value=move || reason.get() on:input=move |ev| reason.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"開始日時"</span><input class="input" type="datetime-local" prop:value=move || starts_at.get() on:input=move |ev| starts_at.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"終了日時"</span><input class="input" type="datetime-local" prop:value=move || ends_at.get() on:input=move |ev| ends_at.set(event_target_value(&ev))/></label>
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
