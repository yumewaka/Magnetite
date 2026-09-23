//! Proxy IP block list (S-PROXY-05). Order up/down and enable toggle reflect
//! immediately.

use super::nav::ProxyNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader};
use crate::server_fns::proxy::{
    list_ip_blocks, DeleteIpBlock, SaveIpBlock, SetIpBlockOrder, ToggleIpBlock,
};
use leptos::prelude::*;
use magnetite_core::domains::proxy::model::IpBlock;

#[component]
pub fn IpBlocklistPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let blocks = Resource::new(move || reload.get(), |_| list_ip_blocks());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let cidr = RwSignal::new(String::new());
    let reason = RwSignal::new(String::new());
    let order = RwSignal::new("0".to_string());
    let expires = RwSignal::new(String::new());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        cidr.set(String::new());
        reason.set(String::new());
        order.set("0".into());
        expires.set(String::new());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |b: IpBlock| {
        edit_id.set(b.id.clone());
        cidr.set(b.cidr.clone());
        reason.set(b.reason.clone().unwrap_or_default());
        order.set(b.order.to_string());
        expires.set(
            b.expires_at
                .map(|e| e.format("%Y-%m-%d").to_string())
                .unwrap_or_default(),
        );
        enabled.set(b.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveIpBlock>::new();
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
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let now = chrono::Utc::now();
        let expires_at = chrono::NaiveDate::parse_from_str(expires.get().trim(), "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(23, 59, 59))
            .map(|dt| dt.and_utc());
        let block = IpBlock {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            cidr: cidr.get(),
            reason: {
                let r = reason.get();
                if r.trim().is_empty() {
                    None
                } else {
                    Some(r)
                }
            },
            order: order.get().trim().parse::<i32>().unwrap_or(0),
            expires_at,
            enabled: enabled.get(),
        };
        save.dispatch(SaveIpBlock { block });
    };

    let reorder = ServerAction::<SetIpBlockOrder>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = reorder.value().get() {
            toast.success("優先度を変更しました。");
            reload.update(|n| *n += 1);
        }
    });
    let toggle = ServerAction::<ToggleIpBlock>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("保存しました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteIpBlock>::new();
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
        Some((_, c)) => format!("IP ブロック「{c}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, _)) = delete_target.get() {
            delete.dispatch(DeleteIpBlock { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "IP ブロックリスト".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 作成"</button>
        </PageHeader>
        <ProxyNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                blocks.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "IP ブロックがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|b: IpBlock| {
                            let b_edit = b.clone();
                            let id_up = b.id.clone();
                            let id_down = b.id.clone();
                            let id_tog = b.id.clone();
                            let id_del = b.id.clone();
                            let cidr_del = b.cidr.clone();
                            let ord = b.order;
                            let enabled = b.enabled;
                            let exp = b.expires_at.map(|e| e.format("%Y-%m-%d").to_string()).unwrap_or_else(|| "無期限".into());
                            view! {
                                <tr>
                                    <td class="prio-cell">
                                        <button class="icon-button" title="上げる" on:click=move |_| { reorder.dispatch(SetIpBlockOrder { id: id_up.clone(), order: ord - 1 }); }>"\u{25B2}"</button>
                                        <span>{ord}</span>
                                        <button class="icon-button" title="下げる" on:click=move |_| { reorder.dispatch(SetIpBlockOrder { id: id_down.clone(), order: ord + 1 }); }>"\u{25BC}"</button>
                                    </td>
                                    <td class="mono">{b.cidr.clone()}</td>
                                    <td>{b.reason.clone().unwrap_or_default()}</td>
                                    <td>{exp}</td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { toggle.dispatch(ToggleIpBlock { id: id_tog.clone(), enabled: !enabled }); }>{if enabled { "無効化" } else { "有効化" }}</button>
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(b_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_del.clone(), cidr_del.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"優先度"</th><th>"CIDR"</th><th>"理由"</th><th>"失効"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "IP ブロックの作成" } else { "IP ブロックの編集" }}</h2>
                    <label class="field"><span class="field-label">"CIDR"</span><input class="input" prop:value=move || cidr.get() on:input=move |ev| cidr.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"理由（任意）"</span><input class="input" prop:value=move || reason.get() on:input=move |ev| reason.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"優先度"</span><input class="input" type="number" prop:value=move || order.get() on:input=move |ev| order.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"失効日（任意）"</span><input class="input" type="date" prop:value=move || expires.get() on:input=move |ev| expires.set(event_target_value(&ev))/></label>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || enabled.get() on:change=move |ev| enabled.set(event_target_checked(&ev))/><span>"有効"</span></label>
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
