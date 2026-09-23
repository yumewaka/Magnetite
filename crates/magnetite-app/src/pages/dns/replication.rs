//! DNS replication management (07_data_dns replication extension): per-zone
//! primary/secondary role + transfer settings, and TSIG key management.
//! Transfers are authorized by the allow-transfer IP list; NOTIFY is sent to the
//! also-notify targets. Secondary zones mirror an external primary (read-only).

use super::nav::DnsNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::dns::{
    list_tsig_keys, list_zones, CreateTsigKey, DeleteTsigKey, SetZoneReplication,
};
use leptos::prelude::*;
use magnetite_core::domains::dns::model::{Zone, ZoneRole};

fn lines_to_vec(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

#[component]
pub fn ReplicationPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let zones = Resource::new(move || reload.get(), |_| list_zones());
    let tsig_reload = RwSignal::new(0_u32);
    let tsig_keys = Resource::new(move || tsig_reload.get(), |_| list_tsig_keys());

    // ---- zone replication settings form ----
    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let edit_name = RwSignal::new(String::new());
    let role = RwSignal::new("primary".to_string());
    let allow_transfer = RwSignal::new(String::new());
    let also_notify = RwSignal::new(String::new());
    let notify_enabled = RwSignal::new(false);
    let primaries = RwSignal::new(String::new());
    let tsig_name = RwSignal::new(String::new());

    let open_edit = move |z: Zone| {
        edit_id.set(z.id.clone());
        edit_name.set(z.name.clone());
        role.set(match z.role {
            ZoneRole::Secondary => "secondary".into(),
            ZoneRole::Primary => "primary".into(),
        });
        allow_transfer.set(z.allow_transfer.join("\n"));
        also_notify.set(z.also_notify.join("\n"));
        notify_enabled.set(z.notify_enabled);
        primaries.set(z.primaries.join("\n"));
        tsig_name.set(z.tsig_key_name.unwrap_or_default());
        form_open.set(true);
    };

    let save = ServerAction::<SetZoneReplication>::new();
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
        let tsig = {
            let t = tsig_name.get();
            if t.trim().is_empty() {
                None
            } else {
                Some(t)
            }
        };
        save.dispatch(SetZoneReplication {
            id: edit_id.get(),
            role: role.get(),
            allow_transfer: lines_to_vec(&allow_transfer.get()),
            also_notify: lines_to_vec(&also_notify.get()),
            notify_enabled: notify_enabled.get(),
            primaries: lines_to_vec(&primaries.get()),
            tsig_key_name: tsig,
        });
    };
    let is_secondary = move || role.get() == "secondary";

    // ---- TSIG key management ----
    let key_name = RwSignal::new(String::new());
    let key_alg = RwSignal::new("hmac-sha256".to_string());
    let key_secret = RwSignal::new(String::new());
    let create_key = ServerAction::<CreateTsigKey>::new();
    let key_error = RwSignal::new(Option::<String>::None);
    Effect::new(move |_| {
        if let Some(result) = create_key.value().get() {
            match result {
                Ok(()) => {
                    key_error.set(None);
                    key_name.set(String::new());
                    key_secret.set(String::new());
                    toast.success("TSIG 鍵を作成しました。");
                    tsig_reload.update(|n| *n += 1);
                }
                Err(e) => key_error.set(Some(e.to_string())),
            }
        }
    });
    let submit_key = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        create_key.dispatch(CreateTsigKey {
            name: key_name.get(),
            algorithm: key_alg.get(),
            secret_b64: key_secret.get(),
        });
    };

    let delete_key = ServerAction::<DeleteTsigKey>::new();
    let confirm_open = RwSignal::new(false);
    let del_target = RwSignal::new(Option::<(String, String)>::None);
    Effect::new(move |_| {
        if let Some(Ok(())) = delete_key.value().get() {
            toast.success("削除しました。");
            tsig_reload.update(|n| *n += 1);
        }
    });
    let confirm_body = Signal::derive(move || match del_target.get() {
        Some((_, n)) => format!("TSIG 鍵「{n}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm = Callback::new(move |_| {
        if let Some((id, _)) = del_target.get() {
            delete_key.dispatch(DeleteTsigKey { id });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "レプリケーション".to_string())/>
        <DnsNav/>
        <p class="page-hint">
            "ゾーンをプライマリ（外部セカンダリへ AXFR/NOTIFY 提供）またはセカンダリ（外部プライマリから複製）として構成します。"
            "転送は allow-transfer の IP 許可リストで認可します。"
        </p>

        <h2 class="section-title">"ゾーン"</h2>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                zones.get().map(|res| match res {
                    Err(_) => view! {
                        <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/>
                    }.into_any(),
                    Ok(list) if list.is_empty() => view! {
                        <EmptyState message=Signal::derive(|| "ゾーンがありません。".to_string())/>
                    }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|z| {
                            let ze = z.clone();
                            let role_label = match z.role { ZoneRole::Primary => "プライマリ", ZoneRole::Secondary => "セカンダリ" };
                            let sync = match (&z.role, &z.transfer_state) {
                                (ZoneRole::Secondary, Some(s)) => {
                                    if s.last_ok { format!("同期 OK (serial {})", s.last_serial) }
                                    else { format!("失敗: {}", s.last_error.clone().unwrap_or_default()) }
                                }
                                (ZoneRole::Secondary, None) => "未同期".to_string(),
                                _ => "—".to_string(),
                            };
                            let health = match (&z.role, &z.transfer_state) {
                                (ZoneRole::Secondary, Some(s)) => if s.last_ok { "healthy" } else { "error" },
                                (ZoneRole::Secondary, None) => "unknown",
                                _ => "healthy",
                            };
                            view! {
                                <tr>
                                    <td>{z.name.clone()}</td>
                                    <td>{role_label}</td>
                                    <td>{if z.notify_enabled { "NOTIFY 有効" } else { "—" }}</td>
                                    <td>
                                        <StatusBadge health=Signal::derive(move || health.to_string())/>
                                        " "{sync}
                                    </td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary"
                                            on:click=move |_| open_edit(ze.clone())>"設定"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! {
                            <table class="data-table">
                                <thead><tr>
                                    <th>"ゾーン"</th><th>"役割"</th><th>"NOTIFY"</th><th>"同期状態"</th><th>"操作"</th>
                                </tr></thead>
                                <tbody>{rows}</tbody>
                            </table>
                        }.into_any()
                    }
                })
            }}
        </Suspense>

        <h2 class="section-title">"TSIG 鍵"</h2>
        <p class="page-hint">"転送/NOTIFY 認証用の共有鍵。秘密鍵はサーバー側で保管され表示されません（対向と同じ値を設定）。"</p>
        <form class="field-row" on:submit=submit_key>
            <label class="field">
                <span class="field-label">"鍵名"</span>
                <input class="input" prop:value=move || key_name.get()
                    on:input=move |ev| key_name.set(event_target_value(&ev))/>
            </label>
            <label class="field">
                <span class="field-label">"アルゴリズム"</span>
                <select class="input" prop:value=move || key_alg.get()
                    on:change=move |ev| key_alg.set(event_target_value(&ev))>
                    <option value="hmac-sha256">"hmac-sha256"</option>
                    <option value="hmac-sha384">"hmac-sha384"</option>
                    <option value="hmac-sha512">"hmac-sha512"</option>
                </select>
            </label>
            <label class="field">
                <span class="field-label">"秘密鍵 (base64)"</span>
                <input class="input" prop:value=move || key_secret.get()
                    on:input=move |ev| key_secret.set(event_target_value(&ev))/>
            </label>
            <button class="btn btn-primary" type="submit" prop:disabled=move || create_key.pending().get()>"追加"</button>
        </form>
        {move || key_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || tsig_keys.get().map(|res| match res {
                Ok(list) if list.is_empty() => view! {
                    <EmptyState message=Signal::derive(|| "TSIG 鍵がありません。".to_string())/>
                }.into_any(),
                Ok(list) => {
                    let rows = list.into_iter().map(|k| {
                        let (kid, kname) = (k.id.clone(), k.name.clone());
                        view! {
                            <tr>
                                <td>{k.name.clone()}</td>
                                <td>{k.algorithm.wire_name()}</td>
                                <td class="row-actions">
                                    <button class="icon-button" title="削除"
                                        on:click=move |_| { del_target.set(Some((kid.clone(), kname.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                </td>
                            </tr>
                        }
                    }).collect_view();
                    view! {
                        <table class="data-table">
                            <thead><tr><th>"名前"</th><th>"アルゴリズム"</th><th>"操作"</th></tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                    }.into_any()
                }
                Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| tsig_reload.update(|n| *n += 1))/> }.into_any(),
            })}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || format!("{} の複製設定", edit_name.get())}</h2>
                    <label class="field">
                        <span class="field-label">"役割"</span>
                        <select class="input" prop:value=move || role.get()
                            on:change=move |ev| role.set(event_target_value(&ev))>
                            <option value="primary">"プライマリ（提供）"</option>
                            <option value="secondary">"セカンダリ（複製）"</option>
                        </select>
                    </label>
                    <Show when=move || !is_secondary() fallback=|| ()>
                        <label class="field">
                            <span class="field-label">"allow-transfer（1行に1つ、IP/CIDR、any 可）"</span>
                            <textarea class="input" rows="3" prop:value=move || allow_transfer.get()
                                on:input=move |ev| allow_transfer.set(event_target_value(&ev))
                                placeholder="203.0.113.0/24"></textarea>
                        </label>
                        <label class="field">
                            <span class="field-label">"also-notify（NOTIFY 送信先、host または host:port）"</span>
                            <textarea class="input" rows="2" prop:value=move || also_notify.get()
                                on:input=move |ev| also_notify.set(event_target_value(&ev))
                                placeholder="203.0.113.2"></textarea>
                        </label>
                        <label class="field field-inline">
                            <input type="checkbox" prop:checked=move || notify_enabled.get()
                                on:change=move |ev| notify_enabled.set(event_target_checked(&ev))/>
                            <span>"変更時に NOTIFY を送信"</span>
                        </label>
                    </Show>
                    <Show when=is_secondary fallback=|| ()>
                        <label class="field">
                            <span class="field-label">"プライマリ（転送元、host または host:port、1行に1つ）"</span>
                            <textarea class="input" rows="2" prop:value=move || primaries.get()
                                on:input=move |ev| primaries.set(event_target_value(&ev))
                                placeholder="198.51.100.1"></textarea>
                        </label>
                    </Show>
                    <label class="field">
                        <span class="field-label">"TSIG 鍵（任意）"</span>
                        <select class="input" prop:value=move || tsig_name.get()
                            on:change=move |ev| tsig_name.set(event_target_value(&ev))>
                            <option value="">"（なし）"</option>
                            <Suspense fallback=|| ()>
                                {move || tsig_keys.get().map(|res| match res {
                                    Ok(list) => list.into_iter().map(|k| view! {
                                        <option value=k.name.clone()>{k.name.clone()}</option>
                                    }).collect_view().into_any(),
                                    Err(_) => ().into_any(),
                                })}
                            </Suspense>
                        </select>
                    </label>
                    {move || save_error.get().map(|e| view! { <p class="field-error" role="alert">{e}</p> })}
                    <div class="slideover-actions">
                        <button type="button" class="btn btn-secondary" on:click=move |_| form_open.set(false)>"キャンセル"</button>
                        <button type="submit" class="btn btn-primary" prop:disabled=move || save.pending().get()>"保存"</button>
                    </div>
                </form>
            </div>
        </Show>

        <ConfirmDialog
            title=Signal::derive(|| "削除の確認".to_string())
            body=confirm_body
            open=confirm_open
            on_confirm=on_confirm
        />
    }
}
