//! Proxy virtual host management (S-PROXY-02).

use super::nav::ProxyNav;
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::toast::use_toast;
use crate::components::ui::{EmptyState, ErrorState, LoadingState, PageHeader, StatusBadge};
use crate::server_fns::proxy::{
    list_certificates, list_vhosts, DeleteVhost, SaveVhost, ToggleVhost,
};
use leptos::prelude::*;
use magnetite_core::domains::proxy::model::{
    LbStrategy, ProxyMode, Upstream, UpstreamScheme, VirtualHost,
};

#[component]
pub fn VhostsPage() -> impl IntoView {
    let toast = use_toast();
    let reload = RwSignal::new(0_u32);
    let vhosts = Resource::new(move || reload.get(), |_| list_vhosts());
    let certs = Resource::new(|| (), |_| list_certificates());

    let form_open = RwSignal::new(false);
    let edit_id = RwSignal::new(String::new());
    let hostname = RwSignal::new(String::new());
    let path_prefix = RwSignal::new(String::new());
    let listen_port = RwSignal::new("80".to_string());
    let up_host = RwSignal::new(String::new());
    let up_port = RwSignal::new("8080".to_string());
    let up_scheme = RwSignal::new("http".to_string());
    let tls = RwSignal::new(false);
    let cert_ref = RwSignal::new(String::new());
    let force_https = RwSignal::new(false);
    let mode = RwSignal::new("http".to_string());
    let lb = RwSignal::new("round_robin".to_string());
    let enabled = RwSignal::new(true);

    let open_create = move |_| {
        edit_id.set(String::new());
        hostname.set(String::new());
        path_prefix.set(String::new());
        listen_port.set("80".into());
        up_host.set(String::new());
        up_port.set("8080".into());
        up_scheme.set("http".into());
        tls.set(false);
        cert_ref.set(String::new());
        force_https.set(false);
        mode.set("http".into());
        lb.set("round_robin".into());
        enabled.set(true);
        form_open.set(true);
    };
    let open_edit = move |v: VirtualHost| {
        edit_id.set(v.id.clone());
        hostname.set(v.hostname.clone());
        path_prefix.set(v.path_prefix.clone().unwrap_or_default());
        listen_port.set(v.listen_port.to_string());
        if let Some(u) = v.upstream.first() {
            up_host.set(u.host.clone());
            up_port.set(u.port.to_string());
            up_scheme.set(
                match u.scheme {
                    UpstreamScheme::Https => "https",
                    UpstreamScheme::Http => "http",
                }
                .into(),
            );
        }
        tls.set(v.tls_enabled);
        cert_ref.set(v.certificate_ref.clone().unwrap_or_default());
        force_https.set(v.force_https);
        mode.set(
            match v.proxy_mode {
                ProxyMode::Tcp => "tcp",
                ProxyMode::Http => "http",
            }
            .into(),
        );
        lb.set(
            match v.lb_strategy {
                LbStrategy::LeastConn => "least_conn",
                LbStrategy::IpHash => "ip_hash",
                LbStrategy::Weighted => "weighted",
                LbStrategy::RoundRobin => "round_robin",
            }
            .into(),
        );
        enabled.set(v.enabled);
        form_open.set(true);
    };

    let save = ServerAction::<SaveVhost>::new();
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
        let vhost = VirtualHost {
            id: edit_id.get(),
            created_at: now,
            updated_at: now,
            created_by: String::new(),
            hostname: hostname.get(),
            path_prefix: {
                let p = path_prefix.get();
                if p.trim().is_empty() {
                    None
                } else {
                    Some(p)
                }
            },
            listen_port: listen_port.get().trim().parse::<u16>().unwrap_or(0),
            upstream: vec![Upstream {
                host: up_host.get(),
                port: up_port.get().trim().parse::<u16>().unwrap_or(0),
                weight: 1,
                scheme: match up_scheme.get().as_str() {
                    "https" => UpstreamScheme::Https,
                    _ => UpstreamScheme::Http,
                },
            }],
            tls_enabled: tls.get(),
            certificate_ref: {
                let c = cert_ref.get();
                if c.trim().is_empty() {
                    None
                } else {
                    Some(c)
                }
            },
            force_https: force_https.get(),
            proxy_mode: match mode.get().as_str() {
                "tcp" => ProxyMode::Tcp,
                _ => ProxyMode::Http,
            },
            lb_strategy: match lb.get().as_str() {
                "least_conn" => LbStrategy::LeastConn,
                "ip_hash" => LbStrategy::IpHash,
                "weighted" => LbStrategy::Weighted,
                _ => LbStrategy::RoundRobin,
            },
            enabled: enabled.get(),
        };
        save.dispatch(SaveVhost { vhost });
    };

    let toggle = ServerAction::<ToggleVhost>::new();
    Effect::new(move |_| {
        if let Some(Ok(())) = toggle.value().get() {
            toast.success("保存しました。");
            reload.update(|n| *n += 1);
        }
    });

    let delete = ServerAction::<DeleteVhost>::new();
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
        Some((_, h)) => format!("仮想ホスト「{h}」を削除します。よろしいですか？"),
        None => String::new(),
    });
    let on_confirm_delete = Callback::new(move |_| {
        if let Some((id, hostname)) = delete_target.get() {
            delete.dispatch(DeleteVhost { id, hostname });
        }
    });

    view! {
        <PageHeader title=Signal::derive(|| "仮想ホスト".to_string())>
            <button class="btn btn-primary" on:click=open_create>"＋ 追加"</button>
        </PageHeader>
        <ProxyNav/>
        <Suspense fallback=|| view! { <LoadingState/> }>
            {move || {
                vhosts.get().map(|res| match res {
                    Err(_) => view! { <ErrorState on_retry=Callback::new(move |_| reload.update(|n| *n += 1))/> }.into_any(),
                    Ok(list) if list.is_empty() => view! { <EmptyState message=Signal::derive(|| "仮想ホストがありません。".to_string())/> }.into_any(),
                    Ok(list) => {
                        let rows = list.into_iter().map(|v: VirtualHost| {
                            let v_edit = v.clone();
                            let id_t = v.id.clone();
                            let id_d = v.id.clone();
                            let host_d = v.hostname.clone();
                            let enabled = v.enabled;
                            let health = if v.enabled { "healthy" } else { "unknown" };
                            let tls = if v.tls_enabled { "TLS" } else { "-" };
                            view! {
                                <tr>
                                    <td class="mono">{v.hostname.clone()}</td>
                                    <td>{v.listen_port}</td>
                                    <td>{tls}</td>
                                    <td><StatusBadge health=Signal::derive(move || health.to_string())/></td>
                                    <td class="row-actions">
                                        <button class="btn btn-secondary btn-sm" on:click=move |_| { toggle.dispatch(ToggleVhost { id: id_t.clone(), enabled: !enabled }); }>{if enabled { "無効化" } else { "有効化" }}</button>
                                        <button class="icon-button" title="編集" on:click=move |_| open_edit(v_edit.clone())>"\u{270E}"</button>
                                        <button class="icon-button" title="削除" on:click=move |_| { delete_target.set(Some((id_d.clone(), host_d.clone()))); confirm_open.set(true); }>"\u{1F5D1}"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view();
                        view! { <table class="data-table"><thead><tr><th>"ホスト名"</th><th>"ポート"</th><th>"TLS"</th><th>"状態"</th><th>"操作"</th></tr></thead><tbody>{rows}</tbody></table> }.into_any()
                    }
                })
            }}
        </Suspense>

        <Show when=move || form_open.get() fallback=|| ()>
            <div class="slideover-overlay" on:click=move |_| form_open.set(false)>
                <form class="slideover" on:click=|ev| ev.stop_propagation() on:submit=submit>
                    <h2 class="slideover-title">{move || if edit_id.get().is_empty() { "仮想ホストの作成" } else { "仮想ホストの編集" }}</h2>
                    <label class="field"><span class="field-label">"ホスト名"</span><input class="input" prop:value=move || hostname.get() prop:disabled=move || !edit_id.get().is_empty() on:input=move |ev| hostname.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"パスプレフィックス（任意・例 /api）"</span><input class="input" placeholder="空=全パス" prop:value=move || path_prefix.get() on:input=move |ev| path_prefix.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"リッスンポート"</span><input class="input" type="number" prop:value=move || listen_port.get() on:input=move |ev| listen_port.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"転送先ホスト"</span><input class="input" prop:value=move || up_host.get() on:input=move |ev| up_host.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"転送先ポート"</span><input class="input" type="number" prop:value=move || up_port.get() on:input=move |ev| up_port.set(event_target_value(&ev))/></label>
                    <label class="field"><span class="field-label">"転送先スキーム（バックエンドへの接続）"</span>
                        <select class="input" prop:value=move || up_scheme.get() on:change=move |ev| up_scheme.set(event_target_value(&ev))>
                            <option value="http">"HTTP"</option><option value="https">"HTTPS（TLS バックエンド）"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"プロキシモード"</span>
                        <select class="input" prop:value=move || mode.get() on:change=move |ev| mode.set(event_target_value(&ev))>
                            <option value="http">"HTTP"</option><option value="tcp">"TCP (L4ストリーム)"</option>
                        </select></label>
                    <label class="field"><span class="field-label">"LB 戦略"</span>
                        <select class="input" prop:value=move || lb.get() on:change=move |ev| lb.set(event_target_value(&ev))>
                            <option value="round_robin">"ラウンドロビン"</option><option value="least_conn">"最小接続"</option><option value="ip_hash">"IP ハッシュ"</option><option value="weighted">"重み付き"</option>
                        </select></label>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || tls.get() on:change=move |ev| tls.set(event_target_checked(&ev))/><span>"TLS 有効"</span></label>
                    <Show when=move || tls.get() fallback=|| ()>
                        <label class="field"><span class="field-label">"証明書"</span>
                            <select class="input" prop:value=move || cert_ref.get() on:change=move |ev| cert_ref.set(event_target_value(&ev))>
                                <option value="">"（選択）"</option>
                                <Suspense fallback=|| ()>
                                    {move || certs.get().map(|res| res.unwrap_or_default().into_iter().map(|c| { let n = c.name.clone(); view! { <option value=c.name>{n}</option> } }).collect_view())}
                                </Suspense>
                            </select></label>
                    </Show>
                    <label class="field field-inline"><input type="checkbox" prop:checked=move || force_https.get() on:change=move |ev| force_https.set(event_target_checked(&ev))/><span>"HTTPS 強制"</span></label>
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
