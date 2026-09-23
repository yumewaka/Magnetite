//! Confirmation dialog for destructive operations (10 §2.5). The caller
//! supplies the confirmed message text; the dialog focuses and closes on Esc.

use leptos::prelude::*;
use magnetite_core::i18n::use_i18n;

/// A modal confirm dialog. Renders only when `open` is true.
///
/// - `title` / `body`: already-localized strings from the caller.
/// - `on_confirm`: invoked when the primary action is chosen.
/// - `open`: controls visibility; the dialog clears it on cancel/confirm.
#[component]
pub fn ConfirmDialog(
    #[prop(into)] title: Signal<String>,
    #[prop(into)] body: Signal<String>,
    open: RwSignal<bool>,
    #[prop(into)] on_confirm: Callback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let confirm = move |_| {
        on_confirm.run(());
        open.set(false);
    };
    view! {
        <Show when=move || open.get() fallback=|| ()>
            <div class="modal-overlay" on:click=move |_| open.set(false)>
                <div
                    class="modal confirm-dialog"
                    role="dialog"
                    aria-modal="true"
                    on:click=|ev| ev.stop_propagation()
                >
                    <h2 class="modal-title">{move || title.get()}</h2>
                    <p class="modal-body">{move || body.get()}</p>
                    <div class="modal-actions">
                        <button class="btn btn-secondary" on:click=move |_| open.set(false)>
                            {move || i18n.t("action.cancel")}
                        </button>
                        <button class="btn btn-danger" on:click=confirm>
                            {move || i18n.t("action.confirm")}
                        </button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
