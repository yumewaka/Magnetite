//! Japanese dictionary (canonical). Keep keys in sync with [`super::en`];
//! `super::tests::ja_and_en_cover_the_same_keys` enforces it.

macro_rules! dict {
    ($($key:literal => $value:literal),* $(,)?) => {
        /// All keys defined in this dictionary.
        pub const KEYS: &[&str] = &[$($key),*];

        /// Look up a translation for `key`.
        pub fn lookup(key: &str) -> Option<&'static str> {
            match key {
                $($key => Some($value),)*
                _ => None,
            }
        }
    };
}

dict! {
    "app.title" => "Magnetite",
    "app.tagline" => "統合サービス基盤",

    // Sidebar groups and cross-cutting nav
    "nav.group.cross" => "横断",
    "nav.group.domains" => "ドメイン",
    "nav.group.admin" => "管理",
    "nav.dashboard" => "ダッシュボード",
    "nav.audit" => "監査ログ",
    "nav.alerts" => "アラート",
    "nav.backup" => "バックアップ",
    "nav.logs" => "ログ",
    "nav.settings" => "設定",
    "nav.account" => "アカウント",

    // Domains
    "domain.dns" => "DNS",
    "domain.dhcp" => "DHCP",
    "domain.ldap" => "LDAP",
    "domain.mail" => "メール",
    "domain.proxy" => "プロキシ",
    "domain.k8s" => "コンテナ / K8s",
    "domain.sso" => "SSO",
    "domain.watch" => "監視",
    "domain.addc" => "AD ドメイン",
    "domain.portal" => "ポータル",

    // Roles
    "rbac.viewer" => "閲覧者",
    "rbac.operator" => "オペレータ",
    "rbac.admin" => "管理者",

    // Actions
    "action.add" => "追加",
    "action.edit" => "編集",
    "action.delete" => "削除",
    "action.save" => "保存",
    "action.cancel" => "キャンセル",
    "action.retry" => "再試行",
    "action.search" => "検索",
    "action.confirm" => "実行",
    "action.close" => "閉じる",
    "action.login" => "ログイン",
    "action.logout" => "ログアウト",

    // Generic states
    "state.empty" => "データがありません。",
    "state.loading" => "読み込み中…",
    "state.error" => "データの取得に失敗しました。",
    "state.forbidden" => "この操作を行う権限がありません。",

    // Pagination / counts
    "common.count" => "件数",
    "common.page" => "ページ",
    "common.of" => "/",
    "common.prev" => "前",
    "common.next" => "次",

    // Toasts
    "toast.saved" => "保存しました。",
    "toast.deleted" => "削除しました。",

    // Confirm dialog
    "confirm.delete.title" => "削除の確認",
    "confirm.delete.body" => "対象を削除します。よろしいですか？",

    // Errors (mirror CoreError)
    "error.forbidden" => "この操作を行う権限がありません。",
    "error.unauthenticated" => "認証が必要です。",
    "error.validation" => "入力内容を確認してください。",
    "error.referenced" => "他の設定から参照されているため削除できません。",
    "error.duplicate" => "同じ名称が既に存在します。",
    "error.not_found" => "対象が見つかりません。",
    "error.backend" => "処理中にエラーが発生しました。",

    // Login
    "login.title" => "ログイン",
    "login.username" => "ユーザー名",
    "login.password" => "パスワード",
    "login.submit" => "ログイン",
    "login.sso" => "SSO でログイン",
    "login.error" => "ユーザー名またはパスワードが正しくありません。",

    // First-run setup
    "setup.title" => "初期セットアップ",
    "setup.desc" => "最初の管理者アカウントを作成してください。",
    "setup.username" => "管理者ユーザー名",
    "setup.password" => "パスワード",
    "setup.password_confirm" => "パスワード（確認）",
    "setup.submit" => "管理者を作成",
    "setup.password_policy" => "パスワードは8文字以上で、英字と数字を含めてください。",
    "setup.error.mismatch" => "パスワードが一致しません。",
    "setup.error.policy" => "パスワードは8文字以上で、英字と数字を含めてください。",

    // Dashboard
    "dashboard.title" => "統合ダッシュボード",
    "dashboard.subtitle" => "全ドメインの稼働状況",
    "dashboard.refresh" => "更新",

    // Theme / language
    "theme.light" => "ライト",
    "theme.dark" => "ダーク",
    "theme.toggle" => "テーマ切替",
    "lang.toggle" => "言語切替",

    // Health states
    "health.healthy" => "正常",
    "health.warning" => "警告",
    "health.error" => "異常",
    "health.unknown" => "不明",
    "health.disabled" => "未構成",

    // Alert states
    "alert.open" => "未対応",
    "alert.acknowledged" => "確認済",
    "alert.resolved" => "解決済",
    "alert.suppressed" => "メンテナンス中",

    // User menu
    "user.menu" => "ユーザーメニュー",
    "user.role" => "ロール",
}
