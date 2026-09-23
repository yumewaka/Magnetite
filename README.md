# Magnetite（統合再設計版）

社内インフラを構成する 8 サービス（**SSO / LDAP / DNS / DHCP / Mail / Proxy / コンテナ・K8s / 監視**）を、
**単一バイナリ・単一プロセス・単一DB** のモノリスとして統合管理する Web アプリケーション。

旧 `service-integration`（プロセス分離＋APIゲートウェイ型ポータル）を再設計し、プロセス管理・
ゲートウェイ・サービス個別認証を廃止。認証（ローカル＋SSO）・認可（RBAC）・UI/UX・監査・アラート・
バックアップ・テンプレート等の横断機能を統一する。

> 設計書は [`design/`](design/) 配下。実装はこの設計書に従う。

## アーキテクチャ

| クレート | 役割 |
|---|---|
| `magnetite-core` | 設定・共有モデル・認可エンジン・パスワードポリシー・エラー・i18n（ドメイン非依存、WASM 対応） |
| `magnetite-db` | 単一組込み DB（SurrealDB / RocksDB）とリポジトリ層（アカウント・セッション・監査）。サーバ専用 |
| `magnetite-app` | Leptos アプリ（シェル・標準UIキット・画面・server functions）。SSR ＋ WASM hydrate |
| `magnetite-server` | Axum バイナリ（起動・常駐タスク・静的配信・graceful shutdown） |

- スタック：Rust / Leptos 0.8（SSR + WASM hydrate）/ Axum 0.8 / SurrealDB 3 / Argon2。
- 単一組込み DB が全データの唯一の正（09_runtime_spec §0）。セッションも DB 永続化（再起動耐性）。
- 認可は統一 RBAC（Viewer < Operator < Admin、default deny）を全機能へ一様適用（08_authz）。

## 実装状況

**Phase 0（基盤）完了**：ワークスペース、コア（設定/モデル/認可/i18n）、DB（アカウント/セッション/監査）、
アプリシェル、標準UIキット、ログイン・初回セットアップ・統合ダッシュボード、Axum 起動・graceful shutdown。

**8ドメイン全ての管理画面 完了**（DNS / DHCP / LDAP / Mail / Proxy / K8s / SSO / Watch）：
各ドメインのデータモデル・検証（core）、リポジトリ（db）、server functions（認可＋監査）、CRUD画面。
参照整合ガード（カスケード削除・削除ガード・一意制約）と AC 準拠の確定文言を実装。
テスト：core 53 + db 39（SurrealDB/RocksDB 実DB）。SSR・WASM(hydrate) 両ビルドをクリーンに維持。

**未実装（後続フェーズ）**：横断共通画面（S-Audit 監査ビューア／S-Alerts アラート一覧・確認＋ルール評価エンジン／
S-Backup／S-Logs／S-Settings／S-Account）、SSO(OIDC/PKCE) ログインフロー、実デーモン連携
（DNS クエリテスト/ログ・DHCP リース・LDAP LDIF/ACL/スキーマ・Proxy アクセスログ）、通知先管理。
各ドメインで先送りにした画面は該当ドメイン節（設計書）と [`design/HANDOFF.md`](design/HANDOFF.md) を参照。

## ビルドと実行

前提：Rust nightly（`rust-toolchain.toml` で固定）、`wasm32-unknown-unknown` ターゲット、
RocksDB ビルド用の LLVM/libclang。

```sh
# コア／DB のユニットテスト
cargo test -p magnetite-core
cargo test -p magnetite-db

# サーバの型チェック（SSR）
cargo check -p magnetite-server

# フルビルド＋起動（cargo-leptos が必要）
cargo install cargo-leptos
cargo leptos watch          # http://127.0.0.1:4000
```

設定は [`magnetite.toml`](magnetite.toml)（＝`AppConfig`）。`data/magnetite-db/` に DB が作られる。
初回起動時、ローカルアカウントが 0 件なら初期管理者作成へ誘導される（AC-03）。

## ライセンス

MIT
