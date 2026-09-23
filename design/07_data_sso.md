# データモデル：SSO / 認証プロバイダ管理ドメイン

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| ハブ | [07_data_model.md](07_data_model.md)（§3 共有構造・規約が正） |

> 本書は統一認証基盤の **管理面**（外部連携IdP設定・OIDCクライアント登録・発行済みSSOセッション）のデータ種別を定義する。
> **前提（ハブ準拠）**：共通フィールド（`id`/`created_at`/`updated_at`/`created_by`）は §3.1 を継承し**再掲しない**。監査は §3.2 `AuditEntry` を参照（本書で監査種別を再定義しない）。**tenant/tenant_id は持たない**（§0 参照）。
> **スコープ外**：エンドユーザのログイン識別（`LocalAccount` §3.7）・ポータルセッション（`Session` §3.8）・横断監査（`AuditEntry` §3.2）はハブ §3 で定義済のため本書では扱わない。テナント・SSOユーザ・SSO監査ログ・Webhook（→§3.4 `NotificationTarget`）も本書の対象外。

## 0. テナント縮退方針（重要）

移行元 SSO（`service-integration/detail_sso.md`）のマルチテナント構造を**全廃**する。

| 移行元 | 本設計での扱い |
|---|---|
| `SsoTenant` / `CreateSsoTenant` / `UpdateSsoTenant` / `SsoTenantSettings` / `SsoTenantStats` | **削除**（単一の暗黙テナントへ縮退）。テナント種別・テナント設定・テナント統計は作らない。 |
| 各種別の `tenant_id` フィールド | **全廃**。`OidcClient` / `SsoSession` / `Provider` いずれも tenant 参照を持たない。 |
| `SsoUser`（テナント従属ユーザ） | 本ドメイン対象外。ログイン識別は §3.7 `LocalAccount`、認証主体参照は subject 文字列で表す。 |
| `SsoAuditLog`（テナント別監査） | §3.2 `AuditEntry`（横断・追記不変）へ集約。 |
| `SsoWebhook`（テナント別通知） | §3.4 `NotificationTarget`（`domain=sso`）へ集約。 |

## 1. 種別一覧

| データ種別 | 説明 | 定義 |
|---|---|---|
| `Provider` | 外部／連携 IdP（OIDC/OAuth プロバイダ）の設定 | §2 |
| `OidcClient` | 本基盤に登録された OIDC リライングパーティ（クライアント） | §3 |
| `SsoSession` | 本基盤が発行した SSO セッション（発行済トークン付随） | §4 |

## 2. Provider（外部／連携 IdP 設定）

外部 IdP（Google / GitHub / Azure / 汎用 OIDC 等）との**アップストリーム連携**設定。移行元 `SsoExternalProvider` から tenant を除いた縮退版。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | プロバイダ表示名 |
| `provider_type` | ProviderType (enum) | ○ | `oidc`/`google`/`github`/`azure`/`custom` | プロバイダ種別 |
| `issuer` | URL | 任意 | `custom`/`oidc` 時は事実上必須 | OIDC issuer（`.well-known` ディスカバリ元） |
| `client_id` | String | ○ | | アップストリーム発行の OAuth クライアントID |
| `client_secret` | Secret\<String\> | ○ | **マスク**・保存時暗号化 | クライアントシークレット。§5.1 マスク方針 |
| `authorize_url` | URL | 任意 | issuer 未指定時に指定 | 認可エンドポイント |
| `token_url` | URL | 任意 | 同上 | トークンエンドポイント |
| `userinfo_url` | URL | 任意 | 同上 | ユーザ情報エンドポイント |
| `scopes` | Set\<String\> | ○ | 既定 `{openid, profile, email}` | 要求スコープ |
| `redirect_uri` | URL | ○ | 本基盤側コールバック | このプロバイダ向けリダイレクトURI |
| `auto_provision` | bool | ○ | 既定 false | 初回ログイン時の自動プロビジョニング可否 |
| `enabled` | bool | ○ | 既定 true | 有効／無効 |

## 3. OidcClient（登録 OIDC クライアント）

本基盤を IdP として利用する**ダウンストリームのリライングパーティ**登録（OIDC/OAuth2 のクライアント登録面）。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `client_name` | String | ○ | 一意 | クライアント表示名 |
| `client_id` | String | ○ | 一意・発行値 | 発行された OAuth クライアントID |
| `client_secret` | Secret\<String\> | 任意 | **マスク**・`public` 時 null | クライアントシークレット。§5.1 |
| `client_type` | ClientType (enum) | ○ | `confidential`/`public` | 機密／公開クライアント種別 |
| `grant_types` | Set\<GrantType\> | ○ | `authorization_code`/`refresh_token`/`client_credentials` 等 | 許可するグラント種別 |
| `response_types` | Set\<String\> | ○ | 既定 `{code}` | 許可するレスポンス種別 |
| `redirect_uris` | Set\<URL\> | ○ | 非空・完全一致検証 | 許可リダイレクトURI（複数可） |
| `scopes` | Set\<String\> | ○ | 既定 `{openid}` | このクライアントに許可するスコープ |
| `token_endpoint_auth_method` | AuthMethod (enum) | ○ | `client_secret_basic`/`client_secret_post`/`none` | トークンEP認証方式 |
| `provider_ref` | ref→Provider | 任意 | | 特定の外部Providerに紐づく場合の連携元（§5.2） |
| `enabled` | bool | ○ | 既定 true | 有効／無効 |

## 4. SsoSession（発行済み SSO セッション）

本基盤が発行した SSO セッション。移行元 `SsoSession` から tenant を除いた縮退版。ポータルのログインセッション（§3.8 `Session`）とは別系統（SSO 経路で本基盤が主体的に発行・失効管理する）。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `session_ref` | String | ○ | 一意 | セッション識別子（トークン参照キー） |
| `subject` | String（sub） | ○ | | 認証主体の subject（SSO subject。tenant 修飾しない・§5.2） |
| `client_ref` | ref→OidcClient | 任意 | | セッションを発行したクライアント |
| `provider_ref` | ref→Provider | 任意 | | 上流認証に用いた外部Provider（§5.2） |
| `scopes` | Set\<String\> | ○ | | このセッションに付与されたスコープ |
| `access_token` | Secret\<String\> | 任意 | **マスク**・保存時暗号化 | 発行アクセストークン。§5.1 |
| `refresh_token` | Secret\<String\> | 任意 | **マスク**・保存時暗号化 | リフレッシュトークン。§5.1 |
| `ip_address` | IpAddr | 任意 | | アクセス元IP |
| `user_agent` | String | 任意 | | ユーザエージェント |
| `issued_at` | DateTime(UTC) | ○ | | 発行時刻 |
| `expires_at` | DateTime(UTC) | ○ | | 失効予定時刻 |
| `revoked_at` | DateTime(UTC) | 任意 | | 明示失効時刻（未失効なら null） |

> インメモリ管理か永続化かの意味論・失効の実行時挙動は 09（runtime_spec）に委譲。

## 5. 参照

### 5.1 シークレットのマスク方針
- `Provider.client_secret` / `OidcClient.client_secret` / `SsoSession.access_token` / `SsoSession.refresh_token` は `Secret<T>` 型で保持し、**保存時暗号化・API 応答ではマスク**（例：`****`／末尾数桁のみ）する。
- 監査（§3.2 `AuditEntry.detail`）に載せる場合も機微値はマスク（ハブ §3.2 の注記に準拠）。

### 5.2 参照元 → 参照先
| 参照元 | 参照先 | 関係 |
|---|---|---|
| `OidcClient.provider_ref` | `Provider` | クライアントが紐づく外部連携元（任意） |
| `SsoSession.provider_ref` | `Provider` | セッションの上流認証プロバイダ（任意） |
| `SsoSession.client_ref` | `OidcClient` | セッションを発行したクライアント（任意） |
| `SsoSession.subject` | SSO subject（外部識別子・非DB参照） | 認証主体。`LocalAccount` とは非リンク（ハブ §6 未確定に準拠） |

### 5.3 参照先 → 参照元（削除影響の逆引き）
| 参照先 | 削除／変更時に再検証する参照元 | 方針 |
|---|---|---|
| `Provider` | `OidcClient.provider_ref` / `SsoSession.provider_ref` | Provider 削除・無効化時、当該 Provider 由来の `SsoSession` を**失効**（`revoked_at` セット）。`OidcClient.provider_ref` は連携解除。**AC-19（プロバイダ削除でセッション失効）／AC-05（失効の即時反映）準拠**。 |
| `OidcClient` | `SsoSession.client_ref` | クライアント削除・無効化時、当該クライアント発行の `SsoSession` を**失効**（AC-19/AC-05 準拠）。 |
| `subject`（主体の無効化） | `SsoSession.subject` | 主体無効化時、当該 subject の全 `SsoSession` を失効（移行元 `revoke_user_sessions` 相当。tenant 修飾なしの subject 単位）。 |

## 6. 補足
- **テナント縮退**：移行元の `Tenant` 種別および全種別の `tenant_id` を**全廃**し、単一の暗黙テナントへ縮退した（§0）。テナント設定・テナント統計・テナント別監査／Webhook も本ドメインでは作らず、横断構造（§3.2／§3.4）へ集約する。
- 監査・通知・共通フィールドはハブ §3 が正。本書は SSO 管理面の固有フィールドと参照のみを定義する。
- 未確定：SSO subject と `LocalAccount` の任意リンク（ハブ §6 に準拠し現状は非リンク）、セッションの永続化要否（09）。
