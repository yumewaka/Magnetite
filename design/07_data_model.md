# データモデル：Magnetite（統合再設計版）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |

> 本書は「**データの中身**（何を持つか）」を定義する。データの**解釈・実行ルール**（実行意味論・永続化・実行時エラー）は 09_runtime_spec に分離して書く。
> 確定方針（2026-07-05）：**単一組込みDB（SurrealDB相当）が全ドメイン＋横断データの唯一の正**。**マルチテナントは廃止**（tenant フィールドを持たない）。**ログイン識別とドメインユーザは分離**。

## 1. 再編4分類（旧構造 → 新扱い）

旧「ポータル＝プロセス分離＋ゲートウェイ」型の設定/ランタイム/認証モデルを、モノリス化に合わせて整理する。

| 旧構造 | 分類 | 新扱い |
|---|---|---|
| `MagnetiteConfig` / `ServerConfig` / `SsoConfig` | 維持（簡素化） | `AppConfig`（server / sso / domains / policy）。SSO は任意経路として維持。 |
| `ServiceConfig`（api_base_url/health_url 等） | 属性化＋削除 | `DomainConfig`（display_name / icon / **enabled** のみ）。ネットワーク接続系フィールドは**削除**（内部モジュール化）。 |
| `ServiceAuthType`（Jwt/ApiKey/Session/None） | **削除** | 統一認証へ吸収。サービス個別認証は持たない。 |
| `ProcessConfig` | **削除** | プロセス管理廃止に伴い全廃。 |
| `ProcessState` / `ServiceStatus`（プロセス視点） | 属性化・再定義 | `DomainStatus`（`state: HealthState`＝Healthy/Warning/Error/Unknown の4値）＋主要指標。プロセスPID/uptime/restart は削除。 |
| `HealthStatus` | 吸収 | `DomainStatus` に吸収。 |
| `LogLine`（stdout/stderr stream） | 吸収・再定義 | `LogEntry`（動作/クエリ/アクセスの区別＋level）。stdout/stderr 概念は廃止。 |
| `UserSession`（OIDCトークン保持） | 統合・再定義 | `Session`（ローカル＋SSO両対応。SSO時のみトークン保持）。 |
| `CurrentUser` | 維持 | `CurrentUser`（+ `role`）。 |
| `OidcTokenResponse` | 維持 | SSO経路でのみ使用。 |
| SSO ドメインの `Tenant` | **削除** | 単一（暗黙）テナントへ縮退。tenant 参照を全廃。 |
| 各ドメインの監査/アラート/通知/テンプレート/バックアップ | **統合** | 横断共有構造（§3）へ集約。各ドメインは `domain` 属性で区別し参照。 |
| 各ドメインの実エンティティ（ゾーン/ユーザ/リース等） | 維持 | 各ドメインのデータ種別として保持（§4）。共通フィールドは §3.1 を継承。 |

## 2. 種別一覧（全体像）

### 2.1 横断・基盤

| 分類 | データ種別 | 説明 | 定義 |
|---|---|---|---|
| 共有 | （共通フィールド） | 全永続エンティティが持つ id/日時/作成者 | §3.1 |
| 共有 | `AuditEntry` | 横断監査ログの1件 | §3.2 |
| 共有 | `Alert` | 横断アラートの1件（open/ack/resolved） | §3.3 |
| 共有 | `NotificationTarget` | 通知先（Webhook等） | §3.4 |
| 共有 | `Template` | 定型設定の雛形（domain別） | §3.5 |
| 共有 | `Backup` | 構成バックアップ（domain別・メタ＋実体参照） | §3.6 |
| 認証 | `LocalAccount` | ローカルログイン用アカウント（Argon2） | §3.7 |
| 認証 | `Session` | ログインセッション（ローカル/SSO） | §3.8 |
| 認証 | `Role` | RBACロール（Viewer/Operator/Admin） | §3.9 |
| 設定 | `AppConfig` 他 | アプリ設定（server/sso/domains/policy） | §3.10 |
| 運用 | `DomainStatus` | ドメイン稼働状態＋主要指標 | §3.11 |
| 運用 | `LogEntry` | 動作/クエリ/アクセスログの1件 | §3.12 |

### 2.2 ドメイン別データ種別（詳細は 07_data_<domain>.md）

| ドメイン | 主なデータ種別 | 詳細ファイル |
|---|---|---|
| DNS | Zone / Record / RpzRule / QueryLog(→LogEntry) | 07_data_dns.md |
| DHCP | Pool / Reservation / Lease / DhcpConfig | 07_data_dhcp.md |
| LDAP | DirectoryEntry / User / Group / OrgUnit / AclRule / Schema | 07_data_ldap.md |
| Mail | MailUser / MailDomain / Alias / MailingList / ProtocolConfig | 07_data_mail.md |
| Proxy | VirtualHost / Certificate / AclRule / IpBlock / AccessLog(→LogEntry) | 07_data_proxy.md |
| K8s | Host / Cluster / AlertRule(→Alert生成) | 07_data_k8s.md |
| SSO | Provider / OidcClient / SsoSession | 07_data_sso.md |
| Watch | MonitoredHost / MonitorRule / HostGroup / MaintenanceWindow / Metric | 07_data_watch.md |

> `Template`/`Backup`/`AlertRule` 等の横断共有部分は §3 に集約し、ドメイン側は「固有フィールド＋共有構造への参照」のみ定義する。

## 3. 共有構造（先に定義・重複記述しない）

### 3.1 共通フィールド（全永続エンティティが継承）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `id` | ULID/UUID | ○ | 一意識別子（DB採番） |
| `created_at` | DateTime(UTC) | ○ | 作成日時 |
| `updated_at` | DateTime(UTC) | ○ | 最終更新日時 |
| `created_by` | ref→操作者 | ○ | 作成/最終更新した操作者（監査と連動） |

> 以降の各構造では共通フィールドを**再掲しない**（固有フィールドのみ記す）。

### 3.2 AuditEntry（横断監査ログ）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `actor` | ref→操作者 | ○ | 実行者（ユーザ名/subject） |
| `actor_role` | Role | ○ | 実行時ロール |
| `domain` | DomainKey (enum) | ○ | 対象ドメイン or `portal`（横断） |
| `action` | ActionKind (enum) | ○ | create/update/delete/control/login/restore 等 |
| `target_kind` | String | ○ | 対象データ種別 |
| `target_id` | String | ○ | 対象ID |
| `result` | Result (success/failure) | ○ | 結果 |
| `ip` | IpAddr | ○ | 送信元IP |
| `detail` | JSON（変更差分等） | 任意 | 詳細。機微値はマスク |
> **追記のみ・改変不可**（更新/削除APIを持たない）。保持期間は 05/設定。

### 3.3 Alert（横断アラート）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `domain` | DomainKey | ○ | 発生元ドメイン |
| `severity` | Severity (critical/warning/info) | ○ | 重大度 |
| `state` | AlertState (open/acknowledged/resolved) | ○ | 状態。既定 open |
| `summary` | String | ○ | 概要 |
| `source_ref` | String | 任意 | 発生対象（host/cert等）への参照 |
| `rule_ref` | ref→AlertRule/MonitorRule | 任意 | 生成元ルール |
| `acknowledged_by`/`resolved_by` | ref→操作者 | 任意 | 状態遷移者 |
| `acknowledged_at`/`resolved_at` | DateTime | 任意 | 状態遷移日時 |
| `suppressed` | bool | ○ | メンテナンス窓等で抑止中か |

### 3.4 NotificationTarget（通知先／連携先）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `name` | String（一意） | ○ | 通知先名 |
| `kind` | NotifyKind (`webhook` / `audit_sink`(SIEM等)) | ○ | 種別。`audit_sink` は監査イベントの外部連携（旧 SSO の監査 Webhook を吸収） |
| `endpoint` | URL | ○ | Webhook URL 等 |
| `min_severity` | Severity | 条件 | アラート通知（`webhook`）で必須。`audit_sink` では不要 |
| `event_filter` | Set<String> | 任意 | `audit_sink` の購読イベント種別（監査アクション等） |
| `signing_secret` | Secret（マスク） | 任意 | 署名シークレット（監査へ値を残さない） |
| `domains` | Set<DomainKey> | 任意 | 対象ドメイン（空=全) |
| `enabled` | bool | ○ | 有効/無効 |
> 旧「各サービス個別の Webhook」（Proxy/SSO 等）は本構造へ**全統合**（方針④）。ドメイン固有の Webhook 画面は持たず、S-Alerts 通知設定（アラート）／S-Audit・S-Settings（監査連携 `audit_sink`）から一元管理する。

### 3.5 Template（定型設定の雛形）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `domain` | DomainKey | ○ | 適用先ドメイン |
| `name` | String（domain内一意） | ○ | テンプレート名 |
| `body` | JSON/YAML | ○ | 適用内容（ドメイン別スキーマ） |
| `description` | String | 任意 | 説明 |

### 3.6 Backup（構成バックアップ）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `domain` | DomainKey or `all` | ○ | 対象 |
| `kind` | BackupKind (manual/auto) | ○ | 種別 |
| `size_bytes` | u64 | ○ | サイズ |
| `artifact_ref` | String | ○ | 実体（BLOB/ファイル）参照 |
| `format_version` | String | ○ | 形式バージョン（リストア互換判定用） |

### 3.7 LocalAccount（ローカルログイン用）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `username` | String（一意） | ○ | ログイン名 |
| `password_hash` | Argon2 hash | ○ | パスワードハッシュ |
| `role` | Role | ○ | RBACロール |
| `enabled` | bool | ○ | 有効/無効 |
| `last_login_at` | DateTime | 任意 | 最終ログイン |
> **ログイン識別**であり、ドメインのユーザ（LDAP/Mail等）とは別物。

### 3.8 Session（ログインセッション）
| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `session_id` | String（Cookie値） | ○ | セッションID |
| `subject` | ref→LocalAccount or SSO subject | ○ | 認証主体 |
| `auth_method` | AuthMethod (local/sso) | ○ | 認証経路 |
| `role` | Role | ○ | 実効ロール |
| `display_name`/`email` | String | 任意 | 表示情報 |
| `sso_tokens` | OidcTokenResponse | 任意 | SSO時のみ（access/refresh/expires） |
| `login_ip` | IpAddr | ○ | ログイン元 |
| `expires_at` | DateTime | ○ | 有効期限 |
> **DB永続化**（設計確定 2026-07-05：再起動耐性）。失効・期限・SSOトークンの扱いは 09。

### 3.9 Role（RBAC）
`enum Role { Viewer, Operator, Admin }`。権限境界は AC-04／各画面の権限節に準拠。

### 3.10 AppConfig（アプリ設定・抜粋）
| 構造 | 主フィールド |
|---|---|
| `AppConfig` | `server` / `sso`（任意） / `domains: Map<DomainKey, DomainConfig>` / `policy` |
| `ServerConfig` | `host` / `port` / `base_url` |
| `SsoConfig` | `issuer_url` / `client_id` / `client_secret` / `redirect_uri` / `scopes` |
| `DomainConfig` | `display_name` / `icon` / `enabled` |
| `PolicyConfig` | `dashboard_refresh_secs` / `retention_days`（監査/ログ） / パスワードポリシー |
> 旧 `ServiceAuthType` / `ProcessConfig` / `api_base_url` 等は**削除**（§1）。実体は 09 の設定/リロード仕様へ。

### 3.11 DomainStatus（運用状態）
| フィールド | 型 | 説明 |
|---|---|---|
| `domain` | DomainKey | 対象 |
| `state` | HealthState (Healthy/Warning/Error/Unknown) | 稼働状態 |
| `metrics` | Map<String, Value> | 主要指標（ドメイン別。例: DNS=ゾーン数/直近クエリ数） |
| `checked_at` | DateTime | 取得時刻 |

### 3.12 LogEntry（運用ログ）
| フィールド | 型 | 説明 |
|---|---|---|
| `domain` | DomainKey or `system` | 発生元 |
| `log_kind` | LogKind (operation/query/access) | ログ種別 |
| `level` | LogLevel (DEBUG/INFO/WARN/ERROR) | レベル |
| `message` | String | 本文 |
| `at` | DateTime | 発生時刻 |
| `meta` | JSON | 付随情報 |
> 監査ログ（AuditEntry）とは別系統（運用/動作ログ）。

## 4. ドメイン別フィールド定義

各ドメインのデータ種別の固有フィールドは、以下のサブドキュメントに定義する（共通フィールド §3.1 を継承、tenant は持たない、監査/アラート/テンプレ/バックアップは §3 を参照）。

- 07_data_dns.md / 07_data_dhcp.md / 07_data_ldap.md / 07_data_mail.md
- 07_data_proxy.md / 07_data_k8s.md / 07_data_sso.md / 07_data_watch.md

## 5. 参照関係マップ

> ここでは横断・基盤の参照を定義する。ドメイン内・ドメイン間の詳細参照は各 07_data_<domain>.md の「参照」節を集約して §5.3 に反映する（Phase 4 仕上げ時）。

### 5.1 参照元 → 参照先（横断）
| 参照元 | 参照先 | 関係 |
|---|---|---|
| AuditEntry.actor / created_by | LocalAccount or SSO subject | 操作者 |
| Alert.rule_ref | AlertRule(K8s) / MonitorRule(Watch) | 生成元ルール |
| Template.domain / Backup.domain / Alert.domain | DomainKey(enum) | 所属ドメイン |
| NotificationTarget.domains | DomainKey(enum) | 対象ドメイン |
| Session.subject | LocalAccount or SSO subject | 認証主体 |

### 5.2 参照先 → 参照元（削除影響の逆引き）
| 参照先 | これを削除/変更する時に再検証する参照元 | 方針 |
|---|---|---|
| LocalAccount | Session（失効）/ AuditEntry（履歴は保持） | アカウント削除で当該Sessionを失効。監査は actor 名を残す（追記不変） |
| MonitorRule/AlertRule | Alert.rule_ref | ルール削除時、生成済み Alert の rule_ref は残す（履歴保持）。以後の生成を停止 |
| DomainKey（ドメイン無効化） | Template/Backup/Alert/NotificationTarget | 無効化ドメインの新規操作を停止（既存データは保持） |

### 5.3 ドメイン内・ドメイン間参照（8ドメイン集約）

**参照元 → 参照先（forward）**

| ドメイン | 参照元 → 参照先 | 関係 |
|---|---|---|
| DNS | Record → Zone / Zone.soa.mname → NS Record | 多対1／整合 |
| DHCP | Reservation → Pool / Lease → Pool | 多対1（Reservation は MAC-IP 1:1） |
| LDAP | Entry・OU → parent_dn / Group.members → User(dn) / AclRule.target_dn・subject → Entry・User・Group / objectClass → Schema | 階層・多対多・参照 |
| Mail | MailUser・Alias・MailingList → MailDomain / Alias.宛先 → MailUser / MailingList.owner → MailUser | 多対1・宛先実在 |
| Proxy | VirtualHost.certificate_ref → Certificate / AclRule.vhost_ref → VirtualHost | TLS必須参照・従属 |
| K8s | Host → Cluster / AlertRule.target_ref → Cluster・Host | 所属・対象 |
| SSO | OidcClient → Provider / SsoSession → Provider・OidcClient・subject | 従属・発行元 |
| Watch | MonitorRule → MonitoredHost / HostGroup.members → MonitoredHost / MaintenanceWindow → Host・Group / Metric → Host | 対象・所属 |
| 横断 | Alert.rule_ref → K8s.AlertRule / Watch.MonitorRule | 生成元ルール（§5.1） |

**参照先 → 参照元（削除影響の逆引き＝削除時に再検証する参照元）**

| 参照先（削除/変更対象） | 再検証する参照元 | 方針（AC整合） |
|---|---|---|
| DNS Zone | Record群 | 配下Recordがあれば確認 `このゾーンには N 件のレコードがあります。まとめて削除しますか？`（AC-13）。承認でカスケード削除 |
| DHCP Pool | Reservation / Active Lease | 使用中の予約・有効リースがあればガード。範囲制約：Pool↔Pool重複禁止 `指定範囲は既存プールと重複しています。`（AC-14）、Reservation.IP は Pool 範囲内かつ一意 |
| LDAP OrgUnit | 配下 Entry / User / OU | 配下ありは削除拒否 `この OU には配下エントリがあります。先に移動または削除してください。`（AC-15）。DN改名は members・AclRule・配下を追従 |
| LDAP Schema | それを使う Entry(objectClass) | 使用中Schemaは削除不可 |
| Mail MailDomain | 所属 MailUser / Alias | 所属ありは削除拒否 `このドメインには N 件のアカウントがあります。`（AC-16）。**改名時は所属 MailUser/Alias のアドレスのドメイン部を追従更新**（または改名不可とする＝実装ポリシー） |
| Mail MailUser | Alias.宛先 / MailingList.owner | 宛先/オーナー参照を再検証。Alias宛先不在は `宛先のアカウントが存在しません。`（AC-16） |
| Proxy Certificate | VirtualHost.certificate_ref | TLS利用中の証明書削除をガード。期限は Certificate.not_after で AC-17 バッジ判定 |
| Proxy VirtualHost | AclRule.vhost_ref | vhost削除で従属AclRuleを連鎖削除 |
| K8s Cluster / Host | Host.cluster_ref / AlertRule.target_ref | クラスタ削除で所属 Host の `cluster_ref` を解除（または削除拒否）、対象ルールを再検証。Host削除で対象ルール/メトリクスを再検証 |
| K8s AlertRule / Watch MonitorRule | 生成済 Alert.rule_ref | ルール削除後も生成済Alertの rule_ref は**保持**（履歴不変）、以後の生成のみ停止（§5.2） |
| SSO Provider / OidcClient | SsoSession | プロバイダ/クライアント/subject 削除で当該 SsoSession を失効（AC-19／AC-05） |
| Watch MonitoredHost | MonitorRule / HostGroup.members / MaintenanceWindow / Metric | ホスト削除で参照ルール・グループ・窓・メトリクスを再検証 |

**優先度・順序を持つ参照**（first-match 評価）
- Proxy: `AclRule.priority` / `IpBlock.order`（昇順・先勝ち、同値は created_at で安定化）。
- LDAP AclRule / Watch MonitorRule も評価順を持つ場合は各 07_data_<domain>.md に従う。

> 弱い参照（式・タグ・名前一致など DBの外部キーにならない参照）が各ドメインにある場合は、当該 07_data_<domain>.md の「参照」節に別掲する。

## 6. 未確定（実装/後続フェーズ送り）
- SSO subject とローカルアカウントの**任意リンク**の要否（現状は非リンク）。
- ドメイン別 `metrics` の具体キー → 各 07_data_<domain>.md／08。
- （解決済）Session は DB永続化（09 §6）。ドメイン実データは単一DBが正＝設定の正＋実デーモン駆動（09 §0/§4）。保持世代・容量は 05 §8。
