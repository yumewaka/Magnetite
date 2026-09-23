# データモデル：Proxy ドメイン（Magnetite 統合再設計版）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| 親ハブ | [07_data_model.md](07_data_model.md) |

> 本書は Proxy ドメインの**固有フィールド**のみを定義する。
> - 共通フィールド（`id`/`created_at`/`updated_at`/`created_by`）は §3.1 を**継承**し再掲しない。
> - 監査は §3.2 AuditEntry、アラートは §3.3 Alert、**通知（旧 ProxyWebhook）は §3.4 NotificationTarget へ統合済**（本書で Webhook 種別は定義しない）。
> - `tenant` フィールドは持たない（単一 DB が唯一の正）。
> - **アクセスログ（旧 ProxyAccessLog）は §3.12 LogEntry（`log_kind=access`）へ吸収**（本書で独立種別は定義しない。§参照 3 を見よ）。
> - 統計/ヘルス（旧 ProxyStats/ProxyHealthStatus）は §3.11 DomainStatus（`domain=proxy` の `metrics`）へ吸収。

## 1. データ種別一覧

| データ種別 | 説明 | 定義 |
|---|---|---|
| `VirtualHost` | 仮想ホスト（vhost）。ホスト名・リッスンポート・upstream・TLS 設定 | §2.1 |
| `Certificate` | TLS サーバ証明書。有効期限・発行者・SAN | §2.2 |
| `AclRule` | アクセス制御ルール（CIDR 一致 → 許可/拒否）。優先度付き | §2.3 |
| `IpBlock` | IP ブロックリストのエントリ（CIDR 単位の遮断）。優先度付き | §2.4 |
| アクセスログ | §3.12 LogEntry（`log_kind=access`）を参照（本書で独立定義しない） | §3参照 |

## 2. 固有フィールド定義

### 2.1 VirtualHost（仮想ホスト）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `hostname` | String | ○ | 一意（大小無視）。FQDN 形式 | 受け付けるホスト名（vhost 名） |
| `listen_port` | u16 | ○ | 1–65535。既定 80 | リッスンポート |
| `upstream` | Vec\<Upstream\> | ○ | 1 件以上 | 転送先（バックエンド）群。§2.1.1 |
| `tls_enabled` | bool | ○ | 既定 false | TLS 終端の有効/無効 |
| `certificate_ref` | ref→Certificate | 任意※ | `tls_enabled=true` の時は必須 | 使用する TLS 証明書（§2.2） |
| `force_https` | bool | ○ | 既定 false | HTTP→HTTPS 強制リダイレクト |
| `proxy_mode` | ProxyMode (enum) | ○ | `Http`/`Https`/`Tcp` 等。既定 `Http` | プロキシモード |
| `lb_strategy` | LbStrategy (enum) | ○ | `RoundRobin`/`LeastConn`/`IpHash` 等。既定 `RoundRobin` | ロードバランス戦略 |
| `enabled` | bool | ○ | 既定 true | 有効/無効 |

※ `certificate_ref` は `tls_enabled=false` の場合 null 可。`tls_enabled=true` かつ未設定は不正。

#### 2.1.1 Upstream（VirtualHost 内包・値型）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `host` | String | ○ | ホスト名 or IP | 転送先ホスト |
| `port` | u16 | ○ | 1–65535 | 転送先ポート |
| `weight` | u16 | 任意 | 既定 1 | LB 重み（`RoundRobin` 等で使用） |
| `scheme` | UpstreamScheme (enum) | 任意 | `Http`/`Https`。既定 `Http` | バックエンド接続スキーム |

### 2.2 Certificate（TLS 証明書）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | 証明書名（表示・参照キー） |
| `subject` | String | ○ | — | サブジェクト（CN 等） |
| `issuer` | String | ○ | — | **発行者**（Issuer DN / CA 名） |
| `san` | Vec\<String\> | ○ | 0 件以上 | **SAN**（Subject Alternative Names。DNS 名/IP） |
| `serial` | String | 任意 | — | シリアル番号 |
| `fingerprint_sha256` | String | 任意 | 16進 | 証明書フィンガープリント（重複検出用） |
| `not_before` | DateTime(UTC) | ○ | — | 有効期間開始日時 |
| `not_after` | DateTime(UTC) | ○ | `>= not_before` | **有効期限**（期間終了日時）。**AC-17 期限バッジの判定基準**※ |
| `cert_pem` | PEM | ○ | 機微。マスク表示 | サーバ証明書本体（PEM） |
| `chain_pem` | PEM | 任意 | — | 中間証明書チェーン（PEM） |
| `key_present` | bool | ○ | — | 秘密鍵の保持有無（鍵 PEM 実体は表示しない） |

※ **AC-17 期限バッジ**：`not_after` を現在時刻と比較して算出する（永続フィールドは `not_after` のみ、バッジ状態は導出値）。
> - `now >= not_after` → `期限切れ`
> - `not_after - now <= しきい値`（既定 30 日。しきい値は PolicyConfig / 09 で確定） → `まもなく期限切れ`
> - それ以外 → 通常（バッジ無し）
>
> 期限接近/切れ時のアラートは §3.3 Alert（`domain=proxy`, `source_ref`=当該 Certificate）として生成する。

### 2.3 AclRule（アクセス制御ルール）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `cidr` | CIDR (String) | ○ | IPv4/IPv6 CIDR 表記 | **一致条件**（送信元 IP レンジ） |
| `action` | AclAction (enum) | ○ | `Allow`/`Deny` | **許可/拒否**の判定 |
| `scope` | AclScope (enum) | ○ | `Global`/`Vhost`。既定 `Global` | 適用範囲 |
| `vhost_ref` | ref→VirtualHost | 任意※ | `scope=Vhost` の時は必須 | 適用対象 vhost（§2.1） |
| `priority` | i32 | ○ | 既定 0。**小さいほど先に評価**（`order`） | **優先度**。同値時は `created_at` 昇順で安定化 |
| `enabled` | bool | ○ | 既定 true | 有効/無効 |
| `description` | String | 任意 | — | 説明 |

※ `scope=Global` の時 `vhost_ref` は null。`scope=Vhost` かつ未設定は不正。
> 評価は `priority` 昇順で最初に一致した `action` を採用（first-match）。`Global` と `Vhost` の評価順序・既定動作（暗黙 Allow/Deny）は 09 実行意味論で確定。

### 2.4 IpBlock（IP ブロックリスト）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `cidr` | CIDR (String) | ○ | IPv4/IPv6 CIDR 表記。一意推奨 | **ブロック対象**の IP レンジ |
| `reason` | String | 任意 | — | ブロック理由 |
| `order` | i32 | ○ | 既定 0。小さいほど先に評価 | **優先度**（評価順） |
| `expires_at` | DateTime(UTC) | 任意 | null=無期限 | **失効日時**。到達で自動的に無効化 |
| `enabled` | bool | ○ | 既定 true | 有効/無効 |

> IpBlock は AclRule より前段の粗いブロックとして機能する（両者の適用順序は 09 で確定）。

## 3. 参照（§参照）

### 3.1 参照元 → 参照先

| 参照元 | 参照先 | 関係 | 備考 |
|---|---|---|---|
| `VirtualHost.certificate_ref` | `Certificate`（§2.2） | vhost が使用する TLS 証明書 | `tls_enabled=true` 時必須 |
| `AclRule.vhost_ref` | `VirtualHost`（§2.1） | vhost スコープ ACL の適用対象 | `scope=Vhost` 時必須 |
| `Certificate` 期限接近/切れ | `Alert`（§3.3, `domain=proxy`） | `source_ref`=Certificate。AC-17 と連動 | 生成元 |
| （アクセスログ） | `LogEntry`（§3.12, `log_kind=access`, `domain=proxy`） | client_ip/method/host/path/status/bytes/duration は `meta` に格納 | 独立種別を持たない |
| 統計/ヘルス | `DomainStatus`（§3.11, `domain=proxy`） | vhosts_count/certs_count/接続数等は `metrics` | 独立種別を持たない |
| 通知（旧 Webhook） | `NotificationTarget`（§3.4） | Proxy 固有 Webhook は持たず横断通知先へ統合 | §1 方針 |

### 3.2 参照先 → 参照元（削除影響の逆引き）

| 参照先（削除/変更対象） | 再検証する参照元 | 方針 |
|---|---|---|
| `Certificate` | `VirtualHost.certificate_ref`（`tls_enabled=true`） | 参照中の証明書は**削除ガード**。使用 vhost があれば削除拒否、または vhost を先に無効化/差し替え |
| `VirtualHost` | `AclRule.vhost_ref`（`scope=Vhost`）／アクセスログ（LogEntry, host 一致） | vhost 削除時、紐づく `Vhost` スコープ ACL を連鎖削除 or 孤立警告。LogEntry（履歴）は保持 |
| `AclRule` / `IpBlock` | — | 参照される側ではない。削除は即時。評価順（`priority`/`order`）の欠番は許容（再採番不要） |

### 3.3 優先度・評価順（order）

| 種別 | 優先度フィールド | 意味 | 同値時 |
|---|---|---|---|
| `AclRule` | `priority` (i32) | 昇順評価・first-match。小さいほど先 | `created_at` 昇順で安定化 |
| `IpBlock` | `order` (i32) | 昇順評価。小さいほど先 | `created_at` 昇順で安定化 |

> IpBlock（前段の遮断）→ AclRule（許可/拒否）の全体評価順序、Global/Vhost ACL の合成、既定アクションは 09 実行意味論で確定する。

## 4. 未確定（後続フェーズ送り）

- AC-17 期限バッジの「まもなく期限切れ」しきい値（既定 30 日）の確定先 → PolicyConfig / 09。
- IpBlock と AclRule の総合評価順・既定アクション（暗黙 Allow/Deny）→ 09。
- upstream ヘルスチェック仕様（能動監視の有無）→ 09 / DomainStatus の metrics 定義。
