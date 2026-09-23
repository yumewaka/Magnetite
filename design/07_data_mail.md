# データモデル：Mail ドメイン（Magnetite 統合再設計版）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| 親ドキュメント | 07_data_model.md（§3 共有構造・§3.1 共通フィールドを継承） |

> 本書は Mail ドメインの**固有フィールド**のみを定義する。
> - **§3.1 共通フィールド（`id`/`created_at`/`updated_at`/`created_by`）は継承し、ここでは再掲しない。**
> - 監査は `AuditEntry`（§3.2）、アラートは `Alert`（§3.3）、テンプレ/バックアップは `Template`/`Backup`（§3.5/§3.6）、運用ログ/状態は `LogEntry`/`DomainStatus`（§3.11/§3.12）を参照。Mail 側に重複定義しない。
> - **tenant は持たない**（単一DB・単一テナント）。
> - **メールユーザ（`MailUser`）はドメイン固有データであり、ポータルのログイン識別（`LocalAccount`, §3.7）とは別物**。`MailUser` でポータルにログインすることはない。
> - `enabled`/`display_name`/`quota` 等の運用フィールドはドメイン固有として本書に定義する（§3.1 の共通4フィールドとは別）。

## 1. 対象データ種別

| データ種別 | 説明 | 定義 |
|---|---|---|
| `MailUser` | メールアカウント（ローカルパート＋所属ドメイン＋クォータ） | §2.1 |
| `MailDomain` | メールドメイン（ドメイン名・上限・既定クォータ） | §2.2 |
| `Alias` | エイリアス（転送元→転送先アドレス群） | §2.3 |
| `MailingList` | メーリングリスト（リストアドレス＋購読メンバー群） | §2.4 |
| `ProtocolConfig` | SMTP/IMAP/POP 系プロトコルの有効状態・ポート | §2.5 |
| `ServerConfig` | メールサーバ全体設定（ホスト名・最大サイズ・ACME 等） | §2.6 |

> 旧 `MailProtocolSettings`（7 プロトコル束）は `ServerConfig.protocols: Map<MailProtocol, ProtocolConfig>` として `ServerConfig` に内包する（§2.5/§2.6）。旧 `MailDashboardStats`/`MailDailyCount`/`MailHealthResponse` は永続エンティティではなく集計・稼働状態であり、`DomainStatus`（§3.11）の `metrics` へ吸収する（本書では種別として定義しない）。

## 2. 固有フィールド定義

### 2.1 MailUser（メールアカウント）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `local_part` | String | ○ | メールローカルパート形式・同一 `domain_ref` 内で一意 | アドレスの `@` より前（例: `alice`） |
| `domain_ref` | ref→MailDomain | ○ | 実在する有効ドメイン | 所属メールドメイン |
| `email` | EmailAddress | ○ | `{local_part}@{MailDomain.name}`・全体で一意（導出可） | 完全なメールアドレス |
| `display_name` | Option\<String\> | 任意 | — | 表示名 |
| `mail_role` | MailRole (enum) | ○ | 既定 `user` | メール上のロール（`user`/`admin` 等。ポータル RBAC の `Role` とは別） |
| `password_hash` | Argon2 hash | ○ | 平文は保持しない | メールログイン用パスワードハッシュ（§3.7 の `LocalAccount` とは無関係） |
| `quota_bytes` | u64 | ○ | 0=無制限。作成時は MB 指定→バイト換算 | 割り当てクォータ（バイト） |
| `used_bytes` | u64 | ○ | 導出値（サービス実測。読み取り専用） | 使用量（バイト） |
| `enabled` | bool | ○ | 既定 `true` | 有効/無効 |

> `email` は `local_part` と `domain_ref`（→`MailDomain.name`）から導出可能。永続化するか導出するかは 09 で確定。

### 2.2 MailDomain（メールドメイン）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | DomainName | ○ | FQDN 形式・全体で一意 | メールドメイン名（例: `example.com`） |
| `enabled` | bool | ○ | 既定 `true` | 有効/無効 |
| `max_users` | Option\<u32\> | 任意 | 1 以上の整数。空=無制限 | 収容可能な最大 `MailUser` 数 |
| `default_quota_bytes` | Option\<u64\> | 任意 | 作成時は MB 指定→バイト換算 | 新規ユーザの既定クォータ |
| `mx_records` | Vec\<MxRecord\> | 任意 | 各要素 `{ host: DomainName, priority: u16 }`。priority 昇順が優先 | 当ドメインの MX（表示/検証用。実配信ゾーンは DNS ドメイン管理） |

> `mx_records` は DNS ドメインの `Zone`/`Record`（07_data_dns.md）と論理的に対応するが、Mail ドメインとしては表示・整合チェック用途で保持する（正の権威は DNS 側）。実装で重複を避ける場合は導出参照とする（09 で確定）。

### 2.3 Alias（エイリアス）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `source_address` | EmailAddress | ○ | メールアドレス形式・全体で一意（既存 `MailUser.email` と重複不可） | 転送元アドレス（`@` の左が `domain_ref` に属する） |
| `domain_ref` | ref→MailDomain | ○ | 実在する有効ドメイン | 所属メールドメイン |
| `destination_addresses` | Vec\<EmailAddress\> | ○ | 1 件以上・各要素メール形式。各要素は実在する `MailUser.email` を指すこと | 転送先アドレス群（宛先） |
| `enabled` | bool | ○ | 既定 `true` | 有効/無効 |

> 転送先の実在制約は AC-16／S-MAIL-04 に準拠。存在しない宛先を含む作成/更新は拒否し `宛先のアカウントが存在しません。` を該当フィールド直下に表示する。

### 2.4 MailingList（メーリングリスト）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `address` | EmailAddress | ○ | メールアドレス形式・全体で一意 | リストの受信アドレス |
| `domain_ref` | ref→MailDomain | ○ | 実在する有効ドメイン | 所属メールドメイン |
| `name` | String | ○ | — | リスト名 |
| `description` | Option\<String\> | 任意 | — | 説明 |
| `owner_ref` | ref→MailUser | ○ | 実在する `MailUser` | リストオーナー |
| `members` | Vec\<MailingListMember\> | ○ | 空可。要素は §2.4.1 | 購読メンバー群 |
| `reply_policy` | ReplyPolicy (enum) | ○ | 既定 `list`（`list`/`sender`/`both` 等） | 返信先ポリシー |
| `enabled` | bool | ○ | 既定 `true` | 有効/無効 |

#### 2.4.1 MailingListMember（購読者・埋め込み値）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `email` | EmailAddress | ○ | メール形式・同一リスト内で一意 | メンバーのメールアドレス（外部アドレス可） |
| `name` | Option\<String\> | 任意 | — | メンバー表示名 |
| `receive` | bool | ○ | 既定 `true` | 配信を受信するか |
| `can_post` | bool | ○ | 既定 `true` | リスト宛に投稿できるか |

> メンバーの `email` は必ずしも `MailUser` 実在を要さない（外部購読者を許容）。宛先実在必須の `Alias` とは制約が異なる。

### 2.5 ProtocolConfig（プロトコル設定・埋め込み値）

`ServerConfig.protocols: Map<MailProtocol, ProtocolConfig>` の値。`MailProtocol` は次の 7 種を列挙する。

`enum MailProtocol { Smtp, SmtpSubmission, Smtps, Imap, Imaps, Pop3, Pop3s }`

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `enabled` | bool | ○ | — | プロトコルの有効/無効 |
| `port` | u16 | ○ | 1〜65535・`protocols` 内で他プロトコルと重複不可 | リッスンポート番号 |

> 標準ポート参考: SMTP=25 / Submission=587 / SMTPS=465 / IMAP=143 / IMAPS=993 / POP3=110 / POP3S=995。ポート検証は S-MAIL-06（`1〜65535 の数値を入力してください。` / `ポートが他プロトコルと重複しています。`）に準拠。

### 2.6 ServerConfig（メールサーバ全体設定）

サーバ全体で 1 件（シングルトン）。プロトコル束を内包する。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `hostname` | DomainName | ○ | FQDN 形式 | メールサーバのホスト名（HELO/EHLO 名） |
| `max_message_size_bytes` | u64 | ○ | 1 以上 | 1 通あたり最大メッセージサイズ（バイト） |
| `protocols` | Map\<MailProtocol, ProtocolConfig\> | ○ | 7 種すべてを含む。ポートは全体で一意（§2.5） | プロトコル別設定（旧 `MailProtocolSettings` を内包） |
| `acme_enabled` | bool | ○ | 既定 `false` | ACME（Let's Encrypt 等）自動証明書取得の有効/無効 |
| `acme_email` | Option\<String\> | 任意 | `acme_enabled=true` のとき必須・メール形式 | ACME 連絡先メールアドレス |
| `acme_domains` | Vec\<DomainName\> | 任意 | 各要素 FQDN。`acme_enabled=true` のとき 1 件以上 | ACME 対象ドメイン一覧 |

## 3. 参照

### 3.1 参照元 → 参照先（Mail ドメイン内）

| 参照元 | 参照先 | 関係 | 制約 |
|---|---|---|---|
| `MailUser.domain_ref` | `MailDomain` | 所属（N:1） | 実在する有効ドメイン必須。ドメイン削除は §3.2 のガード対象 |
| `Alias.domain_ref` | `MailDomain` | 所属（N:1） | 同上 |
| `Alias.destination_addresses[]` | `MailUser.email` | 転送先（宛先。N:M） | **各宛先は実在する `MailUser` を指すこと**（AC-16） |
| `MailingList.domain_ref` | `MailDomain` | 所属（N:1） | 実在する有効ドメイン必須 |
| `MailingList.owner_ref` | `MailUser` | オーナー（N:1） | 実在必須 |
| `MailingList.members[].email` | （外部アドレス可） | 購読者 | 実在制約なし（外部購読者を許容） |
| `ServerConfig.protocols[].port` | （他プロトコル） | ポート占有 | `protocols` 内で一意（重複不可） |

### 3.2 参照先 → 参照元（削除影響の逆引き）

| 参照先（削除/変更対象） | 再検証する参照元 | 方針・整合するメッセージ |
|---|---|---|
| `MailDomain` | `MailUser.domain_ref` / `Alias.domain_ref` / `MailingList.domain_ref` | **所属アカウント（`MailUser`／`Alias`）が 1 件以上あれば削除を拒否**。`このドメインには N 件のアカウントがあります。`（AC-16／S-MAIL-03 E-M04）。N=0 のときのみ削除実行 |
| `MailUser`（宛先として） | `Alias.destination_addresses[]` | Alias 作成/更新時に宛先実在を検証。不在を含めば保存せず該当フィールドに `宛先のアカウントが存在しません。`（AC-16／S-MAIL-04 E-M03） |
| `MailUser`（オーナー/購読として） | `MailingList.owner_ref` / `MailingList.members[].email` | オーナー削除時はリストのオーナー再設定を要求（09 で確定）。members の外部アドレスは影響なし |
| `MailUser` 削除時 | 当該ユーザを宛先に含む `Alias` | 宛先集合から除去または Alias を要再検証（残宛先 0 件なら Alias 無効化。09 で確定） |
| `MailDomain.name` 変更 | 配下 `MailUser.email` / `Alias.source_address` / `MailingList.address` / `ServerConfig.acme_domains` | ドメイン名変更は配下アドレスの再計算・整合再検証を伴う（原則リネーム非推奨。09 で確定） |
| `MailProtocol` ポート変更 | 他 `ProtocolConfig.port` | 重複時は保存拒否 `ポートが他プロトコルと重複しています。`（S-MAIL-06） |

### 3.3 ドメイン外参照

| 参照元 | 参照先 | 関係 |
|---|---|---|
| `MailDomain.mx_records` / `ServerConfig.acme_domains` | DNS `Zone`/`Record`（07_data_dns.md） | 論理対応（正の権威は DNS 側）。表示・整合チェック用途 |
| 監査/アラート/状態/ログ | `AuditEntry`(§3.2)/`Alert`(§3.3)/`DomainStatus`(§3.11)/`LogEntry`(§3.12) | `domain = DomainKey::Mail` で区別して参照（Mail 側に重複定義しない） |

## 4. 未確定（09/後続へ送り）

- `MailUser.email` を永続化するか `local_part`＋`domain_ref` から導出するか。
- `MailDomain.mx_records` を保持するか DNS から導出参照するか（重複回避）。
- `MailUser` 削除時の `Alias` 宛先・`MailingList` オーナーのカスケード意味論（無効化/再設定/拒否）。
- `MailDomain.name` リネーム可否と配下アドレス再計算方針。
