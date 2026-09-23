# データモデル：DNS ドメイン（Magnetite 統合再設計版）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| 親ドキュメント | 07_data_model.md（§3 共有構造・§3.1 共通フィールド） |

> 本書は DNS ドメインの**固有フィールド**のみを定義する。以下はハブ規約（07_data_model.md）に従い**再掲・再定義しない**。
> - **共通フィールド**（`id` / `created_at` / `updated_at` / `created_by`）は全エンティティが §3.1 を継承する。
> - `tenant` フィールドは持たない（マルチテナント廃止・単一組込みDBが唯一の正）。
> - 監査は §3.2 `AuditEntry`、アラートは §3.3 `Alert`、通知は §3.4 `NotificationTarget` を参照（DNS 側で再定義しない）。
> - **クエリログ**は §3.12 `LogEntry`（`log_kind = query`）へ吸収する（本書 §4 参照）。
> - **テンプレート**は §3.5 `Template`、**バックアップ**は §3.6 `Backup` を用い、DNS 固有の `body` / 実体スキーマのみ本書 §5・§6 に記す。
> - 稼働状態/統計（旧 `DnsDashboard` / `DnsServerStats`）は §3.11 `DomainStatus` の `metrics` に吸収する（本書では再定義しない）。

## 1. 対象データ種別

| データ種別 | 説明 | 永続 | 定義 |
|---|---|---|---|
| `Zone` | DNS ゾーン（SOA を内包） | ○ | §2 |
| `Record` | ゾーン配下のリソースレコード | ○ | §3 |
| `RpzRule` | RPZ（Response Policy Zone）ルール | ○ | §4 |
| クエリログ | §3.12 `LogEntry`（`log_kind=query`）へ吸収 | ○ | §5 |
| テンプレート | §3.5 `Template`（`domain=dns`）の `body` スキーマ | ○ | §6 |
| バックアップ | §3.6 `Backup`（`domain=dns`）の実体スキーマ | ○ | §7 |

> 旧 `QueryTestRequest` / `QueryTestResult`（クエリテスト）は永続エンティティではなく**リクエスト/レスポンスDTO**のため、本データモデルの対象外（09_runtime_spec 側で扱う）。
> 旧 `AclRule`（ゾーン単位 ACL）は DNS 固有の永続種別として残す場合に §4 に準じて別途定義する（現行スコープでは Zone/Record/RpzRule を主対象とする）。

## 2. Zone（DNS ゾーン）

ゾーンは名前空間の権威境界を表し、SOA を内包する。共通フィールド（§3.1）を継承。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意。FQDN 形式（例 `example.com`）。末尾ドット正規化。RFC1035 ラベル規則 | ゾーン名（ゾーンのапex 名）。 |
| `soa` | `Soa`（埋め込み） | ○ | §2.1 の各制約に従う | SOA レコード情報。 |
| `enabled` | bool | ○ | 既定 `true` | 有効フラグ。無効時は応答対象外。 |

> ゾーンの `id`（§3.1）が `Record.zone` からの参照キーとなる（§8）。NS レコード群はゾーン内の `Record`（`record_type=NS`）として保持し、`soa.mname` がプライマリ NS を指す。

### 2.1 Soa（Zone に埋め込む SOA 情報）

`Zone.soa` として埋め込む値オブジェクト（独立エンティティではないため共通フィールドを持たない）。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `mname` | String | ○ | FQDN。ゾーン内 NS レコードのいずれかと整合させる | プライマリネームサーバー名。 |
| `rname` | String | ○ | ドット表記メール（`@`→`.`）。FQDN 形式 | 管理者メールアドレス。 |
| `serial` | u32 | ○ | 既定 `1`。更新のたびに増加させる（単調増加推奨） | シリアル番号。 |
| `refresh` | u32 | ○ | 秒。既定 `3600`。`> 0` | セカンダリのリフレッシュ間隔。 |
| `retry` | u32 | ○ | 秒。既定 `900`。`> 0`。`< refresh` 推奨 | リフレッシュ失敗時のリトライ間隔。 |
| `expire` | u32 | ○ | 秒。既定 `604800`。`> refresh` | 権威失効までの猶予。 |
| `minimum` | u32 | ○ | 秒。既定 `86400` | ネガティブキャッシュ TTL（最小 TTL）。 |

## 3. Record（リソースレコード）

ゾーン配下の 1 リソースレコード。共通フィールド（§3.1）を継承。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `zone` | ref→Zone.id | ○ | 存在する `Zone` を指す。削除時ガードあり（§8） | 所属ゾーン。 |
| `name` | String | ○ | FQDN。所属ゾーン名でサフィックス一致すること（apex は ゾーン名自身） | レコード名。 |
| `ttl` | u32 | ○ | 秒。既定 `3600` | キャッシュ有効期間。 |
| `record_type` | RecordType (enum) | ○ | §3.1 の許容値 | レコード種別。 |
| `data` | RecordData（種別別）| ○ | `record_type` に対応した構造（§3.2） | レコード値。 |
| `enabled` | bool | ○ | 既定 `true` | 有効フラグ。 |

### 3.1 RecordType（レコード種別 enum）

`A` / `AAAA` / `CNAME` / `MX` / `TXT` / `NS` / `PTR` / `SRV` / `CAA`。

> 制約（型固有）：`CNAME` は同名の他レコードと共存不可（apex への CNAME 禁止）。`NS` はゾーン委任/権威 NS を表す。`SRV` は `_service._proto.name` 命名に従う。

### 3.2 RecordData（`record_type` 別の値スキーマ）

`data` は種別に応じて以下の構造を取る（旧 `build_record_data` 相当）。型付き列挙として保持し、永続層では JSON 表現も許容する。

| 種別 | data 構造 | 主なフィールドと制約 |
|---|---|---|
| `A` | `{ address }` | `address`: IPv4 アドレス。 |
| `AAAA` | `{ address }` | `address`: IPv6 アドレス。 |
| `CNAME` | `{ target }` | `target`: FQDN。 |
| `MX` | `{ preference, exchange }` | `preference`: u16（小さいほど優先）／`exchange`: FQDN。 |
| `TXT` | `{ text }` | `text`: 文字列（255 オクテット境界で分割可）。 |
| `NS` | `{ nsdname }` | `nsdname`: FQDN。 |
| `PTR` | `{ ptrdname }` | `ptrdname`: FQDN（逆引き名）。 |
| `SRV` | `{ priority, weight, port, target }` | `priority`/`weight`: u16、`port`: u16、`target`: FQDN。 |
| `CAA` | `{ flags, tag, value }` | `flags`: u8、`tag`: `issue`/`issuewild`/`iodef` 等、`value`: 文字列。 |
| その他 | `{ value }` | `value`: 文字列（未対応種別のフォールバック）。 |

## 4. RpzRule（RPZ ルール）

Response Policy Zone による応答ポリシー。共通フィールド（§3.1）を継承。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `domain` | String | ○ | 対象ドメイン名（FQDN、ワイルドカード可） | ポリシー適用対象の名前。 |
| `action` | RpzAction (enum) | ○ | §4.1 の許容値 | 応答時のアクション。 |
| `redirect_to` | Option\<String\> | 条件付き必須 | `action = Redirect` の時のみ設定。他アクションでは `None` | リダイレクト先 FQDN/IP。 |
| `enabled` | bool | ○ | 既定 `true` | 有効フラグ。 |

> 注：ここでの `domain` フィールドは RPZ の**対象名（悪性ドメイン名）**であり、§3 の `DomainKey`（Magnetite ドメイン区分）とは別概念。DNS ドメインの `RpzRule` は暗黙に `DomainKey = dns` に属する。

### 4.1 RpzAction（RPZ アクション enum）

| 値 | 意味 |
|---|---|
| `Nxdomain` | 存在しない名前として応答（NXDOMAIN）。 |
| `Nodata` | 名前は存在するが該当型データ無しとして応答（NODATA）。 |
| `Redirect` | `redirect_to` の宛先へ差し替え応答（要 `redirect_to`）。 |
| `Drop` | 応答を返さず破棄。 |

## 5. クエリログ（→ §3.12 LogEntry に吸収）

DNS のクエリ履歴は独立エンティティを持たず、§3.12 `LogEntry` を用いる（`domain = dns`, `log_kind = query`）。旧 `QueryLogEntry` の各値は `LogEntry` の以下へマップする。

| 旧 QueryLogEntry フィールド | LogEntry での格納先 |
|---|---|
| `timestamp` | `at` |
| `query_name` / `query_type` | `message` 本文＋ `meta.query_name` / `meta.query_type` |
| `client_addr` | `meta.client_addr` |
| `response_code`（NOERROR/NXDOMAIN 等） | `meta.response_code`（`level` は失敗系で WARN 等へマップ） |
| `source`（local/cache/forward） | `meta.source` |
| `latency_us` | `meta.latency_us` |

> ダッシュボード統計（total_queries/cache_hits/forwarded/failed 等）は §3.11 `DomainStatus.metrics`（`domain=dns`）へ集約し、本書では再定義しない。

## 6. テンプレート body スキーマ（→ §3.5 Template）

DNS のレコードテンプレートは §3.5 `Template`（`domain = dns`）を用いる。共通メタ（`name` / `description` 等）は §3.5 に従い、DNS 固有の `body` は以下の構造とする。

`body`（DNS テンプレート）:

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `records` | Vec\<TemplateRecord\> | ○ | 1 件以上推奨 | 適用する定型レコード群。 |

`TemplateRecord`（`body.records` の要素）:

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name_suffix` | String | ○ | 適用先ゾーン名に付与するサフィックス（空=apex） | 生成レコード名の相対部分。 |
| `ttl` | u32 | ○ | 秒。既定 `3600` | 生成レコードの TTL。 |
| `record_type` | RecordType | ○ | §3.1 準拠 | 生成レコードの種別。 |
| `data` | RecordData | ○ | §3.2 準拠 | 生成レコードの値。 |

> テンプレートのゾーンへの一括適用は `Record` を生成する操作（旧 `apply_template`）であり、実行意味論は 09_runtime_spec に置く。

## 7. バックアップ実体スキーマ（→ §3.6 Backup）

DNS の構成バックアップは §3.6 `Backup`（`domain = dns`）を用いる。メタ（`kind` / `size_bytes` / `artifact_ref` / `format_version` 等）は §3.6 に従い、`artifact_ref` が指す実体（DNS バックアップ本体）のスキーマは以下とする。

DNS バックアップ実体:

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `zones` | Vec\<Zone\> | ○ | ゾーン一覧。 |
| `records` | Vec\<Record\> | ○ | レコード一覧。 |
| `templates` | Vec\<Template.body(DNS)\> | 任意 | レコードテンプレート一覧。 |
| `rpz_rules` | Vec\<RpzRule\> | 任意 | RPZ ルール一覧。 |
| `acl_rules` | Vec\<AclRule\> | 任意 | ゾーン ACL ルール一覧（採用時）。 |

> リストア（旧 `restore_backup`）は破壊的一括操作のため `Admin` ロール必須（AC-04）。互換判定は §3.6 `format_version` による。

## 8. 参照

### 8.1 ドメイン内参照（参照元 → 参照先）

| 参照元 | 参照先 | 関係 | 備考 |
|---|---|---|---|
| `Record.zone` | `Zone.id` | 各レコードは 1 ゾーンに所属（多対1） | ゾーン名でのサフィックス整合を検証。 |
| `Zone.soa.mname` | `Record`（同ゾーン内 `NS`） | プライマリ NS 名の整合 | mname は権威 NS のいずれかを指すべき。 |
| `Template.body.records[*]` | `Record`（適用時に生成） | テンプレート適用で `Record` を生成 | 生成物であり参照ではない（適用時マテリアライズ）。 |
| `Backup(dns).zones/records/...` | `Zone` / `Record` / `RpzRule` | スナップショット（値のコピー） | 参照ではなく実体複製。 |

### 8.2 削除影響の逆引き（参照先 → 再検証する参照元）

| 参照先（削除/変更対象） | 再検証する参照元 | 方針 |
|---|---|---|
| `Zone` | `Record`（`Record.zone` で当該ゾーンを指す群） | **配下レコードがある場合、削除前に確認**：`このゾーンには N 件のレコードがあります。まとめて削除しますか？`（AC-13）。承認時は**ゾーンと配下レコードを一括削除**（カスケード）。0 件時は通常確認（S-00 E-08）。いずれも監査（§3.2）へ記録。 |
| `Record`（`NS`） | 同ゾーン `Zone.soa.mname` | 権威 NS を削除する場合、`soa.mname` が宙に浮かないよう整合を再検証（少なくとも 1 つの権威 NS を残す）。 |
| `RpzRule` | （ドメイン内参照なし） | 単独削除可。監査（§3.2）へ記録。 |
| DNS ドメイン無効化（`DomainKey=dns`） | §3.5 `Template` / §3.6 `Backup` / §3.3 `Alert` / §3.4 `NotificationTarget`（`domain=dns`） | §5.2（ハブ）に従い、無効化ドメインの**新規操作を停止・既存データは保持**。 |

> クエリログ（§5, `LogEntry`）・監査（§3.2, `AuditEntry`）は追記系で、`Zone`/`Record` 削除時も履歴として保持する（削除連動しない）。

### 8.3 横断参照（ハブ §5 への接続）

- 全 DNS エンティティの `created_by`（§3.1）→ 操作者（`LocalAccount` or SSO subject）。
- DNS 操作の監査 → §3.2 `AuditEntry`（`domain = dns`, `target_kind = Zone/Record/RpzRule`）。
- DNS 由来アラート → §3.3 `Alert`（`domain = dns`）。
- 本書 §8.2 の削除ガードは、ハブ §5.3 の代表例「Zone削除→Record」と整合する。
