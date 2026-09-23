# データモデル：Watch（監視）ドメイン

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| ハブ | 07_data_model.md（§3 共有構造・規約） |

> 本書は Watch ドメインの**固有フィールド**のみを定義する。
> **共通フィールド（`id`/`created_at`/`updated_at`/`created_by`）はハブ §3.1 を継承し再掲しない。** `tenant` は持たない（単一DBが正）。
> **アラート本体はハブ §3.3 `Alert`（open/acknowledged/resolved）を唯一の正とする。** Watch 側は Alert を**生成する側**の `MonitorRule` を定義する（アラートの状態・確認/解決・重大度・抑止フラグは §3.3 に集約、ここでは持たない）。
> **通知**はハブ §3.4 `NotificationTarget` を参照（Watch 側に固有の通知先は持たない）。
> **監査**はハブ §3.2 `AuditEntry`、**運用/メトリクス系ログ**は §3.12 `LogEntry` を参照する（Watch 固有の監査ログ種別は持たない）。

対象データ種別：**MonitoredHost / MonitorRule / HostGroup / MaintenanceWindow / Metric**。

---

## 1. MonitoredHost（監視対象ホスト）

監視対象となるサーバ（ホスト）。アドレスと稼働状態を持つ。

| 名 | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | ホスト表示名 |
| `ip_address` | IpAddr | ○ | 有効な IPv4/IPv6 | 監視対象アドレス |
| `hostname` | String | 任意 | FQDN 形式 | ホスト名（FQDN 等） |
| `description` | String | 任意 | | 説明 |
| `host_type` | HostType (enum) | ○ | 既定 `server` | ホスト種別（server 等） |
| `status` | HostStatus (enum) | ○ | `online`/`offline`/`warning`/`unknown`、既定 `unknown` | 稼働状態（監視結果で更新） |
| `os_type` | String | 任意 | | OS 種別 |
| `agent_version` | String | 任意 | | 監視エージェントのバージョン |
| `snmp_enabled` | bool | ○ | 既定 `false` | SNMP 監視の有効/無効 |
| `last_seen` | DateTime(UTC) | 任意 | | 最終応答日時（監視で更新） |
| `tags` | Set\<String\> | 任意 | | タグ一覧 |

> `status` / `last_seen` は監視処理により更新される派生状態（実行意味論は 09）。

---

## 2. MonitorRule（監視ルール ＝ Alert 生成側）

対象ホスト（または全体）に対し、メトリクスの閾値超過で **ハブ §3.3 `Alert` を生成する**ルール。
生成された Alert 側は `Alert.rule_ref` で本ルールを参照し、`Alert.domain = watch`、確認/解決/抑止は §3.3 側で管理する。

| 名 | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | | ルール名 |
| `target_host` | ref→MonitoredHost | 任意 | 未指定=全ホスト対象 | 対象ホスト（null で全体ルール） |
| `metric` | MetricKey (enum) | ○ | `cpu_percent`/`memory_percent`/`disk_percent`/`net_rx`/`net_tx` 等 | 評価対象メトリクス |
| `warning_threshold` | f64 | 任意 | warning≤critical（同方向時） | 警告閾値（Severity=warning のAlert生成境界） |
| `critical_threshold` | f64 | 任意 | | 危険閾値（Severity=critical のAlert生成境界） |
| `severity` | Severity (critical/warning/info) | ○ | §3.3 と同一 enum | 生成するアラートの重大度（閾値別に決定／既定重大度） |
| `eval_interval_secs` | u32 | ○ | > 0、既定 60 | 評価間隔（秒） |
| `enabled` | bool | ○ | 既定 `true` | ルールの有効/無効 |

> 少なくとも `warning_threshold` または `critical_threshold` の一方は指定必須（09 で検証）。
> 本ルールが生成する Alert 本体（状態・確認者・解決日時・発生回数・runbook 等）は**ハブ §3.3 に持ち、ここでは重複定義しない**。

---

## 3. HostGroup（ホストグループ）

複数ホストを論理的にまとめる集合。

| 名 | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | グループ名 |
| `description` | String | 任意 | | 説明 |
| `members` | Set\<ref→MonitoredHost\> | ○ | 各要素は実在ホスト | 所属ホストの集合 |

> `members` は MonitoredHost への参照集合。ホスト削除時の扱いは §6 参照。

---

## 4. MaintenanceWindow（メンテナンス窓）

計画停止期間。期間中は対象ホストに紐づく Alert を抑止する（**AC-20 `メンテナンス中`**）。

| 名 | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | | メンテナンス名 |
| `target_host` | ref→MonitoredHost | 任意 | `target_host`/`target_group` の少なくとも一方 | 対象ホスト |
| `target_group` | ref→HostGroup | 任意 | 同上 | 対象グループ（配下ホストへ展開） |
| `reason` | String | 任意 | | 理由 |
| `starts_at` | DateTime(UTC) | ○ | `starts_at` < `ends_at` | 開始日時 |
| `ends_at` | DateTime(UTC) | ○ | 同上 | 終了日時 |

> **AC-20（抑止）**：`starts_at ≤ now ≤ ends_at` の間、対象ホスト（`target_group` 指定時はその配下ホスト）に対する MonitorRule 由来の Alert 生成を抑止し、既存 open Alert は §3.3 `Alert.suppressed = true` として `メンテナンス中` を表す。窓終了で抑止解除（評価再開）。抑止の実行意味論は 09。

---

## 5. Metric（メトリクス時系列）

ホストから収集したリソース使用状況の時系列サンプル。MonitorRule の評価入力。

| 名 | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `host_ref` | ref→MonitoredHost | ○ | 実在ホスト | 対象ホスト |
| `name` | MetricKey (enum) | ○ | MonitorRule.metric と同一空間 | メトリクス名（cpu_percent 等） |
| `value` | f64 | ○ | | 測定値（単位はメトリクス依存：% / bytes 等） |
| `timestamp` | DateTime(UTC) | ○ | | 測定時刻 |

> 時系列は `(host_ref, name, timestamp)` を軸とする追記系サンプル。保持期間は 05/設定。
> 集約系（CPU/メモリ/ディスク/ネットワークを1レコードにまとめる収集形態）を採る場合も、論理モデルは name/value/timestamp の系列として扱う。

---

## 6. 参照

### 6.1 参照元 → 参照先

| 参照元 | 参照先 | 関係 | 備考 |
|---|---|---|---|
| `MonitorRule.target_host` | MonitoredHost | 監視対象（null=全体） | |
| `HostGroup.members` | MonitoredHost | 集合メンバ | 多対多 |
| `MaintenanceWindow.target_host` | MonitoredHost | 抑止対象ホスト | |
| `MaintenanceWindow.target_group` | HostGroup | 抑止対象グループ（配下ホストへ展開） | |
| `Metric.host_ref` | MonitoredHost | 測定元ホスト | |
| `Alert.rule_ref`（ハブ §3.3） | MonitorRule | 生成元ルール | `Alert.domain = watch` |
| `Alert.source_ref`（ハブ §3.3） | MonitoredHost | 発生対象ホスト | 任意 |

### 6.2 参照先 → 参照元（削除影響の逆引き）

| 参照先 | 削除/変更時に再検証する参照元 | 方針 |
|---|---|---|
| MonitoredHost | MonitorRule.target_host / HostGroup.members / MaintenanceWindow.target_host / Metric.host_ref / Alert.source_ref | ホスト削除時、参照する MonitorRule・HostGroup メンバ・MaintenanceWindow を再検証（対象消失を除去 or 削除ガード）。生成済 Alert の `source_ref` は履歴として保持。時系列 Metric は保持または保持期間に従い整理（09/05）。 |
| MonitorRule | **Alert.rule_ref（ハブ §3.3）** | **ルール削除時、生成済み Alert は保持し `rule_ref` を残す（履歴保持）＝ハブ §5.2 準拠。以後の Alert 生成を停止。** |
| HostGroup | MaintenanceWindow.target_group | グループ削除時、当該グループを対象とする MaintenanceWindow を再検証（対象消失を除去 or 削除ガード）。グループ削除は所属 MonitoredHost 自体には影響しない。 |
| MaintenanceWindow | Alert.suppressed（ハブ §3.3） | 窓削除/失効で抑止を解除（`suppressed` を再評価）。過去に抑止された Alert 履歴は保持。 |

> 監査（AuditEntry §3.2）・通知（NotificationTarget §3.4）・アラート状態遷移（Alert §3.3）は横断共有構造に従い、本ドメインでは重複定義しない。
