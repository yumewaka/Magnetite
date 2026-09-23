# データモデル：DHCP ドメイン（Magnetite 統合再設計版）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| ハブ | [07_data_model.md](07_data_model.md)（規約・共有構造） |

> 本書は DHCP ドメインの**データ種別の固有フィールド**を定義する。
> **共通フィールド（`id`/`created_at`/`updated_at`/`created_by`）は §3.1 を継承し、再掲しない。**
> **監査（AuditEntry §3.2）／アラート（Alert §3.3）／テンプレート（Template §3.5）／バックアップ（Backup §3.6）／通知（NotificationTarget §3.4）は横断共有構造（§3）を参照**し、本書では定義しない。
> **tenant フィールドは持たない**（マルチテナント廃止）。**単一組込みDBが唯一の正**。
> 実行意味論（リース払い出し／期限判定／状態遷移などの実行時ルール）は 09_runtime_spec に分離。

対象データ種別：**Pool**（アドレス配布範囲）／**Reservation**（固定割当）／**Lease**（払い出し）／**DhcpConfig**（サーバー設定）。

---

## 1. Pool（アドレスプール）

DHCP がアドレスを払い出す配布範囲。IPv4/IPv6 いずれか一方または両方の範囲を保持する。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意（ドメイン内） | プール名。UI から表示・識別に使用 |
| `subnet_v4` | CIDR (String) | 任意 | 例 `192.168.1.0/24`。IPv4 レンジ指定時は必須 | IPv4 サブネット |
| `range_start_v4` | Ipv4Addr | 任意 | `subnet_v4` 内。`<= range_end_v4` | IPv4 配布開始アドレス |
| `range_end_v4` | Ipv4Addr | 任意 | `subnet_v4` 内。`>= range_start_v4` | IPv4 配布終了アドレス |
| `subnet_v6` | CIDR (String) | 任意 | 例 `2001:db8::/64`。IPv6 レンジ指定時は必須 | IPv6 サブネット |
| `range_start_v6` | Ipv6Addr | 任意 | `subnet_v6` 内。`<= range_end_v6` | IPv6 配布開始アドレス |
| `range_end_v6` | Ipv6Addr | 任意 | `subnet_v6` 内。`>= range_start_v6` | IPv6 配布終了アドレス |
| `gateway` | IpAddr | 任意 | サブネット内 | 配布するデフォルトゲートウェイ |
| `dns_servers` | Vec\<IpAddr\> | 任意 | 空可 | 配布する DNS サーバー一覧（DHCP オプション） |
| `domain_name` | String | 任意 | — | 配布するドメイン名（DHCP オプション） |
| `lease_duration_secs` | u32 | 任意 | `> 0`。未指定時は `DhcpConfig.default_lease_secs` を適用 | 当プールのリース期間（秒） |
| `enabled` | bool | ○ | 既定 `true` | プール有効フラグ（無効時は新規払い出しを停止） |

> IPv4/IPv6 のいずれか少なくとも一方のレンジ（`range_start_*`/`range_end_*`）が定義されていること。
> アドレス範囲は既存プールと重複してはならない（**AC-14**、§4 参照節を参照）。

---

## 2. Reservation（固定割当）

特定 MAC アドレスへ IP を固定的に割り当てる予約。所属プールに紐付く。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `pool_ref` | ref→Pool | ○ | 存在する Pool。削除時ガードあり（§4） | 所属プール |
| `mac_address` | MacAddr (String) | ○ | 正規化 `aa:bb:cc:dd:ee:ff`。プール内で一意 | 対象クライアントの MAC アドレス |
| `ip_address` | IpAddr | ○ | 所属プールのサブネット内で一意。**Pool の配布範囲と MAC-IP を1:1で固定紐付け** | 固定で割り当てる IP アドレス |
| `hostname` | String | 任意 | — | ホスト名 |
| `description` | String | 任意 | — | 説明 |

> **MAC-IP 紐付け**：`(mac_address, ip_address)` は当該予約の主対応。同一プール内で `mac_address` と `ip_address` はそれぞれ一意（同一 MAC への二重予約・同一 IP の二重予約を禁止）。
> `ip_address` は所属プールのサブネット範囲に収まること（配布レンジ内／外は 09 の運用ポリシーに従う）。

---

## 3. Lease（リース）

DHCP が実際に払い出した／払い出し中のアドレス割当。運用時に生成・更新される動的レコード。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `pool_ref` | ref→Pool | ○ | 存在する Pool | 払い出し元プール |
| `ip_address` | IpAddr | ○ | プールのサブネット内。アクティブ時は一意 | 払い出された IP アドレス |
| `mac_address` | MacAddr (String) | 任意 | 正規化形式 | クライアント MAC（client_id に含まれる場合あり） |
| `client_id` | String/JSON | 任意 | — | クライアント識別子（DUID/MAC 等） |
| `hostname` | String | 任意 | — | クライアントのホスト名 |
| `state` | LeaseState (enum) | ○ | `Active`/`Offered`/`Expired`/`Released` | リース状態 |
| `lease_start` | DateTime(UTC) | ○ | — | リース開始日時 |
| `lease_expiry` | DateTime(UTC) | ○ | `> lease_start`。`Active` は現在時刻 `< lease_expiry` | リース有効期限（**期限切れ判定の基準**） |
| `last_renewal` | DateTime(UTC) | 任意 | — | 最終更新（RENEW）日時 |
| `protocol_version` | ProtoVer (enum) | ○ | `V4`/`V6` | プロトコルバージョン |

> `state`：`Offered`（OFFER 済み未確定）→ `Active`（ACK 確定・有効）→ `Expired`（`lease_expiry` 経過）／`Released`（RELEASE 明示解放）。状態遷移の実行意味論は 09。
> **アクティブ制約**：同一 `ip_address` に対し `state = Active` のリースは同時に1件のみ。

---

## 4. DhcpConfig（サーバー設定）

DHCP サービスのサーバー全体設定（単一インスタンス設定）。プールを跨ぐ既定値・機能フラグを保持。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `v4_enabled` | bool | ○ | 既定 `true` | IPv4 DHCP を有効化 |
| `v6_enabled` | bool | ○ | 既定 `false` | IPv6 DHCP を有効化 |
| `default_lease_secs` | u32 | ○ | `> 0` | プール未指定時の既定リース期間（秒） |
| `max_lease_secs` | u32 | 任意 | `>= default_lease_secs` | リース期間の上限 |
| `default_dns_servers` | Vec\<IpAddr\> | 任意 | 空可 | プール未指定時に配布する既定 DNS サーバー |
| `default_domain_name` | String | 任意 | — | プール未指定時に配布する既定ドメイン名 |
| `authoritative` | bool | ○ | 既定 `true` | 当サーバーがサブネットの権威か（NAK 挙動に影響） |
| `raw` | JSON | 任意 | — | サービス実体設定の生 JSON（参照/リロード対象・09） |

> 設定のリロード（ホットリロード）・永続化要否は 09_runtime_spec に従う。
> ダッシュボード統計（server_stats/utilization/lease_counts 等）は**運用状態**であり永続データ種別ではない。`DomainStatus.metrics`（§3.11）／`LogEntry`（§3.12）へ集約する。

---

## 5. 参照

### 5.1 参照元 → 参照先

| 参照元 | 参照先 | 関係 | 説明 |
|---|---|---|---|
| Reservation.pool_ref | Pool | 多対1 | 固定割当は必ずいずれかのプールに所属 |
| Lease.pool_ref | Pool | 多対1 | リースは払い出し元プールを参照 |
| Reservation.(mac_address, ip_address) | ― | 1:1 紐付け | MAC と IP の固定対応（プール内で各々一意） |

> 監査/アラート/テンプレ/バックアップ/通知は §3 の横断共有構造を `domain = dhcp` として参照（本書で個別定義しない）。

### 5.2 参照先 → 参照元（削除影響の逆引き）

| 参照先（削除/変更対象） | 再検証する参照元 | 方針 |
|---|---|---|
| Pool | Reservation（`pool_ref`） / Lease（`pool_ref`） | 配下に Reservation または Active な Lease が存在する場合、プール削除を**ガード**（拒否 or 明示的なカスケード）。削除可否と払い出し済みリースの扱いは 09 に従う |
| Pool のアドレス範囲変更 | 既存 Reservation.ip_address / Active Lease.ip_address | 範囲外となる予約・リースを再検証（範囲外化の可否は 09） |
| Reservation | 対応する Active Lease | 予約削除後、固定割当由来のリースは通常払い出しへ移行（実行意味論は 09） |

### 5.3 制約：アドレス範囲重複（AC-14）

- **Pool ↔ Pool**：新規作成・更新時、指定した配布範囲（`range_start_*`〜`range_end_*` / `subnet_*`）が**既存プールの配布範囲と重複してはならない**。
  - 違反時メッセージ：`指定範囲は既存プールと重複しています。`（AC-14）
- **Pool ↔ Reservation**：Reservation の `ip_address` は所属プールのサブネット内で一意であり、他プールの範囲や他予約 IP と衝突しないこと。プール範囲の縮小により既存予約 IP が範囲外になる変更は §5.2 に従い再検証する。
- 重複判定は IPv4/IPv6 を別系統として、同一アドレスファミリ内で行う。
