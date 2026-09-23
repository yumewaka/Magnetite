# 実デーモン連携 設計（09 §4/§12 の具体化・提案）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（提案・レビュー用） |
| 位置づけ | 09_runtime_spec §4（連携インターフェース）と §12（未確定事項）を実装可能なレベルまで具体化する提案。権威仕様の確定は本書へのユーザー承認をもって行う。 |
| 前提（改訂） | 参照元 `service-integration/crates/*-project` は git サブモジュールで**実体あり**（初回スキャンの cwd 誤りで空と誤認・訂正）。旧各サービスは**外部デーモンを使わず Rust で自前実装したプロトコルサーバ**である（下記 §-1）。 |

---

## -1. 【重要・方針是正】外部デーモン駆動 → プロセス内埋め込みサーバ

> 本書 §0〜§12（初版）は 09_runtime_spec §0 の「実デーモン（bind/kea/OpenLDAP/postfix/nginx）へ
> 設定をレンダリングして適用」という記述を前提にしていた。だが**旧システムの実装を確認した結果、
> その前提は実態と異なる**。以下に是正方針を示す。§0〜§12（初版）は「不採用の外部デーモン案（参考）」
> として残す。

### 判明した旧アーキテクチャ（`service-integration` サブモジュール実体）

各サービスは **Rust で自前実装したプロトコルサーバ**を、組込み SurrealDB＋Leptos 管理UIとともに
**単一バイナリ**で動かしている（外部 bind/kea/postfix 等を呼ばない）。

| 旧プロジェクト | 実体 | 主な実装 |
|---|---|---|
| dns-project | 権威DNSサーバ（UDP/TCP/DoT/DoH） | `hickory-proto` でメッセージ処理。ACL/RPZ/DNSSEC/AXFR/forwarder/cache/GeoDNS/DNS64 を自前 |
| dhcp-project | DHCPv4/v6 デュアルスタックサーバ | `socket2` 生ソケット |
| ldap-project | LDAP サーバ | 自前 |
| mail-project | SMTP/IMAP/POP3 セルフホスト型 + Webmail | 自前 |
| proxy-project | Forward/Reverse Proxy（HTTP/HTTPS/TCP/SOCKS5） | 自前 |
| sso-project | **IdP サーバ**（OAuth2/OIDC/SAML/SCIM、外部IdP連携も） | 自前。※Magnetite は RP ではなく**発行側** |
| container-project | K8s クラスタ管理 | 例外：**外部 k8s API クライアント**（自前プロトコルサーバではない） |
| watch-project | 監視システム（エージェントレス/エージェント） | 自前コレクタ |

### 是正後の連携方式：**埋め込みプロトコルサーバ（in-process）**

- Magnetite は「設定を外部デーモンへレンダリング」するのではなく、**各プロトコルサーバをプロセス内で
  自ら動かす**（＝旧システムと同じ方式を monolith に統合）。`magnetite-server` が各サーバを
  バックグラウンド tokio タスクとして起動し、**単一 magnetite-db を共有**する。
- **設定反映は関数呼び出し/通知で即時**（config ファイル生成・reload・reconcile・ドリフト是正は不要。
  サーバは DB を live 参照するか、変更通知で内部ビューを更新）。09 §3〜§4 の render/apply/reconcile
  パイプラインは**埋め込み方式では大幅簡略化**される。
- **ログ取り込みが自然解決**：各埋め込みサーバはプロセス内なので、query/access ログを
  `Db::append_log` に**直接**書ける（外部ファイル追尾・syslog 不要）。→ [S-Logs 取り込みTODO] を解消。
- **health/DomainStatus** は各埋め込みサーバの稼働状態から直接算出（ダッシュボードの "unknown" を実値へ）。
- 例外：**Container/K8s** は外部 k8s への API クライアント（埋め込みサーバではない）。**SSO** は自前 IdP。

### 抽象（是正案）：`EmbeddedService`

```rust
#[async_trait]
pub trait EmbeddedService: Send + Sync {
    fn domain(&self) -> DomainKey;
    /// 設定(DB)を読み、リッスン開始。graceful shutdown 対応。
    async fn start(&self, db: Db, shutdown: CancellationToken) -> Result<(), ServiceError>;
    /// 稼働・リッスン状態。
    fn health(&self) -> DaemonHealth;      // Healthy/Warning/Error/Unknown/Disabled
    /// 設定変更の即時反映（DBコミット後に呼ぶ。ファイル生成なし）。
    async fn notify_config_changed(&self, domain: DomainKey);
}
```

- 旧案の `DomainConnector`（render/apply/reload/reconcile）は**外部デーモン前提のため不要**。
  代わりに上記 start/health/notify を持つ。`ConnectorRegistry` は `ServiceRegistry` に。
- 各サーバは共有 DB へ書き込む/読み出す。ポートやTLS等は AppConfig の per-domain 設定から。

### スコープと段階（是正案）

- これは **8 プロトコルサーバの monolith への移植**であり、大規模・多フェーズ。旧サブモジュール実装
  （dns-server の `dns/` 等）を **magnetite-db スキーマ / magnetite-core モデル / Leptos 0.8** に
  適応して取り込む。ライセンス/流用可否は要確認（同一著者リポジトリ想定）。
- **Phase E0（土台）**：`EmbeddedService` トレイト＋`ServiceRegistry`＋`magnetite-server` の
  起動/停止(graceful)/health 配線＋`append_log` ブリッジ＋ダッシュボード health 実値化。
  この時点でサーバ実体は無し（全ドメイン Disabled 表示）＝**現状挙動を変えない安全増分**。
- **Phase E1〜**：ドメイン別に実サーバ移植（推奨初手＝**DNS**：最も自己完結で hickory ベースが移植しやすい）。
  以降 DHCP→Proxy→Mail→LDAP→SSO(IdP)→Watch。Container は外部kube APIクライアントとして別扱い。
- 各移植は「プロトコル処理のユニットテスト」を厚く。リッスン系はポートを使うため統合テストで。

### 要確認（この是正の承認）

| # | 決定事項 | 推奨 | 状態 |
|---|---|---|---|
| E-R1 | 連携方式を**埋め込みサーバ**に確定（09 §0 の「外部デーモン駆動」記述を改訂） | 採用 | **確定(2026-07-07)** |
| E-R2 | 旧サブモジュール実装の流用/移植の可否 | 可 | **確定** |
| E-R3 | 初手ドメイン | DNS | **確定・完成** |
| E-R4 | まず Phase E0（土台のみ・挙動不変）を実装するか | する | **完了** |

### R5 決定（2026-07-07）：接続設定は **AppConfig（TOML）集約・再起動スコープ**

- 各ドメインの埋め込みサーバ設定を **`[domains.<d>.server]`** に置く（`listen` 必須、DNS は
  `forwarders` / `query_log`）。起動時に `EmbeddedService` を構築し、**変更は再起動**（ソケットは
  起動時バインド＝09 §7 の server binding と同一クラス）。理由：ソケット再バインドは本質的にホット
  リロード不可なので、"即時反映" を謳うS-Settings に置くと誤解を招く。
- `domains.<d>.enabled`（S-Settings・ホット）は引き続き **UI/機能の表示ON-OFF** を担当（プロトコル
  起動とは別概念）。
- 実装：`magnetite-core::config` に `DomainServerConfig{listen, forwarders, query_log}` ＋
  `DomainConfig.server: Option<..>` ＋ validate（listen/forwarders の SocketAddr 検証）。
  `magnetite-server::build_embedded_services(&config)` が構築。暫定 env（MAGNETITE_DNS_LISTEN /
  _FORWARDERS）は**廃止**。`DnsService::new(addr, forwarders, query_log)`。sample は `magnetite.toml` に
  コメントで記載。core 55 tests（+server-block 検証2）。

---

## 0. 設計原則（09 §0/§3 の再確認）

- **DBが設定の唯一の正。デーモンは従属（DBから render される派生状態）。** 食い違いは DB を正として reconcile。
- Magnetite は**コントロールプレーン**。実トラフィックはデーモンが処理。Magnetite は「設定の保持・検証・レンダリング・適用・health/reconcile」に専念。
- デーモン適用失敗や到達不能で**アプリをクラッシュさせない**。当該ドメインを `Error/Unknown` にし、UI 表示＋監査＋再試行導線（§8）。
- **フェイクの「リロードしたふり」は作らない。** 実デーモンが無い/未設定の場合は「未管理（Unmanaged）」として正直に表示し、DB-only で動作する。

---

## 1. 連携アーキテクチャ：`DomainConnector` 抽象

各ドメインは §4 の意味論（render / apply・reload / status・health / reconcile）を実装する共通トレイトを持つ。**デーモン非依存の抽象**を土台にし、実デーモン実装（BIND/Kea/…）を後から差し込む。

### 1.1 トレイト（Rust 設計案）

```rust
// crates/magnetite-daemon（新規クレート）または magnetite-db 内 daemon モジュール
#[async_trait]
pub trait DomainConnector: Send + Sync {
    fn domain(&self) -> DomainKey;

    /// DB の設定 → デーモン設定表現（ゾーンファイル/JSON/LDIF/map/nginx conf 等）。
    /// 純粋関数に近く、実デーモン無しでもユニットテスト可能（ここを厚くテストする）。
    async fn render(&self, db: &Db) -> Result<RenderedConfig, ConnectorError>;

    /// レンダリング結果をデーモンへ反映（設定配置＋無停止リロード or API 反映）。
    async fn apply(&self, rendered: &RenderedConfig) -> Result<(), ConnectorError>;

    /// デーモンの稼働・整合を取得。
    async fn health(&self) -> DaemonHealth;

    /// DB とデーモンの差分検出＋DBを正として再適用（ドリフト是正）。
    async fn reconcile(&self, db: &Db) -> Result<ReconcileReport, ConnectorError>;
}

pub struct RenderedConfig {
    /// 生成物（パス→内容 or 論理表現）。適用単位ごとに分割可能。
    pub artifacts: Vec<RenderedArtifact>,
    pub fingerprint: String, // ドリフト検出用ハッシュ
}

pub enum DaemonHealth { Healthy, Warning(String), Error(String), Unknown, Unmanaged }

pub enum ConnectorError { Unreachable(String), ApplyFailed(String), Render(String), Unsupported }
```

### 1.2 既定コネクタ：`UnmanagedConnector`（正直な no-op）

- `render` = 成功（生成物は返すが書き込まない）。`apply` = no-op（DB が正）。`health` = `Unmanaged`。`reconcile` = 何もしない。
- ダッシュボード等では **「未管理」** と表示（"healthy" を詐称しない）。
- これにより **現状の DB-only 挙動を一切変えずに**、連携の接続点だけを先に敷ける。

### 1.3 レジストリと AppState 配線

```rust
pub struct ConnectorRegistry { map: HashMap<DomainKey, Arc<dyn DomainConnector>> }
// AppState に registry: Arc<ConnectorRegistry> を追加。
```

- 起動時（09 §2 手順5）に AppConfig のコネクタ設定から各ドメインのコネクタを構築。未設定は `UnmanagedConnector`。

---

## 2. コネクタ選択と設定（要決定：置き場所）

各ドメインに接続方式・エンドポイント・認証情報参照を持たせる。

```toml
# AppConfig 拡張案（domains.<key>.connector）
[domains.dns.connector]
kind = "bind9"                 # unmanaged | bind9 | kea | openldap | postfix | nginx | kube | oidc | ssh
control = "rndc"               # 反映手段（rndc/API/protocol/command）
endpoint = "127.0.0.1:953"     # or unix socket / REST URL / kubeconfig パス
zones_dir = "/etc/bind/zones"  # 方式別パラメータ
credential_ref = "dns_rndc_key" # 機微情報は別管理（§10）
```

- **要決定 R5**：コネクタ設定を **AppConfig 静的（再起動反映）** にするか、**S-Settings で編集可（ホットリロード）** にするか。推奨＝当面は AppConfig 静的（接続先変更は稀・慎重に）＋ health/reconcile はホットに動かす。

---

## 3. 設定適用パイプライン統合（09 §3 の実装）

ドメイン設定の作成/更新/削除サーバ関数の末尾に、共通ヘルパを挟む。

```rust
async fn apply_domain(state: &AppState, domain: DomainKey) -> ApplyOutcome {
    let conn = state.connectors.get(domain);           // 既定 Unmanaged
    let rendered = conn.render(&state.db).await?;       // DB→設定
    match conn.apply(&rendered).await {
        Ok(()) => { update_domain_status(Healthy); Ok }
        Err(e) => {
            update_domain_status(Error);                 // §8
            // 「設定は保存しましたが反映に失敗しました。再試行してください。」
            record_audit_failure(); Err(e)
        }
    }
}
```

- 順序は **DBコミット → デーモン適用**（09 §3）。適用失敗でも DB は正のまま、ドメインを `Error` にして reconcile 再試行導線。
- Unmanaged では apply が常に成功（no-op）なので、現状挙動は不変。

---

## 4. ドメイン別 連携マッピング（推奨・要確定 R1）

> デーモン種別は環境依存。以下は**推奨既定**。採用/変更をユーザー確定してほしい。

| ドメイン | デーモン(推奨) | 連携方式 | 適用単位 | reload | health | ログ取り込み | クエリ/テスト |
|---|---|---|---|---|---|---|---|
| DNS | **BIND9 (named)** | ゾーンファイル生成 | ゾーン | `rndc reload <zone>` | `rndc status` | query log ファイル追尾 | デーモンへ解決問い合わせ（AC-13。Magnetiteは解決を再実装しない） |
| DHCP | **ISC Kea** | Kea JSON 設定生成＋管理API | サブネット/予約 | ctrl-agent `config-reload` | REST `version-get` | Kea ログ/leaseファイル | lease REST（`lease4-get-all`/`lease4-del`） |
| LDAP | **OpenLDAP (slapd)** | **LDAPプロトコル直接**（設定ファイルでなくエントリ操作） | エントリ | 即時（プロトコル反映） | LDAP bind probe | slapd ログ | 検索＝LDAPクエリ / LDIF入出力 |
| Mail | **Postfix + Dovecot** | map生成（virtual/alias）＋`postmap` | map全体 | `postfix reload` | `postfix status`/SMTP probe | maillog 追尾 | — |
| Proxy | **nginx** | vhost conf 生成 | vhost（全体reload） | `nginx -t`＋`nginx -s reload` | `nginx -t`＋upstream check | access log 追尾 | health/upstream 状態 |
| K8s/Container | **kube-apiserver** | kube API（manifest apply）／ホストは既存SSH | リソース | API apply | API `/healthz` | イベント/コンテナログ | メトリクス（metrics-server） |
| SSO | 外部OIDC IdP（例 Keycloak） | **Magnetiteはリライングパーティ（駆動しない）** | — | — | discovery 到達性 | — | **接続テスト＝`.well-known/openid-configuration`＋JWKS取得**（E-S01/S-Settings E-03） |
| Watch | 汎用コレクタ（プラガブル） | 既定＝SSHコマンド/ping/TCP/SNMP | ホスト | — | 収集成否 | — | 収集値→Metric、閾値→Alert（08_alerting） |

- 連携方式の分類：**ファイル生成＋reload**（BIND/Postfix/nginx）、**管理API**（Kea/k8s）、**プロトコルネイティブ**（OpenLDAP）、**プローブのみ**（SSO）。→ **要確定 R2**（このハイブリッドで良いか）。

---

## 5. ライフサイクル管理方針（要確定 R3）

- 09 §10 の既定どおり **外部管理（systemd 等）** を推奨。Magnetite はデーモンの起動/停止を行わず、**設定適用と health/reconcile に専念**。
- 利点：権限最小化・責務分離・監視基盤との整合。Magnetite クラッシュがデーモン停止に波及しない。

---

## 6. ログ取り込み方式（要確定 R4）

- **operation ログ**：Magnetite 内部の `tracing` を LogEntry へブリッジするレイヤ → `append_log`。
- **query/access ログ**：既定＝**ファイル追尾**（BIND querylog、nginx access log、maillog）。バックグラウンドの tailer がパース→正規化→`append_log`。
- 代替：syslog 受信 / デーモン API。追尾を既定、syslog はオプション。
- 保持：`policy.retention_days` に基づくリングバッファ相当の掃引タスク（超過分を物理削除）。

---

## 7. 常駐タスク設計（09 §1 の具体化）

| タスク | 周期(既定・要確定 R7) | 内容 |
|---|---|---|
| セッションクリーンアップ | 60s | 期限切れ Session/SsoSession 物理削除（有効性判定は毎回） |
| デーモン health | 30s | 各コネクタ `health()` → DomainStatus 更新（ダッシュボード反映） |
| reconcile | 5min | `render` fingerprint と実デーモンの差分検出→DBを正として再適用 |
| 監視データ収集 | ルール間隔 | Watch コレクタで値収集→Metric 蓄積・`last_seen` 更新 |
| 監視ルール評価 | 収集後 | 閾値判定→`raise_alert`（08_alerting） |
| 時刻到達掃引 | 60s | 期限切れ IpBlock 失効・証明書期限接近評価→Alert・メンテ窓開始/終了 |
| ログ tailer | 常時 | query/access ログ追尾→`append_log` |
| ログ保持掃引 | 1h | retention 超過ログ削除 |
| 自動バックアップ | スケジュール | 世代管理（BackupKind::Auto） |
| 通知配送 | イベント＋再試行 | NotificationTarget 送信。再試行 3 回・指数バックオフ（30s/2min/10min、要確定 R7） |

- 実装：`magnetite-server` 起動時に `tokio::spawn`。graceful shutdown で停止（09 §10）。

---

## 8. 実行時エラーと DomainStatus 連携（09 §8）

- 適用失敗（DBは成功）：DomainStatus=`Error`、UI「設定は保存しましたが反映に失敗しました。再試行してください。」、監査に失敗記録、reconcile 再試行導線。
- 到達不能：`Error/Unknown`、health 回復後 reconcile。
- ダッシュボード（現状 `health="unknown"` 固定）を **health タスクの DomainStatus 参照**に切替。Unmanaged は「未管理」。

---

## 9. 依存クレート（追加可否 要確定 R6）

| 用途 | 候補クレート |
|---|---|
| DNS 解決テスト/クライアント | `hickory-resolver` / `hickory-client` |
| REST（Kea/k8s/OIDC discovery） | `reqwest` |
| LDAP | `ldap3` |
| Kubernetes | `kube` + `k8s-openapi` |
| SSH（Watch/K8sホスト） | `russh` or `ssh2` |
| reload/postmap/rndc/nginx | `tokio::process::Command` |
| ログ追尾 | `notify` or 自前 tail |

---

## 10. 機微情報

- rndc キー、Kea/API 認証、SSH 秘密鍵、OIDC client_secret 等は **`credential_ref` で間接参照**し、値はクライアントへ出さない・監査に残さない（05 §5、既存の has_secret マスク方針を踏襲）。
- 保存時暗号化方式は 09 §12 の未確定（**要確定 R8**）。当面は既存の DB 保管（マスク投影）を踏襲。

---

## 11. 段階的実装ロードマップ（設計確定後）

- **Phase D0（デーモン非依存の土台）**：`DomainConnector` トレイト＋`ConnectorRegistry`＋`UnmanagedConnector`＋`apply_domain` パイプライン接続＋DomainStatus/health タスク＋ダッシュボード health 切替。**現状挙動不変・ユニットテスト可能・フェイク無し**。
- **Phase D1〜**：ドメイン別実コネクタを1つずつ（推奨順：DNS→Proxy→DHCP→Mail→LDAP→K8s→Watch→SSO）。`render` はユニットテスト、`apply/health` は「実デーモン環境が必要」と明示（この環境ではモック/未検証）。
- **Phase DL**：ログ tailer（query/access）＋ operation ログブリッジ。
- **Phase DT**：常駐タスク群（health/reconcile/収集/評価/掃引/通知配送/自動バックアップ）。

---

## 12. 要決定事項（ユーザー承認待ち）

| # | 決定事項 | 推奨 |
|---|---|---|
| R1 | 各ドメインのデーモン種別（§4表） | BIND9 / Kea / OpenLDAP / Postfix+Dovecot / nginx / kube / 外部OIDC / SSH コレクタ |
| R2 | 連携方式のハイブリッド採用 | ファイル生成+reload／API／プロトコル／プローブ の使い分け |
| R3 | デーモンのライフサイクル管理主体 | 外部（systemd）＝Magnetite はコントロールプレーン専念 |
| R4 | ログ取り込み方式 | ファイル追尾を既定（syslog はオプション） |
| R5 | コネクタ設定の置き場所 | AppConfig 静的（再起動反映）。health/reconcile はホット |
| R6 | 依存クレート追加の可否 | §9 の候補群 |
| R7 | 常駐タスクの周期・再試行既定値 | §7 の表 |
| R8 | 機微値（SSOトークン/認証情報）の暗号化方式 | 当面は既存マスク投影踏襲、暗号化は別途 |

**次アクション**：R1〜R8 を確定 → Phase D0（土台）から実装着手。D0 は現状挙動を変えずコンパイル/テストが通る安全な増分。
