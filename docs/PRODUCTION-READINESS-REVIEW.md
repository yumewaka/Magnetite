# Magnetite 本番稼働レビュー（3観点）

**実施日:** 2026-09-08
**範囲:** Magnetite 全体（LDAP/AD-DC・DNS・Mail・Proxy・SSO・DHCP・Watch・Magnetite Center）
**方法:** ソースコード横断レビュー（`/home/yume/magnetite-migrate`）＋ 実地運用で得た配備状況の知見。
**観点:** ①本番稼働上の懸念 ②冗長化の十分性 ③トラブル対処の仕組み（ログ等）

---

## 総合判定（エグゼクティブサマリ）

各機能の**実装自体は総じて堅牢**（DoS 上限の多くは既に対策済み、AD DRS は属性単位の競合解決、レプリ適用はトランザクション＋`.check()` で失敗を握り潰さない、認証は定数時間比較）。一方で、**本番運用に向けては 4 つの弱点**があります:

1. **冗長化がコードには在るが配備で無効** → **DNS・Mail・Proxy が各 1 ノードのみ＝単一障害点(SPOF)**。実際に冗長なのは AD-DC のみ。
2. **未認証ネットワーク面にプロセス停止級のクラッシャ/DoS** が数点（LDAP 深いBERのスタックオーバーフロー、SMTP AUTH の無制限読み込み OOM 等）。
3. **レプリケーション feed が秘密情報（TLS秘密鍵・SSO署名鍵・NTハッシュ・mail本文）を未認証・平文可の転送**で運ぶ。
4. **障害検知/対応が弱い**：プロトコル認証層（Kerberos/DRSUAPI/LDAP/mail/SSO）のログがほぼ無い、接続元IP未記録、アラートは実質「ホスト停止」のみ＋配送 at-most-once（喪失し得る）、log/audit/metric テーブルが無制限増加、タスク無監視で死んでも検知できない。

> **現環境（実質テスト環境・単一利用者・信頼された内部NW・DNS 以外は停止影響小）向けの現実的優先度**は末尾「§5」に別掲します。未認証NWへ晒さない限り、クラッシャ/秘密情報転送の緊急度は下がりますが、**DNS の SPOF・タスク無監視・ログ欠如は現環境でも効いてくる**ため優先対応を推奨します。

---

## §1. 本番稼働上の懸念

### A. プロセス可用性（クラッシャ / DoS）※未認証面が中心
| 深刻度 | 箇所 | シナリオ | 対策 |
|---|---|---|---|
| **HIGH** | `magnetite-ldap/src/codec.rs:24`＋`filter.rs:24-28`（BER 再帰） | 未認証。深くネストした BER/フィルタ（16MiB枠内）が **8MiB スタックを溢れさせ、プロセス全体を abort**（catch 不能・タスク分離を貫通） | 評価前にネスト深さ上限、frame 上限の引き下げ |
| **HIGH** | `magnetite-mail/src/service.rs:635-639`（`read_auth_line` 無制限） | 未認証。SMTP AUTH 継続行が 64KiB 上限を回避。改行無しで GB 送出 → **OOM** | SASL 継続行も `read_line_capped` に |
| **HIGH** | `magnetite-mail/src/service.rs:274-277,656-684` | `max_message_size_bytes==0`＝無制限扱い → 未認証 DATA 本文に上限なし → **OOM** | `max==0` でも絶対上限を設ける |
| **HIGH** | `magnetite-smb/src/vfs.rs:51,56`（生 `nodes[index]`、`server.rs:896/1354/1358/1380`） | 匿名 SMB → FileId の 4byte index を無検証 → **OOB パニック**（現状は接続単位で分離） | `nodes.get(index)` |
| **HIGH** | `magnetite-smb/src/server.rs:556-557,605-606`（NEGOTIATE/SESSION_SETUP の `le*`） | 未認証・初回パケット。短い body で **パニック**（接続単位分離） | `le16/32/64` を境界チェック化 |
| **MED** | `magnetite-dns/src/service.rs:351`→`resolver.rs:113-130` | 毎 UDP クエリで全ゾーン DB 読み（キャッシュ無・並行数無制限）→ クエリ洪水で増幅 | ゾーンをキャッシュ（書込で無効化）＋並行数/レート制限 |
| **MED** | mail/imap/pop3 コマンドループ、DNS TCP accept | 読取タイムアウト無・接続数上限無 → **slow-loris** で fd/タスク占有 | `timeout` ＋ 同時接続上限 |
| **MED** | `magnetite-proxy/src/forward.rs:307-311` | forward プロキシは応答を全量メモリ展開（`max_body` は要求のみ） | 応答もストリーミング/上限 |
| **MED(潜在)** | RPC 共有ロック `.lock().expect()`（`samr.rs:250/447/526`, `netlogon.rs:203/256`, `directory.rs:179+`） | ロック保持中のパニックで**ポイズニング→接続横断の全体停止**に昇格し得る | `parking_lot`（非ポイズニング）化 |
| **LOW/MED** | `magnetite-server/Cargo.toml:42`（`panic="abort"` 未設定・コメントのみ） | 現状はパニック接続分離。もし `panic=abort` に切替えると上記 SMB/RPC パニックが**未認証リモートのプロセスキル DoS** に | unwind 方針を明示的に固定（セキュリティ関連ビルドフラグとして扱う） |
| **LOW** | `rpc/src/samr.rs:720,769-797` | 認証済 SAMR：空鍵で除算0／全オフセット RC4 走査（最大16M回/req）で CPU 増幅 | 空鍵ガード・走査範囲制限 |

### B. 秘密情報・データ・期限・起動
| 深刻度 | 箇所 | シナリオ | 対策 |
|---|---|---|---|
| **HIGH** | `magnetite-feed/src/lib.rs:96-119`（`NoVerify`）＋`repl.rs:6-10`（平文可） | `/repl/*` が SSO秘密鍵/プロキシ証明書鍵/NTハッシュ/mail本文/bearer を運ぶのに**証明書検証なし・平文可** → MITM で全取得・偽 primary 化 | 証明書ピン留め/検証、鍵運搬 feed は HTTPS 必須化 |
| **HIGH** | `magnetite-ldap/src/consumer.rs:103`（平文 TCP） | syncrepl consumer が上流へ**平文** bind → bind パスワード・ハッシュが平文（既知の「silent ldaps downgrade」） | LDAPS/StartTLS＋検証、平文 bind 拒否 |
| **MED** | 秘密の保存：`magnetite.toml`（追跡・`client_secret="magnetite-secret"` 実値, 14行目）、`0600` 未強制、env 置換は**未実装**（`config.rs:43` は文書のみ） | 全運用秘密が既定パーミッションの平文 TOML に | env/ファイル参照置換の実装、`0600` 強制、配布はプレースホルダのみ |
| **MED** | `magnetite-db/src/store.rs:72-162`（`init_schema` は追加のみ・版管理なし） | アップグレードでフィールド改名/型変更時に既存 RocksDB 行の**デシリアライズ失敗**。※config パース自体は `#[serde(default)]` 徹底で安全 | データ版管理＋明示マイグレーション、新フィールドは `Option`＋`serde(default)` |
| **MED** | `magnetite-proxy/src/acme.rs:40,315`（`ASSUMED_VALIDITY_DAYS=89`） | 実 `not_after` でなく**89日固定仮定**で更新判断 → 短命証明書だと期限切れ TLS 断（＋ ACME タスク無監視） | 発行証明書の実 `not_after` で更新駆動 |
| **MED** | 起動：`main.rs:562-828`（bind 失敗しても中断せず health=Error のみ、`/mgmt/health` はトークン必須） | あるリスナが bind 失敗しても本体 HTTP は「healthy」→ systemd/podman は正常と誤認 | 未認証 `/healthz` `/readyz`（各サービス bind 状態反映） |
| **MED** | `store.rs`（RocksDB 明示 durability 無）／単一組込ストア | 既定 WAL 依存、電源断で直近書込ロスト可能・破損復旧手順なし | sync durability 確認、backup/restore＋破損復旧手順の整備 |
| **LOW** | krbtgt / マシンアカウントのパスワード無ローテーション | セキュリティ衛生（即障害ではない） | krbtgt/マシン秘密のローテ計画 |

**確認済み良好（再指摘不要）:** LDAP 16MiB frame 上限（両経路）、SMB 16MiB frame＋R/W 1MiB＋展開16MiB上限（事前チェック）、DNS TCP は u16 境界、reverse-proxy 要求本文上限＋413、RPC `MAX_PDU=64KiB`・`checked_*`・`.get()` 徹底、各スタブパーサ長さガード、config は `serde(default)` 徹底で前後方互換、ブラウザ投影は秘密をリダクト。

---

## §2. 冗長化の十分性

### ドメイン別 冗長化マトリクス
| ドメイン | 機構（コード） | 配備で有効？ | 主なギャップ |
|---|---|---|---|
| **DNS** | 本格的セカンダリ（AXFR/IXFR/NOTIFY・TSIG 相互認証）`magnetite-dns/src/replication.rs` | **無効**（.30 のみ、.31 は DNS 無効） | **実装・テスト済みだが未配備。最重要 SPOF**（下記 F1） |
| **Mail** | メールボックス変更 feed（複合カーソル永続）`server/src/repl.rs`,`db/mail.rs:1381+` | **無効**（`magnetite.toml:144` コメント） | .31 のみ＝SPOF、旧primary の再同期無し（F4） |
| **Proxy** | vhost/証明書(+鍵)/ACL/IPブロックの全置換・serial gate・**原子的** `repl.rs:335+`,`db/proxy.rs:857+` | **無効**（`:199`） | .31 のみ＝SPOF、鍵を未認証 feed で運ぶ（F2） |
| **LDAP/AD-DC** | AD DRS `GetNCChanges`（属性単位競合解決・USN カーソル）`addc/src/lib.rs` ＋ 別途 LDAP consumer（取込専用） | **有効**（両ノード） | **唯一冗長**。LDAP は provider 側なし（DRS 経路に依存） |
| **DHCP** | リース feed（冪等適用・DB 永続カーソル）`repl.rs:165+`,`db/dhcp.rs:445+` | **無効** | 現構成では非クリティカル |
| **SSO** | IdP/クライアント/**署名鍵**の全置換・serial gate・原子的 `repl.rs:421+`,`db/sso.rs:770+` | **無効**（`:225`） | セッション非複製（要再認証）、鍵反映に**再起動要**（F3） |
| **Magnetite Center**（制御面） | リーダ選出＋health ポーリング＋自動フェイルオーバ（fence/split-brain 対応）`crates/magnetite-center/` | **配備証跡なし**（`[mgmt]` コメント `:27`） | secondary feed が無ければ**昇格対象が無い**（F5） |

### 冗長化の主なリスク
| ID | 深刻度 | 箇所 | シナリオ | 対策 |
|---|---|---|---|---|
| **F1** | **CRITICAL** | `magnetite-dns/src/replication.rs`（DNS 無効 on .31） | .30 停止で**内部DNS全滅**→生存 AD-DC も名前で引けず、MX/プロキシ backend 解決も断（公開MyDNSは別系で生存） | **.31 に TSIG セカンダリを配備**（primary .30、`allow_transfer`+`also_notify`）。コードは準備済み＝**設定のみ** |
| **F4** | **HIGH** | `server/src/role.rs:51-58`,`config.rs:527-534` | フェイルオーバ後に復帰した旧primary が再同期されず→mail/proxy/SSO が乖離、後で LWW で片方消失 | 明示的な再ベースライン（`primary_url` 付与＋全再同期）を実装、失敗時は再シード手順を文書化 |
| **F5** | **HIGH** | `magnetite.toml:27,144,199,225`,`mgmt.rs:254-262` | secondary feed 未有効＋`[mgmt]` 無効 → Mail/Proxy/SSO が SPOF、Center も昇格対象なしで実質不活性 | `[mgmt]` 有効化＋ウォーム secondary を用意（Mail→.30、Proxy→予備、SSO） |
| **F2** | **MED** | `magnetite-feed/src/lib.rs:96-153` | feed が鍵・mail本文を未認証TLS/平文で運ぶ（§1B と同一） | ピア証明書検証／鍵 feed は TLS 必須 |
| **F3** | **MED** | `server/src/repl.rs:415-417` | SSO issuer が複製署名鍵の反映に**再起動要**→フェイルオーバ時にトークン検証断 | pull 後に鍵リング hot-reload |
| **F8** | **MED(緩和済)** | `center/leader.rs`,`store.rs:550-583` | 時刻ずれ/非共有ストアで二重リーダ/stale-leader 競合（promote は冪等＋split-brain ガードで被害小） | multi-center は共有ストア必須、fencing token、NTP 要件明記 |

**冗長化 判定:** 現配備では**不十分**。実装は良質だが「無効化」されている。最優先は **F1（DNS セカンダリ配備＝設定のみ）**、次に **F5（Mail/Proxy/SSO のウォーム secondary＋mgmt 有効化）**、**F4（フェイルバック再同期）**、**F2/F3**。

---

## §3. トラブル対処の仕組み（ログ・監視・アラート）

| 深刻度 | 箇所 | ギャップ | 対策 |
|---|---|---|---|
| **HIGH** | `magnetite-notify/src/lib.rs:105-116`＋`db/alerts.rs:222` | **アラート喪失**：配送前に `notified=true`、失敗は warn のみで再送なし（at-most-once） | 配送成功後にマーク、失敗は未通知のまま次回再送＋連続失敗で自己アラート |
| **HIGH** | Watch 以外に `raise_alert` 呼び出しが無い | **アラート条件がホスト停止のみ**。パニック/レプリ失敗/証明書期限/リスナ停止/DoS拒否で鳴らない | ACME・レプリ・パニックフック・DoS 経路に alert seam 追加 |
| **HIGH** | Kerberos `as_exchange.rs:109-171`/`tgs_exchange.rs:120-201`、`rpc/drsuapi.rs`・`lsa.rs`（tracing 0） | **認証・DCSync/DRS・LSA 秘密アクセスが無ログ** → ブルートフォース/資格情報窃取が不可視 | 各認証判断・レプリ要求を principal/コード付きで記録 |
| **HIGH** | LDAP `service.rs:519-522`（`unwrap_or(false)`）、mail/imap/pop3 認証、SSO endpoints（tracing 0） | **bind/mail/SSO の認証成否が無ログ**、バックエンド障害を「認証失敗」と誤表示、接続元IP 未記録 | 認証成否を tracing で無条件記録、`Err` と `Ok(false)` を区別 |
| **MED** | 全 accept ループ（LDAP/KRB5/SMB/RPC/mail/DHCP）で `_peer` 破棄 | **接続元IP を全ネットワークサーバで記録していない** → 記録済みイベントも発信元を特定不能 | peer IP を認証/エラーログへ伝播 |
| **MED** | `db/logs.rs`・`audit.rs`・`watch.rs:553`（retention 無） | **log/audit/watch_metric が無制限増加**、`count_audit`/`latest_metric` は O(n) 全読み | 定期 prune（`cleanup_expired_sessions` 同様）、`count()` 集計、`ORDER BY … LIMIT 1` |
| **MED** | `main.rs` パニックフック＋94× `tokio::spawn` 無監視 | パニックは terse・バックトレース無、`magnetite-panic.log` はコンテナで揮発、**死んだタスクを検知できず health も Healthy のまま** | フックにバックトレース/スレッド/ERROR、タスク監視で health 反映＋再起動 |
| **MED** | 主本体に `/metrics`・`/healthz` 無、`/mgmt/health` はトークン必須 | **機械可読なヘルス/メトリクス無**、劣化（リスナ停止・レプリ遅延・証明書期限・キュー滞留）を検知不可 | 未認証 `/healthz`＋Prometheus、ヘルス項目の拡充 |
| **MED** | DNS `service.rs:518,541,543,627`（`let _=`）、mail/proxy のエラー握り潰し | ゾーン転送適用失敗・配送/上流エラーの**根本原因が無記録**（サイレント drift） | 適用/転送エラーを warn/error、health 反映 |
| **LOW** | 両ログ経路に相関ID無、operational log は時間範囲/本文検索不可 | journald と DB ログを突合できない、調査が困難 | request/trace id を span と DB meta に付与、時間範囲/CONTAINS フィルタ |
| **INFO(解決済)** | `ddns.rs:195-213` | DDNS の `last_message` 切り詰めは修正済み（`login_status`/notify を前置） | — |

**トラブル対処 判定:** 小規模なら**部分的に可**だが、実インシデントで**盲点**が多い（プロトコル認証層のログ欠如・接続元IP 未記録・アラート喪失/条件不足・無制限増加テーブル・タスク無監視）。「攻撃されている」「レプリがドリフトした」に対しほぼ痕跡が残らない。

---

## §4. 統合・優先度付き対応リスト（本番前）

1. **DNS セカンダリを .31 に配備**（F1・設定のみ・実装済）— 最重要 SPOF を解消。
2. **未認証クラッシャ 3 件を修正**：LDAP 深BER スタックオーバーフロー(§1 #1)、SMTP AUTH/DATA の OOM(§1 #4/#5)。
3. **レプリ/consumer の転送を認証・暗号化**（feed 証明書検証 §1B/F2、LDAP consumer LDAPS §1B）— 鍵/ハッシュを保護。※有効化前提。
4. **タスク監視＋未認証 `/healthz`/`readyz`**（§1B #14, §3 タスク無監視）— 死活・劣化を検知可能に。
5. **アラートの信頼配送＋条件拡充**（§3：再送、パニック/レプリ失敗/証明書期限/認証失敗急増）。
6. **プロトコル認証層のログ＋接続元IP 記録**（§3 HIGH/MED）— 攻撃・不正の可視化。
7. **ウォーム secondary＋`[mgmt]` 有効化**（F5）と**フェイルバック再同期**（F4）— Mail/Proxy/SSO の冗長化と分裂回避。
8. **SMB `le*`/`nodes.get` 境界化＋RPC 非ポイズニングロック＋`panic=abort` 方針固定**（§1 #7/#8/#12/#18/#19）。
9. **ログ/監査/メトリクスの retention＋O(n) 修正**（§3 MED）— 長期稼働の劣化防止。
10. **秘密の保存強化（env/ファイル参照・0600）**＋**スキーマ版管理**＋**ACME 実 not_after 駆動**＋**krbtgt/マシン鍵ローテ**（§1B）。

---

## §5. 現環境（実質テスト環境・単一利用者・信頼NW・DNS 以外低影響）向けの現実的優先度

この環境前提では、未認証NWへ晒す前提の項目（§1A クラッシャ、§1B 秘密転送）の**緊急度は下がります**が、次は**現環境でも効く**ため優先を推奨:

- **最優先: DNS セカンダリ配備（F1）** — .30 停止＝内部名前解決全滅は、テスト環境でも痛い（AD/mail/proxy が芋づる式に不通）。設定のみで塞げる。
- **次: タスク監視＋ヘルス、主要ログ（認証・レプリ・パニック）＋接続元IP** — 「動かない/おかしい」を最短で切り分けるため。今回の一連のトラブル対応でも、ログ欠如・切り詰めで切り分けに時間を要した。
- **アラートの再送＋条件拡充** — 単一利用者でも、証明書期限切れ・レプリ停止・タスク死は気づきにくいので有効。
- **retention（log/audit/metric 無制限増加）** — 長期放置で肥大化するため、早めに prune を。
- クラッシャ/秘密転送/フェイルオーバ整備は、**外部公開範囲を広げる／本番規模に移行する段階**で対応、という順序で妥当。

---

## 補足
- 本レビューは実装＋配備状況に基づく。多くの「実装は在るが無効」項目は**設定/配備で解消**でき、コード改修が要るのは §1A のクラッシャ・§3 のログ/監視・§1B の transport 認証など。
- 深刻度は「本番・未認証NW前提」。現環境の実効リスクは §5 を参照。
