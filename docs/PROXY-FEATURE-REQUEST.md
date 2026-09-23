# Magnetite Proxy — nginx リプレースに必要な機能依頼

**起票日:** 2026-09-01
**背景:** yumewaka.pgw.jp ドメインの Magnetite 移行に伴い、リバースプロキシを既存 nginx
（現在 10.69.134.31 で稼働）から Magnetite 内蔵プロキシへ移し、Web UI で一元管理したい。
現行 nginx 構成を Magnetite プロキシへ移せるか精査した結果、**現状ではフル移行が不可能**な
機能ギャップが複数見つかったため、実装を依頼する。

> 対象コードは移行時点のもの。ファイル/行番号は精査時点の参照。
> 主要ファイル: `crates/magnetite-proxy/src/{service,router,tls,forward}.rs`、
> `crates/magnetite-core/src/domains/proxy/model.rs`、
> `crates/magnetite-server/src/main.rs`（listener 配線）、
> `crates/magnetite-app/src/server_fns/proxy.rs`（server_fn）。

---

## 1. 現行 nginx が担っている構成（＝移行対象）

### 1-1. HTTPS リバースプロキシ（443, `conf.d/*.conf`）6件

| ホスト名 | upstream | 特記 |
|---|---|---|
| drive.yumewaka.pgw.jp | 10.69.134.32:8180 | WebSocket、`client_max_body_size 500m` |
| game-studio.yumewaka.pgw.jp | 10.69.134.32:3000 | WebSocket |
| git.yumewaka.pgw.jp | cochma:8929 | WebSocket、大容量 push（500m） |
| monitor.yumewaka.pgw.jp | kube-master/work01:31904（2upstream） | WebSocket、`allow 10.69.0.0/16` |
| project.yumewaka.pgw.jp | kube-master/work01:31903（2upstream） | WebSocket |
| pwman.yumewaka.pgw.jp | cochma:9445 | `allow 10.69.0.0/16; deny all` |

- 全 vhost で `listen 443 ssl; http2 on; http3 on;`
- 全 vhost で WebSocket 用ヘッダ（`Upgrade`/`Connection "upgrade"`）と
  `Host`/`X-Real-IP`/`X-Forwarded-For`/`X-Forwarded-Proto`/`X-Forwarded-Host` を設定。
- 証明書は `/mnt/nfs/cert/<host>/fullchain.pem`・`privkey.pem`（game-studio のみ `*1.pem`）。

### 1-2. HTTP（80, `conf.http.d/*.conf`）7件

- dashboard / drive / git / mail / monitor / project / pwman の各ホスト名を、すべて
  `proxy_pass http://10.69.134.43` へ転送。用途は要確認（ACME HTTP-01 応答 or リダイレクト集約と推定。
  調査時点で .43:80 は無応答）。

### 1-3. TCP ストリーム（L4, `stream.d/*.conf`）

| ホスト名 | listen | upstream | 用途 |
|---|---|---|---|
| desktop1.yumewaka.pgw.jp | 3389 | kube-master:31770 | RDP |
| desktop2.yumewaka.pgw.jp | 3389 | kube-work01:31770 | RDP（同一 3389 を server_name で振り分け） |
| pg.yumewaka.pgw.jp | 5432 | kube-master:31800 | PostgreSQL |

---

## 2. Magnetite で既に使える機能（実装済み・移行に流用可）

- ホスト名（SNI/Host）単位のリバースプロキシ振り分け（`router.rs` `match_vhost`、完全一致）。
- 443 TLS 終端＋ SNI による vhost 別証明書選択（`tls.rs` `ResolvesServerCertUsingSni`、
  アプリ内証明書ストア連携）。
- 1 vhost に複数 upstream ＋ ロードバランス（`RoundRobin`/`LeastConn`/`IpHash`、`router.rs`）。
- vhost 別・グローバルの IP allow/deny ACL（`AclRule{cidr,action,scope,priority}`、
  既定 Allow。allow-list は「低優先度 `Deny 0.0.0.0/0` ＋ 高優先度 `Allow`」で表現）。
- HTTP→HTTPS 強制リダイレクト（`VirtualHost.force_https`、308）。

→ **pwman / monitor / project の「複数 upstream」「IP ACL」自体は Magnetite でも表現可能。**
ただし後述の WebSocket 等のギャップにより、そのままの移行は不可。

---

## 3. 機能依頼（優先度順）

### P0 — これが無いと nginx を撤去できない

**FR-1. L4 TCP ストリーム転送（最重要）**
現状 `ProxyMode::Tcp` は enum に存在するが `match_vhost` が `Http` しか処理せず
（`router.rs`）、Tcp vhost は決して配信されない“死にコード”。生 TCP のリスナ／転送が皆無。
- 任意 TCP ポート（例 3389/5432）の受け口と upstream への素通し。
- 同一ポートでのホスト名別振り分け（現行 desktop1/desktop2 は 3389 共有）。RDP/PostgreSQL は
  アプリ層プロトコルに SNI が無いため、TLS SNI での分離は不可。**代替の振り分け方式
  （待ち受けポート分離 or 宛先 IP/ポート指定）を含めて設計が必要。**
- これが無い限り RDP・PostgreSQL 中継は Magnetite で代替不能。

**FR-2. WebSocket / HTTP Upgrade 透過（リバースプロキシ）**
現状リバース用リスナは `http1::Builder::serve_connection` を `.with_upgrades()` 無しで使用
（`service.rs`）、ハンドラは `body.collect()` で全量バッファし `Connection: upgrade` を中継しない
（モジュール doc に「Deferred: streaming/websockets」と明記）。
- 6 vhost 全てが WebSocket 前提の設定。GitLab / Grafana(monitor) / Nextcloud(drive) 等は
  WS 依存機能があり、未対応のままだと機能不全になる。
- （参考）forward プロキシ側は `CONNECT` で `.with_upgrades()` 済み（`forward.rs`）なので、
  同等の upgrade 処理をリバース側へ展開する形が想定される。

### P1 — 本番運用に実質必須

**FR-3. ボディのストリーミング処理 ＋ サイズ上限**
`service.rs` で全リクエストボディをメモリに `collect()`。`client_max_body_size` 相当も無し。
現行は最大 500MB を許容しており、**大容量アップロードでメモリ枯渇（DoS）リスク**。
- リクエスト/レスポンスのストリーミング中継と、vhost/グローバルの本文サイズ上限設定。

**FR-4. HTTP/2（＋可能なら HTTP/3/QUIC）**
現状は全リスナ HTTP/1.1 のみ、TLS 設定に ALPN `h2` 無し（`tls.rs`）。現行 nginx は
`http2 on; http3 on;`。最低でも h2（ALPN 交渉）対応を希望。

**FR-5. 転送ヘッダの完全対応**
現状 `X-Forwarded-For` を peer IP で**上書き**するのみ、元の `Host` は破棄（`service.rs`）。
- `Host` 保持、`X-Real-IP`、`X-Forwarded-Proto`、`X-Forwarded-Host` の付与、
  `X-Forwarded-For` は上書きでなく追記。

### P2 — 望ましい

- **FR-6. HTTPS upstream**（`proxy_pass https://`）。`Upstream.scheme=Https` は保持されるが
  フォワーダが `http://` 固定（`service.rs`）。※今回の移行対象は全て http upstream のため影響なし。
- **FR-7. 重み付き LB**。`Upstream.weight` は保存されるが未使用（`router.rs` は `counter % len`）。
- **FR-8. 証明書/vhost のホットリロード**。現状 TLS 設定は起動時ロードのみ（restart-scoped）。
  UI から証明書・vhost を変更しても再起動まで反映されない。
- **FR-9. ACME / Let's Encrypt（HTTP-01）自動発行・更新**。プロキシ側に ACME 実装なし
  （証明書は `create_certificate` で手動投入のみ）。現行 :80→.43 が ACME 用途なら要代替。
- **FR-10. パス/location 単位のルーティング**。現状はホスト名完全一致のみ。

---

## 4. 構造的な制約（実装とは別に運用設計上の注意）

- **443 は 1 プロセスしか待ち受けできない**ため、「一部 vhost だけ Magnetite・残りは nginx」の
  443 分割共存は不可（全 vhost が SNI で 443 を共有）。したがって 443 の移行は**全 vhost 一斉**
  でしか成立せず、P0（特に WebSocket）が解消されるまで部分移行もできない。
- 移行順序の目安: **FR-1・FR-2 完了 → HTTPS vhost 群を一斉切替 → L4（RDP/PG）切替 → nginx 撤去。**

---

## 5. まとめ

| 区分 | 項目 |
|---|---|
| 移行の絶対条件（P0） | FR-1 L4 TCP ストリーム / FR-2 WebSocket 透過 |
| 実質必須（P1） | FR-3 ボディストリーミング+上限 / FR-4 HTTP/2 / FR-5 転送ヘッダ |
| 望ましい（P2） | FR-6〜FR-10 |

P0 の 2 項目が入るまでは nginx を継続する。実装が入り次第、本書の順序で移行を再計画する。
