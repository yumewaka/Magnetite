# Magnetite プロキシ：新規サービス追加＆証明書自動発行 手順書

Magnetite のリバースプロキシ（.31 = 10.69.134.31）に新しい HTTPS サービスを追加し、
**Let's Encrypt 証明書を内蔵 ACME で自動発行・自動更新**する手順。

## 前提（構築済み・共通）
- `.31` の `/etc/magnetite/magnetite.toml` に proxy サーバとACME:
  ```toml
  [domains.proxy]
  enabled = true
  [domains.proxy.server]
  listen = "0.0.0.0:80"          # HTTP-01 チャレンジ＋force_httpsリダイレクト
  tls_listen = "0.0.0.0:443"     # HTTPS終端・SNIで vhost別証明書
  max_body_bytes = 2097152000
  query_log = true
  [domains.proxy.server.acme]
  enabled = true
  staging = false                # 本番 Let's Encrypt
  domains = ["mag-center.yumewaka.pgw.jp", ...]   # ← ここに追加していく
  certificate_name = "proxy-acme"                 # 全ACMEホスト共有の1枚のSAN証明書
  ```
- **内蔵 ACME は「単一の SAN 証明書」方式**：`domains` に列挙した全ホストが1枚の証明書
  （`proxy-acme`）の SAN になる。ホスト追加時はこの証明書を再発行。
- 公開経路：公開DNSが `<host> → 119.244.9.188`（→NAT→.31:80/:443）。LE は :80 に HTTP-01 で到達。
- Web UI ログイン：`claude_service` / `domClaudeaPP12345`（.31:4000）。

## 手順：HTTPS サービス `H.yumewaka.pgw.jp` → バックエンド `B:PORT` を追加

### 1. DNS（前提を満たす）
- **公開DNS**：`H.yumewaka.pgw.jp` を **119.244.9.188**（サイト公開IP）に解決させる
  （LE の HTTP-01 検証と外部アクセスの両方に必要）。
- 内部からもプロキシ経由にしたい場合は、内部DNS(.30)でも `H → 10.69.134.31`（or CNAME）に。
- バックエンド `B:PORT` が **.31 から到達可能**であること（`bash -c 'echo >/dev/tcp/B/PORT'` で確認）。

### 2. ACME 証明書に H を追加（**無停止・Web UI 推奨**）
ACME 設定は DB 化されており、**Web UI から無停止で編集**できる（`304d5b2`）。
- **推奨（無停止）**：Web UI → **Proxy → 証明書 → 「ACME 自動証明書」カード**の「ドメイン」欄に
  `H.yumewaka.pgw.jp` を1行追加して保存。ACME マネージャが約1分以内に取り込み、`proxy-acme`
  証明書を H を含めて自動再発行する（**再起動不要**）。
- toml で管理したい場合：`[domains.proxy.server.acme].domains` に追記。ただし DB に既存設定が
  あると **DB が優先**される（toml は初回 seed のみ）。toml を正としたいなら Web UI で同じ値に
  揃えるか、当該 DB 行をクリアする。
確認（発行成功）：
```
ssh root@10.69.134.31 "journalctl -u magnetite.service --since '2 min ago' | grep -i acme"
# → \"does not yet cover 'H...'; re-issuing\" → \"certificate 'proxy-acme' issued/renewed successfully\"
```
証明書ストア(`proxy-acme`)の SAN に H が入る（Web UI の Proxy→証明書、または ListCertificates）。

### 3. vhost 作成（**無停止・ホット反映**）
Web UI の **Proxy タブ → 仮想ホスト追加**（推奨）、または API。設定値：
- hostname = `H.yumewaka.pgw.jp`
- listen_port = `443`（HTTPでは routing に不使用だが 0 不可）
- proxy_mode = `http`
- tls_enabled = `true` / certificate_ref = **`proxy-acme`**（共有SAN証明書名）
- force_https = `true`
- upstream = `{ host: B, port: PORT, scheme: http }`（複数指定で LB 可、lb_strategy 選択）

API 例（form-urlencoded、`vhost[...]` ネスト。save_vhost のルートハッシュは
`curl .31:4000/pkg/magnetite.wasm | grep -ao 'save_vhost[0-9]*'` で取得）：
```
vhost[id]=                       (空=新規／既存idで更新)
vhost[created_by]=claude_service
vhost[created_at]=1970-01-01T00:00:00Z
vhost[updated_at]=1970-01-01T00:00:00Z
vhost[hostname]=H.yumewaka.pgw.jp
vhost[listen_port]=443
vhost[proxy_mode]=http
vhost[lb_strategy]=round_robin
vhost[tls_enabled]=true
vhost[certificate_ref]=proxy-acme
vhost[force_https]=true
vhost[enabled]=true
vhost[upstream][0][host]=B
vhost[upstream][0][port]=PORT
vhost[upstream][0][scheme]=http
vhost[upstream][0][weight]=1
```
※ SNI 証明書マップと config キャッシュは自動更新（〜30秒）。vhost/証明書/ACL 変更は再起動不要。

### 4. 検証
```
# 提示証明書が本番LE（issuer: Let's Encrypt）で subject が H
echo | openssl s_client -servername H.yumewaka.pgw.jp -connect 10.69.134.31:443 2>/dev/null | openssl x509 -noout -subject -issuer
# HTTPS がバックエンドへ到達
curl -s -o /dev/null -w '%{http_code}\n' --resolve H.yumewaka.pgw.jp:443:10.69.134.31 https://H.yumewaka.pgw.jp/
# force_https（:80→308）
curl -sI --resolve H.yumewaka.pgw.jp:80:10.69.134.31 http://H.yumewaka.pgw.jp/ | head -1
```
ブラウザでの実ログイン等、アプリの動作も確認（WebSocket 利用アプリは要ログイン後確認）。

## アクセス制御（任意：`allow 10.69.0.0/16; deny all` 相当）
既定は Allow。イントラ限定にするには、その vhost に ACL を2本（Web UI Proxy→ACL、または SaveAclRule）：
- `cidr=0.0.0.0/0  action=deny  priority=100  scope=vhost  vhost_ref=<vhost id>`
- `cidr=10.69.0.0/16 action=allow priority=10 scope=vhost vhost_ref=<vhost id>`
（priority 小さいほど先評価。IPv6 で来るなら `::/0` deny も追加。**vhost_ref は hostname でなく vhost の id**。）

## 注意・落とし穴
- **単一SAN証明書**：ホスト追加＝`proxy-acme` 再発行。**ACME `domains` は Web UI から無停止で
  変更でき、約1分で反映・再発行される**（`304d5b2`）。`listen`/`tls_listen` などソケット系の変更は
  引き続き再起動要。vhost/証明書/ACL のデータ変更は無停止。
- **LE 本番レート**：同一登録ドメインで週あたりの発行数上限あり。頻繁な作り直しに注意。
- **~~既知の軽微バグ：`proxy_kv` 未作成で ACME アカウント再登録~~ → 修正済み**（`c965122`）。
  `proxy_kv` テーブルを `init_schema` で作成するようにしたため、ACME アカウント資格情報が永続化され、
  再起動後は既存アカウントを再利用する（修正版バイナリで一度再起動すれば以後有効。初回のみ登録が走る）。
- **ホスト追加時の再発行（挙動補足・修正済み `7f3df74`）**：手順2で `acme.domains` にホストを足して
  再起動すると、`proxy-acme` 証明書の SAN に新ホストが**含まれていなければ自動で再発行**される
  （以前は有効期限だけを見ており、期限内だと新ホストが SAN に入らないバグがあった）。再起動後の
  ログに「does not yet cover '<host>'; re-issuing」→「issued/renewed successfully」が出る。
- **外部発行の通過は不可**：`/.well-known/acme-challenge/*` は Magnetite が自ACME用に処理し
  upstream へ転送しない。**外部の certbot ホスト(旧 malchut 運用)を裏に置く方式は使えない**。
  Magnetite 内蔵 ACME で発行するか、Magnetite を経由しないサービスは別途（DNS-01 等）で。
- **証明書ファイルが必要な非プロキシサービス**：内蔵 ACME は DB 内に保管（NFS へファイル出力しない）。
  ファイルが要るサービスは別手段で発行する。
- HTTP/1.1・HTTP/2・WebSocket・大容量ボディ対応済み。upstream は http(平文)前提
  （https upstream は scheme=https 指定可、証明書検証はしない）。

## 手動証明書のサービス（現状 drive / git）
drive・git は個別の手動 Let's Encrypt 証明書（`/mnt/nfs/cert/<host>/`）を証明書ストアに登録して
利用中（vhost の certificate_ref = 各ホスト名）。ACME 自動更新へ寄せたい場合は、当該ホストを
`acme.domains` に追加＋再起動し、vhost の certificate_ref を `proxy-acme` に変更すればよい（任意）。

## 参考：現在の登録例（mag-center）
- acme.domains に `mag-center.yumewaka.pgw.jp`、certificate_name=`proxy-acme`（本番）
- vhost: hostname=mag-center、tls=true、cert=proxy-acme、force_https=true、upstream=10.69.134.43:80
- 発行済み（issuer: Let's Encrypt CN=YE1）、`https://mag-center.yumewaka.pgw.jp/` → malchut へ到達
