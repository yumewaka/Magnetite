# DDNS 機能 改善依頼（MyDNS.JP で更新が反映されない）

**起票日:** 2026-09-06
**対象:** `crates/magnetite-dns/src/ddns.rs`（＋ `crates/magnetite-app/src/server_fns/dns.rs` の DDNS ステータス保存）
**環境:** DNS ノード .30 で DDNS 有効。provider = MyDNS.JP、管理ドメイン = yumewaka.pgw.jp。

## 概要
Magnetite の DDNS（Template モード）で MyDNS.JP に通知すると **HTTP 200・UI 上は成功**になるが、
**MyDNS 側に更新が反映されず、通知ログにも記録されない**。一方、同一ホスト（.30）からの
従来手段 `wget "http://<user>:<pass>@www.mydns.jp/login.html"` は **確実に成功**し、
MyDNS に「DNS UPDATE / IPv4 UPDATE」が記録される。

**クライアント側（Magnetite）の送出内容は完全に正しいことを確認済み**なので、
「成功判定」と「MyDNS 実処理に至らないケースへの頑健性」の改善を依頼する。

## 切り分け結果（確認済みの事実）
運用チームで以下まで確認済み（MyDNS への追加アクセスは禁止＝スパム/BAN 回避のため、
ローカルのエコーサーバ捕捉とハッシュ照合で検証）。

1. **MyDNS `login.html` は PHP スクリプト内で認証判定**（realm = "Enter MasterID and Password."）:
   - 認証ヘッダ無し → **401**
   - 認証ヘッダ有り・パスワード誤り → **200 で `login_status = 0`（notify NG・更新もログも無し）**
   - 認証正しい → **200 で `login_status = 1`（"Login and IP address notify OK" ＋更新＋ログ）**
   （wget 成功時の実応答本文で確認。`REMOTE ADDRESS: 119.244.9.188` / `SERVER ADDRESS: 144.126.145.255`）
2. **Magnetite が実際に送っている資格情報は正しい**：ローカル捕捉した Authorization ヘッダを
   デコードし、`username=mydns19545` / パスワード長 8 / sha256 が**実パスワードと一致**することを
   ユーザーがハッシュ照合で確認。
3. **Magnetite のリクエストも正常**：`GET /login.html`、`Authorization: Basic <正>`、正しい Host。
   応答は **200** で login.html ページ（タイトルは成功ページと同一・ルート `/` の別ページではない）。
4. それでも **更新・ログ無し**。→ クライアント側は正しく、`login_status` が 0 のまま（または当該ノードで
   実処理されていない）と推定されるが、**`last_message` が途中で切り詰められ `login_status` 行が見えず
   確定できない**。
5. 補足：`www.mydns.jp` は多数IPにラウンドロビン（例 144.126.145.255 / 46.250.249.213 /
   89.117.74.49 / 185.229.119.222 …）。wget は稼働ノードに当たって成功。Magnetite（単発・リトライ無し）は
   別ノードに当たっている可能性がある。

## 依頼内容
1. **応答本文を切り詰めず保存/表示する**
   現状 `DdnsStatus.last_message` が先頭 ~200 文字程度で切れ、`login_status` を判別できない。
   最低限、本文から `login_status` や "notify OK"/"NG" を抽出して保存する（全文保存 or 要約に含める）。
2. **成功判定を本文ベースにする（MyDNS 対応）**
   現状の Template 成功判定は「2xx かつ本文が `ko`/`err…` でない」だが、MyDNS は
   **誤り時も 200 を返す**ため誤検知する。**`login_status = 1` / "notify OK" 等を成功条件**にする
   （プロバイダ非依存にするなら、成功パターンを設定可能にするか、既知プロバイダ別ハンドラを用意）。
3. **wget/ブラウザと同じ挙動に寄せる＋頑健化**
   - 可能なら **チャレンジレスポンス**（無認証で送出 → 401 なら Authorization を付けて再送）も選べるように。
     現状はプリエンプティブ（最初から Authorization 送出）。
   - **失敗時のリトライ**（別ノードへ当たり直す）や、**安定エンドポイントへのピン留め**（解決した
     複数IPを順に試す等）で、ラウンドロビン先の不安定ノードを回避できるようにする。
4. **（任意）MyDNS プリセット**
   `mode = mydns` のようなプリセットを用意し、エンドポイント（`www/ipv4/ipv6.mydns.jp/login.html`）・
   Basic 認証・成功判定（`login_status = 1`）・IPv4/IPv6 指定を既定化すると運用が簡単。

## 受け入れ基準
- MyDNS に対し **正しい資格情報で通知 → MyDNS 側に更新/ログが記録**され、UI も成功と表示。
- **誤った資格情報**では UI が**失敗**と表示（200 login_status=0 を成功としない）。
- 応答本文（`login_status` 等）が UI/ステータスから確認できる。

## 検証時の注意（重要）
**MyDNS への短間隔・多数回アクセスは禁止**（スパム判定・アカウント BAN の恐れ）。
検証は以下のいずれかで：
- **モックプロバイダ**（本リポジトリに既存の e2e テスト `crates/magnetite-dns/src/ddns.rs` の
  `mock_provider` を流用）で 401→200/`login_status=0/1` を再現してロジックを確認する。
- 実 MyDNS に対しては **1回のみ**の確認に留める。

## 参考（現状コード）
- 送信・認証: `crates/magnetite-dns/src/ddns.rs` `http_get`（`Authorization: Basic` は `basic` 引数から付与）、
  `run_update`（Dyndns/Template の URL・basic 組み立て）、`split_userinfo`（`{user}:{pass}@` を分離してヘッダ化）。
- 成功判定: 同ファイル `update_succeeded`（Template は `!= "ko" && !starts_with("err")` ＝ 200-login_status=0 を誤検知）。
- ステータス保存/表示: `crates/magnetite-app/src/server_fns/dns.rs` の DDNS 系 server_fn（`last_message` 切り詰め箇所）。

## 現状の回避策（運用中）
レコードは現在正しく `yumewaka.pgw.jp → 119.244.9.188`。実績のある
`wget "http://<user>:<pass>@www.mydns.jp/login.html"` を cron でフォールバック運用中。
