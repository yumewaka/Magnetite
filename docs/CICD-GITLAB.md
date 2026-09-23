# Magnetite ビルド/デプロイの GitLab CI/CD 化 手順

## 結論：可能です
現行の手動フロー（`podman build` → NFS 配布 → 旧イメージをタグ退避＋`:latest` 付け替え →
`systemctl restart` → 検証）を、GitLab CI/CD でそのまま自動化できます。GitLab Runner が
本番サービスを（自分の権限で）再起動できるため、対話セッションのような再起動ブロックもありません。

構成: **shell executor の GitLab Runner** を、`podman` ＋ BuildKit キャッシュ ＋ NFS(`/mnt/nfs/ad_migrate`)
＋ 各ノード(.30/.31)への root SSH を持つホストに常駐させ、パイプラインでビルド〜デプロイを実行。

---

## 前提（先に整える 3 点）

### 1. Dockerfile を「動く版」にコミット（必須）
現在コミット済みの `Dockerfile` は **ビルドに失敗します**（`cargo install cargo-leptos --locked` が
新しめの cargo で古い依存クレートの manifest を弾く）。運用チームが手動ビルドで使っている
「プレビルド gnu cargo-leptos を取得する版」を **リポジトリにコミット**してください。変更点:
- builder の `apt-get install` 行に **`curl ca-certificates`** を追加。
- `cargo install cargo-leptos --locked` を、**プレビルド gnu バイナリ取得（sha256 検証）**に置換。
- BuildKit cache mount の id を `cargo-registry-v2` / `magnetite-target-v2` に。

該当ブロック（builder ステージ）:
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev build-essential pkg-config libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
# cargo-leptos はソースからコンパイルせず、検証済みプレビルド(gnu)を取得
RUN curl -sSL -o /tmp/cl.tar.gz https://github.com/leptos-rs/cargo-leptos/releases/download/v0.3.7/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz \
    && echo "fda80f4845e92d0e8f5ec13cf1a46982ba7a518ae01182e7e4201312944bc05d  /tmp/cl.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/cl.tar.gz -C /tmp \
    && install -m0755 /tmp/cargo-leptos-x86_64-unknown-linux-gnu/cargo-leptos /usr/local/cargo/bin/cargo-leptos \
    && cargo leptos --version
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-v2 \
    --mount=type=cache,target=/src/target,id=magnetite-target-v2 \
    cargo leptos build --release \
    && mkdir -p /out && cp target/release/magnetite-server /out/ && cp -r target/site /out/site
```
（アプリ本体は `rust-toolchain.toml` の `nightly-2026-08-17` で従来どおりビルドされます。）

### 2. GitLab Runner を登録（shell executor）
- ホスト要件: `podman`、`/mnt/nfs/ad_migrate` マウント、**`ssh root@10.69.134.30` と `ssh root@10.69.134.31` が鍵で通る**こと。
  - 専用ビルドホスト推奨（本番 DNS ノード .30 の負荷を避ける）。.30 上で動かす場合は、.30 自身へ SSH する
    ため .30 の公開鍵を .30 の `authorized_keys` に入れる（自己 SSH）か、pri ジョブだけローカル実行に変える。
- 登録時に **executor = shell**、タグ例 `magnetite-build` を付与（ジョブで `tags: [magnetite-build]`）。
- **キャッシュ永続化のため同一ホスト常駐の shell executor を推奨**。docker/k8s executor だと BuildKit の
  cache mount が毎回消え、フルビルド（数十分）になります。shell + 常駐なら差分ビルドで数分。

### 3. CI/CD 変数（Settings → CI/CD → Variables、Protected/Masked 推奨）
- Runner が既に root SSH 鍵を持つなら不要。持たせる場合は `SSH_PRIVATE_KEY`（各ノードの root 用）。
- ノードIP・NFS パスは下記 yml の `variables:` で管理（必要なら CI 変数へ）。

---

## `.gitlab-ci.yml`（リポジトリ直下に追加）
```yaml
stages: [build, deploy]

variables:
  IMAGE: "localhost/magnetite"
  NFS_TAR: "/mnt/nfs/ad_migrate/magnetite-ci.tar"
  PRI: "10.69.134.30"   # DNS/AD primary
  SEC: "10.69.134.31"   # proxy/mail secondary + mail

build:
  stage: build
  tags: [magnetite-build]
  script:
    - podman build --layers -t "$IMAGE:$CI_COMMIT_SHORT_SHA" -f Dockerfile .
    - rm -f "$NFS_TAR"
    - podman save "$IMAGE:$CI_COMMIT_SHORT_SHA" -o "$NFS_TAR"
  # BuildKit の cache mount は runner ホストに残るので差分ビルドになる

# --- 共通デプロイ（ノードへ配布→タグ退避→latest→再起動→検証） ---
.deploy: &deploy
  stage: deploy
  tags: [magnetite-build]
  when: manual            # ビルド確認後に人が起動（本番切替のため）
  script:
    - |
      ssh -o StrictHostKeyChecking=no root@"$NODE" "
        set -e
        podman load -i '$NFS_TAR'
        podman tag $IMAGE:latest $IMAGE:rollback-prev 2>/dev/null || true
        podman tag $IMAGE:$CI_COMMIT_SHORT_SHA $IMAGE:latest
        systemctl restart magnetite.service
        sleep 8
        systemctl is-active magnetite.service
        echo -n 'running img='; podman inspect --format '{{.Image}}' magnetite | cut -c1-12
      "
    # 軽い疎通確認（ノード共通）
    - curl -sf -o /dev/null "http://$NODE:4000/" && echo "web OK"

deploy:sec:
  <<: *deploy
  variables: { NODE: "$SEC" }
  environment: { name: sec-31 }
  # 追加検証例: プロキシ/mail
  after_script:
    - curl -s -o /dev/null -w 'drive=%{http_code}\n' --resolve drive.yumewaka.pgw.jp:443:$SEC https://drive.yumewaka.pgw.jp/ || true

deploy:pri:
  <<: *deploy
  variables: { NODE: "$PRI" }
  environment: { name: pri-30 }
  after_script:
    - dig @"$PRI" mail.yumewaka.pgw.jp +short || true    # DNS 疎通

# --- ロールバック（手動） ---
.rollback: &rollback
  stage: deploy
  tags: [magnetite-build]
  when: manual
  script:
    - ssh -o StrictHostKeyChecking=no root@"$NODE" "podman tag $IMAGE:rollback-prev $IMAGE:latest && systemctl restart magnetite.service && sleep 6 && systemctl is-active magnetite.service"

rollback:sec: { <<: *rollback, variables: { NODE: "$SEC" } }
rollback:pri: { <<: *rollback, variables: { NODE: "$PRI" } }
```

### 運用フロー
1. main に push → `build` が自動実行（イメージ生成＋NFS へ save）。
2. パイプライン画面で **`deploy:sec`** を手動実行 → .31 切替＋検証。問題なければ
3. **`deploy:pri`** を手動実行 → .30 切替＋検証。
4. 異常時は **`rollback:sec` / `rollback:pri`** を手動実行（直前イメージへ即戻し）。

---

## 現行手動フローとの対応
| 手動でやっていること | パイプラインのジョブ/ステップ |
|---|---|
| `podman build` ＋ `podman save`→NFS | `build` |
| `podman load` / rollback タグ / `:latest` 付け替え | `deploy:*` の ssh スクリプト |
| `systemctl restart magnetite`（＝これまで人が実行） | `deploy:*`（runner が実行、分類器の制約なし） |
| 起動確認・DNS/プロキシ/mail 検証 | `deploy:*` の script / after_script |
| 旧イメージへの復帰 | `rollback:*` |

## セキュリティ上の注意
- deploy ジョブは**本番サービスを root で再起動**します。Runner とデプロイ鍵の権限は絞る
  （専用 deploy ユーザ＋制限 sudo、または root 鍵を Protected 変数に）。
- `deploy:*` は `when: manual` ＋ Protected branch/環境で、誤操作・不用意な本番切替を防ぐ。
- レジストリを使う場合（NFS tar の代替）: GitLab Container Registry に push し、ノードで
  `podman pull`（要 registry 認証）。現行は NFS 配布で完結しているので、まずはそのままで可。

## 補足
- BuildKit キャッシュを runner ホストに残すことがビルド時間短縮の鍵（shell executor＋常駐）。
- 2ノードを常に同一版へ揃える運用が前提（`deploy:sec`→`deploy:pri` の順で実施）。
- 検証を強化したい場合、`deploy:*` に POP3S/LDAP/ACME 等の疎通チェックを追加できる。
