# データモデル：K8s（コンテナ）ドメイン

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| ハブ | 07_data_model.md（§3 共有構造・規約が正） |

> 本書は K8s（コンテナ）ドメインの**固有フィールド**のみを定義する。
> - 共通フィールド（`id` / `created_at` / `updated_at` / `created_by`）は **§3.1 を継承＝再掲しない**。
> - **tenant は持たない**（単一DBが正）。
> - アラート本体は **§3.3 Alert**、通知先は **§3.4 NotificationTarget**、テンプレは **§3.5 Template**、バックアップは **§3.6 Backup** を参照（本書で再定義しない）。
> - K8s 固有は **AlertRule（Alert を生成する側の定義）のみ**。発生アラート・確認応答・重大度・状態遷移は §3.3 Alert に集約。

## 1. 対象データ種別

| データ種別 | 説明 | 定義 |
|---|---|---|
| `Host` | コンテナホスト（K8s ノードとなる物理／仮想マシン。SSH 接続先） | §2 |
| `Cluster` | K8s クラスタ（構成ノード・ネットワーク・バージョン・エンドポイント） | §3 |
| `AlertRule` | K8s アラートルール（Alert を生成する側の定義） | §4 |
| Template（K8s） | K8s リソースの YAML テンプレ → **§3.5 Template**（body スキーマは §5） | §5 |
| Backup（K8s） | クラスタ構成（etcd 等）バックアップ → **§3.6 Backup**（body スキーマは §5） | §5 |
| Alert（発生アラート） | AlertRule が生成 → **§3.3 Alert**（本書で再定義しない） | ハブ§3.3 |

## 2. Host（コンテナホスト）

共通フィールド（§3.1）を継承。以下は固有フィールド。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `hostname` | String | ○ | 一意 | ホスト名 |
| `address` | IpAddr | ○ | IPv4/IPv6 | 管理・SSH 接続先アドレス |
| `ssh_port` | u16 | ○ | 1–65535／既定 22 | SSH ポート番号 |
| `ssh_user` | String | ○ | — | SSH 接続ユーザー名 |
| `auth_method` | HostAuthMethod (enum: password / key) | ○ | — | 認証方式 |
| `credential_ref` | ref→機密ストア | ○ | 機微値は非平文（マスク／参照保持） | 認証情報（パスワード／秘密鍵）の参照 |
| `role` | HostRole (enum: control_plane / worker) | 任意 | クラスタ所属時に確定 | クラスタ内ノードロール |
| `cluster_ref` | ref→Cluster | 任意 | 未所属時 None | 所属クラスタ |
| `state` | HostState (enum: ready / online / offline / error) | ○ | 既定 offline | ホスト稼働状態 |

> 登録時入力（旧 `CreateContainerHost`）は上記のうち `hostname` / `address` / `ssh_port` / `ssh_user` / `auth_method` / `credential_ref` を必須とする。`role` / `cluster_ref` はクラスタ構成時に付与。

## 3. Cluster（K8s クラスタ）

共通フィールド（§3.1）を継承。以下は固有フィールド。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | クラスタ名 |
| `k8s_version` | String | ○ | semver（例 `1.30.2`） | Kubernetes バージョン |
| `api_server_endpoint` | URL | 任意 | `https://host:port` | API サーバーエンドポイント |
| `pod_cidr` | CIDR | ○ | 有効な CIDR | Pod ネットワーク CIDR |
| `service_cidr` | CIDR | ○ | 有効な CIDR／pod_cidr と非重複 | Service ネットワーク CIDR |
| `cni` | String | ○ | 例 `calico` / `flannel` | CNI プラグイン名 |
| `nodes` | Vec\<ClusterNode\> | ○ | §3.1 参照 | 構成ノード一覧 |
| `node_count` | u64 | ○ | `nodes.len()` と整合（導出値） | 構成ノード数 |
| `state` | ClusterState (enum: ready / error / failed) | ○ | 既定 error | クラスタ稼働状態 |

### 3.1 ClusterNode（構成ノード・埋め込み）

Cluster に埋め込まれるノード要素（独立エンティティではなく Host への参照を含む射影）。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `host_ref` | ref→Host | ○ | — | 構成ノードの実体 Host |
| `hostname` | String | ○ | Host 由来 | ノードのホスト名（表示用スナップショット） |
| `address` | IpAddr | ○ | Host 由来 | ノードアドレス（表示用スナップショット） |
| `role` | HostRole (enum: control_plane / worker) | ○ | — | ノードロール |
| `state` | HostState | ○ | — | ノード状態 |

## 4. AlertRule（K8s アラートルール）

**K8s 固有。Alert（§3.3）を生成する側の定義。** 発生アラート・確認応答・状態遷移・通知配信は本書で持たず §3.3 / §3.4 に委譲する。

共通フィールド（§3.1）を継承。以下は固有フィールド。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | ルール名 |
| `target_ref` | ref→Cluster（または Host） | ○ | 対象種別は `target_kind` で区別 | 監視対象 |
| `target_kind` | AlertTargetKind (enum: cluster / host) | ○ | 既定 cluster | 対象種別 |
| `condition` | AlertConditionKind (enum: cpu / memory / pod_restart / node_not_ready) | ○ | — | 判定条件（メトリクス種別） |
| `comparator` | Comparator (enum: gt / gte / lt / lte) | ○ | 既定 gte | 閾値比較演算子 |
| `threshold` | f64 | ○ | condition に応じた単位（% / 回数等） | 閾値 |
| `severity` | Severity (critical / warning / info) | ○ | 生成 Alert の severity に反映 | 発火時の重大度 |
| `enabled` | bool | ○ | 既定 true | 有効／無効（無効時は Alert を生成しない） |

> 生成される発生アラートは §3.3 Alert（`domain=k8s` / `rule_ref`→本 AlertRule / `source_ref`→対象 Cluster・Host / `severity`）として記録される。通知は §3.4 NotificationTarget（`domains` に k8s を含む／`min_severity` 以上）へ配信される。ルール個別の Webhook は §3.4 に集約し、AlertRule 側には持たない。

## 5. Template / Backup（K8s body スキーマのみ）

Template・Backup の本体は **§3.5 Template** / **§3.6 Backup** で定義（`domain=k8s`）。本書は K8s の `body` / `artifact` スキーマのみ言及する。

### 5.1 Template.body（§3.5・domain=k8s）

| キー | 型 | 必須 | 説明 |
|---|---|---|---|
| `resource_kind` | K8sResourceKind (enum: Deployment / Service / ConfigMap / Job) | ○ | K8s リソース種別 |
| `manifest_yaml` | String（YAML） | ○ | マニフェスト本体 |
| `description` | String | 任意 | 説明（§3.5 の `description` を使用可） |

### 5.2 Backup.artifact（§3.6・domain=k8s）

| 観点 | 内容 |
|---|---|
| 対象 | クラスタ構成（etcd スナップショット等） |
| body/メタ | `cluster_ref`（対象クラスタ）／`source_node`（取得元ノードのホスト名）を `artifact_ref` 参照先メタに保持 |
| その他 | `size_bytes` / `format_version` / `kind`（manual/auto）は §3.6 に従う |

## 6. 参照関係

### 6.1 参照元 → 参照先

| 参照元 | 参照先 | 関係 |
|---|---|---|
| `Host.cluster_ref` | Cluster | 所属クラスタ |
| `Cluster.nodes[].host_ref` | Host | 構成ノードの実体 |
| `AlertRule.target_ref` | Cluster / Host（`target_kind` で区別） | 監視対象 |
| 生成 `Alert.rule_ref`（§3.3） | AlertRule | 生成元ルール |
| 生成 `Alert.source_ref`（§3.3） | Cluster / Host | 発生対象 |
| Template（§3.5）/ Backup（§3.6）の `domain` | DomainKey=`k8s` | 所属ドメイン |

### 6.2 参照先 → 参照元（削除影響の逆引き）

| 参照先（削除／変更対象） | 再検証する参照元 | 方針 |
|---|---|---|
| Host | Cluster.nodes[].host_ref / AlertRule.target_ref(host) | クラスタ構成中の Host は削除前に離脱（cluster_ref 解除）を要求。host 対象の AlertRule は無効化／対象再指定。 |
| Cluster | Host.cluster_ref / AlertRule.target_ref(cluster) / 生成 Alert.source_ref / Backup | 削除時、所属 Host の `cluster_ref` を解除（Host 実体は保持）。cluster 対象 AlertRule は無効化。生成済み Alert・Backup は履歴として保持。 |
| AlertRule | 生成済み `Alert.rule_ref`（§3.3） | **ルール削除時、生成済み Alert の `rule_ref` は保持（履歴保持）**、以後の生成を停止（**ハブ §5.2 準拠**）。 |

> ドメイン無効化（DomainKey=`k8s`）時の Template/Backup/Alert/NotificationTarget の扱いはハブ §5.2 に従う（既存データ保持・新規操作停止）。
