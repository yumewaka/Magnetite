# データモデル：LDAP（ディレクトリ）ドメイン

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |
| ハブ | [07_data_model.md](07_data_model.md)（規約・共有構造） |

> 本書は LDAP ドメインのデータ種別の**固有フィールド**を定義する。
> **前提（ハブ §3.1／方針）**：全永続エンティティは共通フィールド（`id`/`created_at`/`updated_at`/`created_by`）を継承するため**再掲しない**。`tenant` は持たない。監査（AuditEntry）/アラート（Alert）/テンプレート（Template）/バックアップ（Backup）/運用ログ（LogEntry）は横断共有構造（ハブ §3）を参照する。単一組込みDBが唯一の正。
> **重要（混同禁止）**：本ドメインの `User`/`Group` は*ディレクトリ上の管理データ*（DIT のエントリ）であり、Magnetite のログイン識別（`LocalAccount`/`Session`：ハブ §3.7/§3.8）とは**別物**。ここで定義するユーザは「ポータルにログインする人」ではなく「LDAP で管理される対象」である。

## 1. 種別一覧

| データ種別 | 説明 | 定義 |
|---|---|---|
| `DirectoryEntry` | 汎用ディレクトリエントリ（DN/RDN・objectClass・任意属性）。DIT の1ノード | §2.1 |
| `User` | ユーザエントリ（inetOrgPerson 系。uid/cn/sn/mail/enabled 等） | §2.2 |
| `Group` | グループエントリ（groupOfNames 系。member 参照） | §2.3 |
| `OrgUnit`（OU） | 組織単位。ツリー階層の中間ノード | §2.4 |
| `AclRule` | アクセス制御ルール（対象DN・主体・操作・効果） | §2.5 |
| `Schema` | スキーマ定義（属性型 AttributeType／オブジェクトクラス ObjectClass） | §2.6 |

> `User`/`Group`/`OrgUnit` は概念的には特定の `objectClass` を持つ `DirectoryEntry` の特化ビューである（DN/RDN・objectClass・親子関係の基盤は §2.1 が担う）。永続化上は「エントリ本体（§2.1）＋種別固有属性」で表現し、種別ごとの固有フィールドを §2.2〜§2.4 に定義する。

## 2. 固有フィールド定義

### 2.1 DirectoryEntry（汎用エントリ／DIT ノード）

DIT（ディレクトリ情報ツリー）を構成する基本単位。親子は DN の階層で表現する。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `dn` | String（DN） | ○ | 全体一意。RFC 4514 形式 | 識別名。ツリー内の絶対パス（例 `uid=jsmith,ou=People,dc=example,dc=com`） |
| `rdn` | String | ○ | `dn` の最左要素と一致 | 相対識別名（表示・改名用。例 `uid=jsmith`） |
| `parent_dn` | ref→DirectoryEntry(dn) / null | ○※ | ルート（base DN）のみ null | 親エントリの DN。**ツリー親子構造の要**（§3 参照） |
| `object_classes` | Set\<String\> | ○ | 少なくとも1つ。うち1つが structural | このエントリの objectClass 群（例 `top,person,organizationalPerson,inetOrgPerson`） |
| `structural_class` | String | ○ | `object_classes` に含まれる | 構造オブジェクトクラス（エントリ種別の主判定） |
| `attributes` | Map\<String, Vec\<String\>\> | ○ | 属性名は Schema に存在 | 属性名→値（複数値対応）。cn/sn/mail 等の実体はここに格納 |
| `has_children` | bool | ○ | 導出可 | 配下エントリの有無（ツリー表示・削除ガード用） |
| `when_created` | DateTime | 任意 | — | ディレクトリ上の作成日時（LDAP 由来。共通 `created_at` とは別系統） |
| `when_changed` | DateTime | 任意 | — | ディレクトリ上の最終変更日時 |

> DN は不変ではなく **改名（modrdn）**で変化しうる。改名時は `rdn`/`dn` と配下エントリの `dn`/`parent_dn` を連動更新する（意味論は 09）。

### 2.2 User（ユーザエントリ）

`objectClass` に `inetOrgPerson`（および `person`/`organizationalPerson`/`top`）を持つエントリの特化ビュー。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `dn` | String（DN） | ○ | §2.1 と同一 | ユーザエントリの DN |
| `uid` | String | ○ | ディレクトリ内一意（RDN に採用可） | ユーザ識別子（uid 属性） |
| `cn` | String | ○ | — | 一般名（Common Name。フルネーム表示） |
| `sn` | String | ○ | inetOrgPerson の必須 | 姓（Surname） |
| `given_name` | String | 任意 | — | 名（givenName） |
| `display_name` | String | 任意 | — | 表示名（displayName） |
| `sam_account_name` | String | 任意 | 一意 | アカウント名（sAMAccountName 互換。AD 系互換用） |
| `mail` | String（Email） | 任意 | RFC 5321 形式 | メールアドレス（mail 属性） |
| `enabled` | bool | ○ | 既定 true | アカウント有効フラグ（無効化＝ログイン不可扱い） |
| `password_ref` | opaque（保存形式は 09） | 任意 | 平文非保持 | userPassword（ハッシュ）。**値は返却しない**。リセットのみ |
| `member_of` | Vec\<ref→Group(dn)\> | 任意 | 導出（Group.members の逆引き） | 所属グループ（表示用の逆参照。正は Group 側） |

> `enabled`/`password_ref` は**ディレクトリ上のユーザ状態**であり、ポータルのログイン（`LocalAccount.enabled`／`password_hash`：ハブ §3.7）とは無関係。

### 2.3 Group（グループエントリ）

`objectClass` に `groupOfNames`（または `groupOfUniqueNames`）を持つエントリの特化ビュー。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `dn` | String（DN） | ○ | §2.1 と同一 | グループエントリの DN |
| `cn` | String | ○ | RDN に採用 | グループ名（Common Name） |
| `sam_account_name` | String | 任意 | 一意 | アカウント名（AD 系互換） |
| `description` | String | 任意 | — | 説明 |
| `members` | Vec\<ref→DirectoryEntry(dn)\> | ○ | 各値は存在する DN（通常 User、ネスト時 Group 可） | メンバーの DN 一覧（member 属性）。**Group→User の主参照** |
| `group_type` | GroupType (security/distribution) | 任意 | — | 種別（セキュリティ/配布） |

> groupOfNames は空 member を許さない実装があるため、最後の1件削除の扱いは 09 に従う。

### 2.4 OrgUnit（OU／組織単位）

`objectClass` に `organizationalUnit` を持つ中間ノード。ツリー階層を形成する。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `dn` | String（DN） | ○ | §2.1 と同一 | OU の DN（例 `ou=People,dc=example,dc=com`） |
| `ou` | String | ○ | RDN に採用（`ou=`） | OU 名（ou 属性） |
| `name` | String | 任意 | — | 表示名 |
| `description` | String | 任意 | — | 説明 |
| `parent_dn` | ref→DirectoryEntry(dn) / null | ○ | ルートのみ null | 親（上位 OU または base DN）。**OU 階層の要** |
| `child_count` | usize | 任意 | 導出 | 直下エントリ数（削除ガード表示用。§3 参照） |

### 2.5 AclRule（アクセス制御ルール）

対象 DN サブツリーに対する主体（subject）の操作可否を定める。

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `rule_id` | String | ○ | 一意（生成 ID） | ルール識別子 |
| `target_dn` | ref→DirectoryEntry(dn) | ○ | 存在する DN またはサブツリー式 | 適用対象 DN（配下サブツリーに及ぶ） |
| `scope` | AclScope (entry/subtree) | 任意 | 既定 subtree | 対象範囲（当該エントリのみ/配下含む） |
| `subject` | String（`dn:...` / `group:...` / `self` / `anonymous` 等） | ○ | — | 適用主体（DN・グループ・特殊主体） |
| `operations` | Set\<AclOp (read/write/add/delete/search/compare)\> | ○ | 少なくとも1つ | 対象操作 |
| `effect` | AclEffect (allow/deny) | ○ | — | 効果。deny 優先の評価順は 09 |
| `priority` | i32 | 任意 | 既定 0 | 評価優先度（競合解決） |

### 2.6 Schema（スキーマ定義）

ディレクトリのスキーマ。属性型（AttributeType）とオブジェクトクラス（ObjectClass）の2サブ種別。

#### 2.6.1 AttributeType（属性型定義）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | 属性名（例 `cn`, `mail`, `uid`） |
| `oid` | String（OID） | ○ | 一意・数値ドット表記 | オブジェクト識別子 |
| `syntax` | String（OID） | ○ | — | 値構文（例 Directory String, IA5 String） |
| `single_valued` | bool | ○ | 既定 false | 単一値制約（false=複数値可） |
| `description` | String | 任意 | — | 説明 |
| `superior` | ref→AttributeType(name) | 任意 | — | 上位属性型（継承元） |

#### 2.6.2 ObjectClass（オブジェクトクラス定義）

| フィールド | 型 | 必須 | 制約 | 説明 |
|---|---|---|---|---|
| `name` | String | ○ | 一意 | オブジェクトクラス名（例 `inetOrgPerson`） |
| `oid` | String（OID） | ○ | 一意 | オブジェクト識別子 |
| `kind` | OcKind (structural/auxiliary/abstract) | ○ | — | 種別 |
| `superior` | ref→ObjectClass(name) | 任意 | 既定 `top` | 上位オブジェクトクラス（継承元） |
| `must_attributes` | Set\<ref→AttributeType(name)\> | ○ | 各値は AttributeType に存在 | 必須属性（MUST） |
| `may_attributes` | Set\<ref→AttributeType(name)\> | 任意 | 各値は AttributeType に存在 | 任意属性（MAY） |
| `description` | String | 任意 | — | 説明 |

## 3. 参照

### 3.1 参照元 → 参照先

| 参照元 | 参照先 | 関係 |
|---|---|---|
| DirectoryEntry.parent_dn / OrgUnit.parent_dn | DirectoryEntry(dn) / OrgUnit(dn) | ツリー親子（DIT 階層） |
| User.dn / Group.dn / OrgUnit.dn | DirectoryEntry(dn) | 特化ビュー↔本体（同一 DN） |
| Group.members | DirectoryEntry(dn)（通常 User、ネスト時 Group） | グループメンバー（Group→User） |
| User.member_of | Group(dn) | 所属（Group.members の逆引き。導出） |
| AclRule.target_dn | DirectoryEntry(dn)（サブツリー） | ACL 適用対象 |
| AclRule.subject（`dn:`/`group:`） | User(dn) / Group(dn) | ACL 適用主体 |
| DirectoryEntry.object_classes / structural_class | Schema.ObjectClass(name) | エントリ↔スキーマ |
| Schema.ObjectClass.must/may_attributes | Schema.AttributeType(name) | スキーマ内参照 |
| Schema.ObjectClass.superior | Schema.ObjectClass(name) | 継承 |
| Schema.AttributeType.superior / .syntax | AttributeType / Syntax | 継承・構文 |

### 3.2 参照先 → 参照元（削除影響の逆引き）

| 参照先（削除/変更対象） | 再検証する参照元 | 方針 |
|---|---|---|
| OrgUnit（OU） | 配下 DirectoryEntry / User / Group / 子 OU（parent_dn） | **配下エントリがある OU は削除不可**。空でない場合は拒否（AC-15：`この OU には配下エントリがあります。先に配下エントリを移動または削除してください。`）。移動または削除後に再実行 |
| DirectoryEntry / User（削除・改名） | Group.members / AclRule.subject / AclRule.target_dn / User.member_of | メンバー・ACL 主体からの当該 DN 参照を除去または再検証。改名（modrdn）時は配下と参照 DN を連動更新 |
| Group（削除） | User.member_of（導出）/ AclRule.subject(`group:`) | 所属表示を再計算。ACL 主体参照は無効化または要見直し |
| DirectoryEntry 改名（DN 変更） | 配下エントリの dn/parent_dn / 各 DN 参照（members/target_dn/subject） | サブツリー全体の DN を再構成し、全参照を追従 |
| Schema.ObjectClass / AttributeType | 使用中の DirectoryEntry.object_classes / attributes / 他スキーマの superior・must/may | **使用中スキーマは削除不可**。参照エントリ・派生クラスが存在する間は拒否 |

> 監査/アラート/テンプレート/バックアップ/運用ログは横断共有構造（ハブ §3）を利用し、本ドメインでは再定義しない。ドメイン横断の参照集約はハブ §5.3（Phase 4 仕上げ）で統合する。
