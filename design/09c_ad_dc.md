# 自作 Active Directory ドメインコントローラ（Option 3・トレーサーバレット）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-08-07 |
| ステータス | PoC（トレーサーバレット、impacket 等で e2e 検証済み） |
| ハブ | [09b_daemon_integration.md](09b_daemon_integration.md)（組込みサービス方針）、[07_data_ldap.md](07_data_ldap.md)（ディレクトリデータ） |

> 本書は Magnetite が**外部依存（Samba/MIT KDC 等）を使わず**、Rust で一から実装した Active Directory ドメインコントローラ（AD DC）機能の総括である。
> 位置づけは**トレーサーバレット PoC**：各プロトコルを「クライアント（主に impacket、一部 MIT kinit / Samba GPParser / ldap3）が実際に受理する最小実装」として作り、**すべて実クライアントで end-to-end 検証**する方針で積み上げた。フルの本番実装ではなく、相互運用が成立する範囲を実証したもの。
> 認証情報の注意：`alice`/`password12`・`bob`/`bobpass123`・`Machine123` は PoC 用ダミーであり実在資格情報ではない。

## 1. 目的とスコープ

Magnetite の LDAP ドメイン（[07_data_ldap.md](07_data_ldap.md)）は当初「RFC4533 syncrepl / AD DirSync でリードオンリー取込み」までだった。本作業は逆方向、すなわち **Magnetite 自身が AD DC として振る舞い、Windows / impacket クライアントに対して Kerberos・DCE/RPC・SMB・LDAP・DNS を提供する**面を実装する。

達成済み（実クライアントで検証）：

- Kerberos KDC（AS/TGS/PAC）＋ GSS-API（MIC/Wrap/AP-REP）
- DCE/RPC：SAMR・LSA・Netlogon セキュアチャネル・DRSUAPI（DCSync + レプリケーション完全面）
- SMB2：SYSVOL 提供・Kerberos 認証・`ncacn_np`（名前付きパイプ RPC）
- LDAP：bind/search に加え **書き込み（Modify/Add）**
- DNS：DC ロケータ SRV/A レコード
- CLDAP：netlogon ping（DC 発見）
- **ドメイン参加の書き込み経路**：マシンアカウント作成 → パスワード設定 → Kerberos 認証、を TCP(NTLM) と SMB パイプ(Kerberos) の両トランスポートで

スコープ外（明示）：フル Windows `Add-Computer` の実機 e2e（Windows VM 必要）、SMB3 signing/encryption、GPO の適用エンジン、フル UI/管理面。

## 2. クレート構成

| クレート | 役割 | 主なプロトコル |
|---|---|---|
| `magnetite-krb5` | Kerberos KDC + 鍵・GSS | AS/TGS/PAC、AP-REQ 検証、AP-REP、GSS MIC/Wrap、s2k、プリンシパルストア |
| `magnetite-rpc` | DCE/RPC（MS-RPCE） | SAMR、LSA/LSAT、Netlogon(MS-NRPC)、DRSUAPI(MS-DRSR)、NTLM/Kerberos RPC 認証 |
| `magnetite-smb` | SMB2 ファイル/パイプサーバ | negotiate、session-setup(NTLM/Kerberos)、SYSVOL、`ncacn_np` パイプ |
| `magnetite-ldap` | LDAP サーバ（`ldap3_proto`） | bind/search/RootDSE + **Modify/Add**、syncrepl provider、GPC |
| `magnetite-gpo` | GPO プロビジョニング | GPT.INI、MS-GPREG Registry.pol、GPC 属性 |
| `magnetite-dns` | 権威 DNS | A/AAAA/CNAME/MX/TXT/NS/PTR/SRV/CAA、DC ロケータ SRV/A |
| `magnetite-db` | 単一組込み DB（SurrealDB） | `ad_principal`（可逆鍵材料）、`entry`（LDAP）、`zone`/`record`（DNS）、DC ロケータ、コンピュータオブジェクト統合 |
| `magnetite-addc` | 全サーバの合成（lib + bin） | 上記を1プロセスに束ね、`AddcService`（EmbeddedService）として magnetite-server に組込み |

**単一の共有 `Directory`**（`magnetite-rpc`）がユーザ/グループ/ドメインの唯一の正で、SAMR・LSA・DRSUAPI・KDC がすべてここから応答する。DB モードでは `magnetite-db` の `ad_principal`（NT ハッシュ + Kerberos AES 鍵、平文なし）から構築する。

## 3. エンドポイント一覧

| ポート | プロトコル | 内容 | 認証 |
|---|---|---|---|
| 88/tcp,udp | Kerberos | KDC（kinit/TGS） | — |
| 445/tcp | SMB2 | SYSVOL + `IPC$` パイプ(`\pipe\{samr,lsarpc,netlogon}`) | NTLM / Kerberos |
| 1025/tcp | ncacn_ip_tcp | SAMR（直接 TCP） | 未認証読取 / NTLM |
| 1027/tcp | ncacn_ip_tcp | DRSUAPI（DCSync レプリケーション） | Kerberos(GSS) |
| 389/tcp | LDAP | bind/search/Modify/Add | simple bind |
| 389/udp | CLDAP | netlogon ping（DC 発見） | — |
| 53/udp,tcp | DNS | DC ロケータ SRV/A 等 | — |

（`magnetite-addc` bin の DB モードでは 389/tcp の LDAP も同一プロセス・共有 DB で提供。UDP389=CLDAP と TCP389=LDAP は共存。）

## 4. ドメイン参加のフローと実装状況

Windows のドメイン参加は「DC 発見 → 認証 → ディレクトリ書き込み」の順で進む。各段階の対応状況：

| 段階 | クライアント動作 | 実装 | 検証マーカー |
|---|---|---|---|
| ① DC 発見(DNS) | `_ldap._tcp.dc._msdcs.<dom>` 等 SRV を引く | `Db::seed_dc_locator`（起動時にゾーンへ投入） | （DNS ユニット/シード） |
| ② DC 発見(CLDAP) | UDP389 に netlogon ping | `cldap.rs`（NETLOGON_SAM_LOGON_RESPONSE_EX + CLDAP フレーミング） | `CLDAP-NETLOGON-OK` |
| ③ Kerberos | kinit/TGS/AP-REQ | `magnetite-krb5`（AS/TGS/PAC/AP-REQ/AP-REP） | `TGS-INTEROP-OK`, `IMPACKET-PAC-OK` |
| ④ マシン作成 | SAMR `CreateUser2InDomain`(opnum50) | RID 割当 + KDC 動的登録 + 永続化 | `SAMR-CREATEUSER2-OK`, `MACHINE-JOIN-AUTH-OK` |
| ⑤ パスワード設定 | SAMR `SetInformationUser2`(opnum58, Internal5) | セッション鍵で SAMPR_ENCRYPTED_USER_PASSWORD を復号 | `SAMR-SETINFO-OK` |
| ⑥ 属性設定 | SAMR `SetInformationUser2`(UAC) / LDAP Modify | userAccountControl / dNSHostName / servicePrincipalName | `SAMR-UAC-OK`, LDAP Modify/Add テスト |
| ⑦ 認証確認 | マシンが kinit | KDC が発行 | `PIPE-WRITE-OK`, `PIPE-SETINFO-OK` |

未達：④〜⑥を Windows の `Add-Computer` が駆動する一連の実機シーケンス（Windows VM 必要）。個々の RPC/LDAP 操作は impacket で検証済み。

### 4.1 書き込み経路の二重トランスポート

SAMR 書き込み（CreateUser2 / SetInformationUser2[password] / UAC）は**両トランスポートで動作**する：

- **ncacn_ip_tcp:1025（NTLM）**：`serve_with_ntlm`。NTLM exported session key で SetInformationUser2 のパスワードバッファを復号。
- **ncacn_np（Kerberos SMB パイプ）**：SMB session-setup で得た Kerberos セッション鍵を**先頭16バイトに切り詰めて**（SMB2 の仕様）パイプへ伝播し、`call_with_session` に渡す。impacket の `smb.getSessionKey()`（AES256 鍵の先頭16バイト）と一致することをダンプで実証。

## 5. 実装の要点（プロトコル別）

### 5.1 Kerberos（`magnetite-krb5`）
`picky-krb` を使い AS-REQ(preauth)→TGT、TGS→サービスチケット、PAC（MS-PAC 二重署名を手 NDR で埋込）を実装。`verify_ap_req`（SMB/RPC の Kerberos 認証で共用）、`build_ap_rep`（相互認証、acceptor subkey = GSS セッション鍵）、GSS-API MIC/Wrap（RFC4121、AES256、impacket と地上真値照合）。プリンシパルストアは**内部可変**（`Arc<PrincipalStore>` の `dynamic` マップ）で、SAMR が作成したマシンを実行時登録できる。

### 5.2 DCE/RPC（`magnetite-rpc`）
接続指向 PDU + BIND(NDR32) + REQUEST/RESPONSE/FAULT。認証は NTLM SSP（exported session key、PKT_INTEGRITY 署名）と Kerberos GSS（PKT_INTEGRITY 署名 + PKT_PRIVACY 封緘）。
- **SAMR**：Connect/LookupDomain/EnumDomains/OpenDomain/EnumUsers（読取）＋ **CreateUser2InDomain / SetInformationUser2[password, UAC] / QueryInformationUser2**（書込）。作成アカウントは KDC + `AccountStore`（DB 永続化 + LDAP computer 統合）へ波及。
- **LSA/LSAT**：OpenPolicy2 / QueryInformationPolicy2 / LookupSids。
- **Netlogon**：ReqChallenge + Authenticate3 セキュアチャネル、sign/seal、NetrLogonSamLogonEx、**NetrServerPasswordSet2(opnum30)**——参加済みマシンがセキュアチャネル経由で自身のパスワードを変更（authenticator チェーン検証 + セッション鍵で `NL_TRUST_PASSWORD` を AES-CFB8 復号 → 新パスワード採用）。
- **DRSUAPI**：DRSBind + DRSGetNCChanges で **レプリケーション完全面**——オブジェクトチェーン（複数）+ DCSync シークレット（暗号化 unicodePwd）+ カーソル(`usnvecFrom`) + `usnvecTo` + `pUpToDateVecSrc`(V2) + ページング(`fMoreData`)。

### 5.3 SMB2/3（`magnetite-smb`）
dialect **2.1 / 3.0 / 3.1.1（negotiate で選択）**。negotiate + session-setup（NTLM SPNEGO / Kerberos AP-REQ）+ SYSVOL の path ベース create/read + QUERY_DIRECTORY（GPO ツリー）。`IPC$` に `ncacn_np` パイプを露出し、WRITE/READ で RPC PDU を `magnetite_rpc::RpcPipe` に橋渡し。Kerberos セッション鍵をパイプの `call_with_session` へ伝播（§4.1）。**SMB 3.0 メッセージ保護**：クライアントが暗号化を提示すれば **AES-128-CCM 暗号化**（`enc.rs`、`SMB2_TRANSFORM_HEADER` でラップ、鍵 = KDF(セッション鍵16B, "SMB2AESCCM"/"ServerOut"·"ServerIn ")、nonce 11B・tag 16B・AAD=header[20:52]）、そうでなければ **AES-128-CMAC 署名**（`sign.rs`、SigningKey = KDF(…, "SMB2AESCMAC"/"SmbSign")）。暗号化トリガはサーバ応答の `SMB2_GLOBAL_CAP_ENCRYPTION` 広告。**SMB 3.1.1（0x0311）**では negotiate contexts（SHA-512 preauth-integrity + AES-128-CCM cipher + LZ77 compression）を交換し、**preauth-integrity ハッシュ（SHA-512 チェーン：negotiate/session-setup を連結、成功応答は除外）を鍵導出の context に使用**（enc/dec = KDF(セッション鍵, "SMBS2CCipherKey"/"SMBC2SCipherKey", preauth hash)）。**マルチチャネル**：`MULTI_CHANNEL` cap 広告 + `FSCTL_QUERY_NETWORK_INTERFACE_INFO`（IOCTL）で `NETWORK_INTERFACE_INFO` を返す（暗号化セッション上で検証）。**圧縮**（`comp.rs`）：MS-XCA Plain LZ77 + `SMB2_COMPRESSION_TRANSFORM_HEADER`（`\xFCSMB`）—— impacket は圧縮トラフィックを駆動しないため negotiate context 受理 + unit（round-trip）検証。**cipher 折衝**：クライアントの `SMB2_ENCRYPTION_CAPABILITIES` を解析し、実装する **4 cipher（AES-128/256 × CCM/GCM）から最強のもの**を選択（優先度 AES-256-GCM > -256-CCM > -128-GCM > -128-CCM、`enc::Cipher`）。AES-256 は 32バイト鍵（KDF L=256）。impacket の SMB 層は AES-128-CCM 固定のため GCM/AES-256 は pycryptodome を基準に ground-truth + unit 折衝で検証（CCM128 は e2e）。クロス接続の channel binding は範囲外。

### 5.4 LDAP（`magnetite-ldap`）
`ldap3_proto` コーデック。simple bind + search（base/one/subtree + filter）+ **AD 対応 RootDSE**（schemaNamingContext/configurationNamingContext/subschemaSubentry/supportedCapabilities=LDAP_CAP_ACTIVE_DIRECTORY_OID 等）+ **subschema subentry でコア AD スキーマ発見**（`schema.rs`、~40 属性/11 クラスを RFC 4512 で提供）+ **AD 運用属性の合成**（検索時に objectGUID/distinguishedName/objectCategory/name/whenCreated/whenChanged を合成、格納値優先・syncrepl 経路は除外）+ **スキーマ強制**（Add/Modify をコアスキーマで検証）—— いずれも ldap3 で検証。**スキーマ強制**（`schema::validate_new_entry`）は Add 時に (1) objectClass の上位クラス連鎖を解決（未知クラス→objectClassViolation=65）(2) 構造クラスがちょうど1つ (3) MUST 属性が全て存在（RDN 属性と objectClass もカウント）(4) 各属性が定義済み（未定義→undefinedAttributeType=17）かつ MUST∪MAY で許可、を検証。Modify では未定義属性の Add/Replace を 17 で拒否。person の MUST は AD 準拠で `[cn]` に緩和。加えて **書込 CRUD 全部**：Modify（RFC4511 §4.6）/ Add（§4.7）/ **Delete（§4.8）** / **ModifyDN・rename（§4.9）**（いずれも認証必須・ACL ゲート）。`Db::create_entry` / `modify_entry` / `delete_entry`（非葉拒否・group member 除去・changelog tombstone）/ `rename_entry`（葉のみ・deleteOldRDN で RDN 属性調整・reparent・group member 書換）で永続化、`userPassword` は Argon2 列へ。computer オブジェクトも Add で作成可能。

### 5.5 DNS / CLDAP（DC 発見）
`Db::seed_dc_locator` が `_kerberos`/`_ldap`/`_gc` の SRV と `magnetite.<dom>`/apex の A を DNS ゾーンへ投入（べき等）。CLDAP は `magnetite-addc::cldap` が UDP389 で netlogon ping に `NETLOGON_SAM_LOGON_RESPONSE_EX`(V5EX) を返す。

### 5.6 統合（`magnetite-addc`）
`AddcService`（`EmbeddedService`）が KDC+SMB+RPC/SAMR+DRSUAPI+CLDAP を1プロセスで起動し、magnetite-server に組込み可能（フル server はコンテナではビルド重すぎるため、addc デーモンが同一の組込みサービスコードで検証）。SAMR 作成マシンは `AccountStore` 経由で **`ad_principal` と LDAP computer オブジェクトの両方**へ統合される。

## 6. 検証済み e2e 一覧（相互運用マーカー）

すべて Debian コンテナ（`rust:1-slim-bookworm` + impacket/ldap3、`nerdctl`）で実クライアント検証。

| マーカー | 内容 |
|---|---|
| `TGS-INTEROP-OK` / `IMPACKET-PAC-OK` | MIT kinit + kvno / impacket PAC デコード |
| `DRS-{NTLM,KERBEROS}-DCSYNC-OK` / `-PRIVACY-OK` | DCSync で NT ハッシュ回収（署名 + 封緘） |
| `DRS-MULTI-OBJECT-OK` / `-CURSOR-OK` / `-UTDV-OK` / `-PAGING-OK` | レプリケーション面（チェーン/カーソル/UTDV/ページング） |
| `SMB-{SYSVOL,KERBEROS}-INTEROP-OK` / `NP-INTEROP-OK` | SYSVOL 読取 / Kerberos SMB / パイプ RPC |
| GPO（GPParser / ldap3 GPC） | Registry.pol パース / GPC 発見 |
| `DIRECTORY-INTEROP-OK` / `ADDC-FULL-INTEGRATION-OK` | 共有ディレクトリ / 全5面フロー |
| `CLDAP-NETLOGON-OK` | CLDAP DC 発見 |
| `SAMR-CREATEUSER2-OK` / `MACHINE-JOIN-AUTH-OK` | マシン作成 → Kerberos 認証 |
| `SAMR-SETINFO-OK` / `SAMR-UAC-OK` / `SAMR-PERSIST-OK` | パスワード設定 / UAC / 再起動後も永続 |
| LDAP Modify/Add（Rust 統合テスト） | dNSHostName/SPN 設定 / computer オブジェクト作成 |
| `SERVER-UNIFY-OK` | 1回の SAMR 作成が ad_principal + LDAP computer に反映（実行中プロセス） |
| `PIPE-WRITE-OK` / `PIPE-SETINFO-OK` | Kerberos SMB パイプ経由の書き込み（作成/UAC/パスワード） |
| `NETLOGON-PWSET-OK` | NetrServerPasswordSet2 でマシンパスワード変更 → 新パスワードで再認証成功・旧パスワード拒否 |
| `SMB3-SIGN-OK` | SMB 3.0 AES-CMAC 署名（dialect 0x0300, SIGNING_REQUIRED）双方向検証 |
| `SMB3-ENC-OK` | SMB 3.0 AES-CCM 暗号化（TRANSFORM_HEADER, ServerIn/ServerOut 鍵）双方向検証 |
| `SMB3-311-OK` | SMB 3.1.1（negotiate contexts + preauth-integrity ハッシュ + 3.1.1 鍵導出 + CCM）検証 |
| `SMB-MC-OK` | マルチチャネル（MULTI_CHANNEL cap + FSCTL ネットワークインターフェース照会）+ 圧縮 context 受理 |

## 7. 設定と実行

`magnetite.toml` の `[domains.addc]` + `[domains.addc.server.addc]`（realm/各 listen/dc_ipv4/cldap_listen）で有効化。特権ポート（88/389/445）のため root 実行またはローカルは高ポートへ上書き。標準の addc bin は環境変数（`REALM`/`KDC_ADDR`/`MAGNETITE_DB_PATH` 等）でも設定可能。

```toml
[domains.addc.server.addc]
realm      = "EXAMPLE.COM"
kdc_listen = "0.0.0.0:88"
smb_listen = "0.0.0.0:445"
rpc_listen = "0.0.0.0:1025"
drs_listen = "0.0.0.0:1027"
```

## 8. 残件

- 実 Windows `Add-Computer` の end-to-end（Windows VM + DC 発見→LDAP/SAMR→Kerberos の一連）。個々の操作は検証済みだが、Windows クライアントが駆動する完全シーケンスは未実施。
- SMB3 signing/encryption、SMB2 の完全な KDF（現状 2.1 相当。SAM パスワードのセッション鍵は先頭16バイト切り詰めで一致）。
- GPO 適用エンジン、LDAP の Delete/ModifyDN、フル管理 UI。
- DRSUAPI の incremental sync は `usnvecFrom`/`usnvecTo`/`pUpToDateVecSrc`/`fMoreData` ページングまで実装済み。宛先 DC の UTDV を用いた真の差分最小化までは未実装。

> 関連メモリ（実装詳細の一次情報）：`ad-dc-kerberos-poc` / `ad-dc-rpc-poc` / `ad-dc-smb-poc` / `ad-dc-gpo-poc` / `ad-dc-directory` / `ad-dc-integration`。
