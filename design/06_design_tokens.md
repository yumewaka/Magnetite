# デザイントークン：Magnetite（統合再設計版）

| 項目 | 内容 |
|---|---|
| ドキュメントバージョン | 0.1（ドラフト） |
| 最終更新日 | 2026-07-05 |
| ステータス | ドラフト |

色・余白・フォント等を一元管理し、画面仕様（S-xx）と標準UI（10）から参照する。実装時はこの値を単一の情報源(SSoT)とする。
方針：**ライト基本＋ダーク対応**（テーマ切替 F-09）。CSS変数で両テーマを供給し、状態色は**色＋テキスト/アイコン**で色覚非依存とする。

## 1. カラー（ライト）

| トークン名 | 用途 | 値 |
|---|---|---|
| color.primary | 主要アクション（作成/保存/リンク） | #2563EB |
| color.on-primary | primary上の文字 | #FFFFFF |
| color.bg | 背景（コンテンツ） | #FFFFFF |
| color.bg-subtle | 補助背景（サイドバー/ヘッダー/行ホバー） | #F8FAFC |
| color.surface | カード/フォーム面 | #FFFFFF |
| color.text | 本文 | #1F2937 |
| color.text-muted | 補助テキスト | #6B7280 |
| color.border | 罫線 | #E5E7EB |
| color.focus | フォーカスリング | #3B82F6 |

## 1b. カラー（ダーク）

| トークン名 | 値 |
|---|---|
| color.bg | #0F172A |
| color.bg-subtle | #1E293B |
| color.surface | #1E293B |
| color.text | #E2E8F0 |
| color.text-muted | #94A3B8 |
| color.border | #334155 |
| color.primary | #3B82F6 |

## 2. 状態・重大度カラー（両テーマ共通の意味）

> 稼働状態（DomainStatus）とアラート重大度（Severity）で共通のセマンティクスを持たせる。バッジは必ずラベル併記。

| トークン名 | 用途 | 値（ライト/ダーク調整） |
|---|---|---|
| color.success | 成功／正常(Healthy) | #16A34A |
| color.warning | 警告(Warning)／warning アラート | #D97706 |
| color.danger | エラー(Error)／critical アラート／破壊的操作 | #DC2626 |
| color.info | 情報(info)／中立通知 | #0EA5E9 |
| color.unknown | 不明(Unknown)／未取得 | #94A3B8 |

| 状態バッジ | 色トークン | ラベル例 |
|---|---|---|
| ●正常 | success | 正常 / Healthy |
| ●警告 | warning | 警告 / Warning |
| ●異常 | danger | 異常 / Error |
| ○不明 | unknown | 不明 / Unknown |
| アラート open | danger/warning（重大度依存） | 未対応 |
| アラート acknowledged | info | 確認済 |
| アラート resolved | success/muted | 解決済 |
| メンテナンス抑止 | unknown | メンテナンス中 |

## 3. タイポグラフィ

| トークン名 | 用途 | サイズ / 行間 / 太さ |
|---|---|---|
| font.h1 | 画面タイトル | 24px / 1.3 / Bold |
| font.h2 | セクション見出し | 20px / 1.4 / Bold |
| font.h3 | カード見出し | 16px / 1.4 / SemiBold |
| font.body | 本文・テーブル | 14px / 1.6 / Regular |
| font.caption | 補助・メタ情報 | 12px / 1.5 / Regular |
| font.mono | ログ/コード/DN/JSON | 13px / 1.5 / Regular（等幅） |

- フォントファミリ：システムUIフォント優先（例：`system-ui, "Segoe UI", "Noto Sans JP", sans-serif`）。等幅は `ui-monospace, Consolas, monospace`。
- 日本語/英語混在に配慮し行間はやや広め。

## 4. スペーシング（余白）

| トークン名 | 値 |
|---|---|
| space.xs | 4px |
| space.sm | 8px |
| space.md | 16px |
| space.lg | 24px |
| space.xl | 32px |

## 5. 角丸・影・レイアウト

| トークン名 | 用途 | 値 |
|---|---|---|
| radius.sm | 入力/バッジ | 4px |
| radius.md | カード/フォーム/ダイアログ | 8px |
| elevation.1 | 行ホバー/軽い浮き | 0 1px 2px rgba(0,0,0,.08) |
| elevation.2 | カード | 0 2px 6px rgba(0,0,0,.10) |
| elevation.3 | スライドオーバー/ダイアログ | 0 8px 24px rgba(0,0,0,.16) |
| layout.sidebar-width | サイドバー幅 | 240px（折りたたみ 56px） |
| layout.header-height | ヘッダー高 | 56px |
| layout.content-max | コンテンツ最大幅 | 1440px |
| layout.slideover-width | 作成/編集スライドオーバー幅 | 480px |

## 6. アイコン／その他

| 項目 | 内容 |
|---|---|
| アイコンセット | 統一の1セット（線画系）を使用。ドメイン識別アイコンは `DomainConfig.icon` で指定 |
| 標準アイコンサイズ | 20px（行内）／24px（ナビ・ヘッダー） |
| フォーカス表示 | `color.focus` の 2px リングを常時可視化 |
| トースト | 成功=success／失敗=danger の左ボーダー＋アイコン、既定 4 秒で自動消去 |
| データテーブル | 行高 40px、ゼブラなし＋ホバー背景（bg-subtle）、ソート矢印は見出しに付与 |

> 本トークンは 10_standard_ui（標準UIキット）で各共通部品（page-header/data-table/form-card/ConfirmDialog/toast/badge）に割り当てる。
