# debugger-workstation

<!-- I18N:START -->
[English](README.md) · [简体中文](README.zh-CN.md) · **日本語** · [한국어](README.ko.md)
<!-- I18N:END -->

ポータブルなリバースエンジニアリング / セキュリティ分析 / デバッグ / 展開 / モバイル分析 / パケットキャプチャ / システム検査 / MCP 自動化のための**雛形リポジトリ**です。

任意の AI エージェント（Claude / Codex / Gemini / Cursor / Copilot / Grok）または人が clone し、[docs/i18n/ja/I18N.md](docs/i18n/ja/I18N.md) で UI 言語を決め、対応する [AGENTS.md](AGENTS.md)（[日本語](AGENTS.ja.md)）のヒアリングに従えば、自分のマシン上に **AI が操作しやすい** ツールステーションを復元できます。会話はその言語で。git のコミットメッセージは英語のままです。

仕事のあと、エージェントは `skills/2026-11-11/station-routers/debugger-review` で採点し、同じ失敗を繰り返さないよう `notes/` に残します。[docs/AGENT_EVOLUTION.md](docs/AGENT_EVOLUTION.md) を参照。

> ⚠️ **サードパーティ製ツールのバイナリは同梱しません。** `manifests/` と `scripts/bootstrap.ps1` から各公式ソースを辿ります。[DISCLAIMER.ja.md](DISCLAIMER.ja.md) を見てください。

---

## 現在の入口と検証範囲

[AI 入口](docs/AI_ENTRY.md)から契約・現行スキル・検証コマンドに進んでください。[2026-11-11 の公開証拠](releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md)は `RELEASE_GATE=RED` / `COMPLETENESS_VERDICT=NOT_COMPLETE` のままです。295 行は当時の主張台帳であり、実行可能なツール数ではありません。[限定 CLI profile](docs/CURRENT-CLI-PROFILE.md)のオフライン PCAP 検証は、パッケージ検証・実 MCP provider・製品全体の合格とは別に報告します。

## このリポジトリの内容

英語の [README.md](README.md) と同じ表です。エージェント契約の日本語は [AGENTS.ja.md](AGENTS.ja.md)。言語の説明は [docs/i18n/ja/I18N.md](docs/i18n/ja/I18N.md)。契約の静的チェックは英語の [docs/EVAL.md](docs/EVAL.md)。

## クイックスタート

```powershell
pwsh scripts\bootstrap.ps1 -InstallRoot "D:\Tool\debugger"
pwsh scripts\bootstrap.ps1 -Apply -CloneMcp -InstallRoot "D:\Tool\debugger"
powershell -File scripts\download-tools.ps1 -Apply
```

ドライランが既定です。Windows PowerShell 5.1 でも動きます（UTF-8 BOM）。PowerShell 7（`pwsh`）を推奨します。

## AI エージェントへ

clone 後、ロケールを解決し、**対応する AGENTS を先に読む**。質問してから `bootstrap.ps1` を実行する。クライアント MCP は `debugger-router` のみ。20 バックエンドをユーザーグローバル MCP に入れない。

## MCP

既定は軽量な `debugger-router` だけです。[設定テンプレート](mcp/.mcp.json.template)の 20 バックエンドを必要時に起動し、同じ `session_id` のプロセスを呼び出し間で再利用します。アイドル期限または明示的な終了で回収します。[BOOTSTRAP](docs/BOOTSTRAP.md) に実行設定と上流コンポーネントの数え方を分けて記載しています。

## セキュリティ

デバッガ、インジェクタ、フック、Frida、キャプチャ、メモリ分析を含み、AV/EDR に掛かることがあります。ドライバ / Npcap / ホスト上の不審サンプルは、影響を短く説明してから意図どおり実行します。セキュリティテスト、CTF、リバースエンジニアリング、研究、教育向けです。

## ライセンス

ライセンスはファイルの種類で分かれます。

- **コードと設定 — MIT**（[LICENSE](LICENSE)）。`mcp/debugger-router`、`mcp/bin`、`scripts`、`manifests`、`skills`、`templates`、エージェント契約（`AGENTS*.md`、`CLAUDE.md`、`GEMINI.md`）、および Markdown 以外のすべてのファイル。フォークは非公開にできます。
- **ドキュメント本文 — CC BY-SA 4.0**（[LICENSE-docs](LICENSE-docs)）。`docs/`（`docs/i18n/` を含む）、`README*.md`、`DISCLAIMER*.md`、`notes/` などの散文。出典を表示すれば再利用できますが、派生ドキュメントも同じライセンスに従います。
- サードパーティ製ツールとサードパーティ製 MCP の権利は各上流に残ります。本リポジトリはそれらのコードやバイナリを再配布しません。詳細は [DISCLAIMER.md](DISCLAIMER.md)。
