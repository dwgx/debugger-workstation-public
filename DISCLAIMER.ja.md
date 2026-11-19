# 免責事項

<!-- I18N:START -->
[English](DISCLAIMER.md) · [简体中文](DISCLAIMER.zh-CN.md) · **日本語** · [한국어](DISCLAIMER.ko.md)
<!-- I18N:END -->

## サードパーティ製ツール

**debugger-workstation** は**雛形 / ブートストラップ**です。ツールのバイナリは各公式から取得します。審査済みソースパッチと個別許諾の保存ソース資産は元の表示を保持し、公開カタログで特定します。例：Ghidra、IDA Pro、radare2、x64dbg、ImHex、capa、Cheat Engine、JADX、Wireshark、7-Zip など（英語版の列挙と同じ）。

**IDA Pro は Hex-Rays の商用ソフトウェア**です。ライセンスは自分で買い、公式から入れます。本リポジトリは IDA 本体を配らず、ライセンス回避もしません。

著作権・商標・ライセンスは各公式に残ります。ツール一覧には `manifests/tools.json` の名前・版・**公式 URL** を記録します。

## サードパーティ MCP

完全なバックエンドは `manifests/mcp-backends.json` の上流から取得します。審査済みパッチは上流のライセンスを保持します。bootstrap は宣言された URL を clone します。**VirusTotal MCP** は IOC を VirusTotal の公開 API に送り、`VIRUSTOTAL_API_KEY` が必要です。自分の調査でのみ使用し、機微サンプルは上げないでください。

## 自作部分

`mcp/debugger-router/`、`mcp/bin/*.cmd`、テンプレート、`scripts/`、`docs/`、`manifests/`。コードと設定は [LICENSE](LICENSE)（MIT）、ドキュメント本文は [LICENSE-docs](LICENSE-docs)（CC BY-SA 4.0）を参照。

## 利用責任

セキュリティテスト、CTF、リバースエンジニアリング、研究、防御分析、教育向けです（アンパック、保護・アンチチート・DRM 分析を含む）。未知 / マルウェアはホストで走らせず、隔離 VM を使ってください。著者は結果について責任を負いません。
