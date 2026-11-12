# debugger-workstation

<!-- I18N:START -->
[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · **한국어**
<!-- I18N:END -->

휴대용 리버스 엔지니어링 / 보안 분석 / 디버깅 / 언팩 / 모바일 분석 / 패킷 캡처 / 시스템 점검 / MCP 자동화를 위한 **뼈대 저장소**입니다.

아무 AI 에이전트(Claude / Codex / Gemini / Cursor / Copilot / Grok)나 사람이 clone한 뒤 [docs/i18n/ko/I18N.md](docs/i18n/ko/I18N.md)로 UI 언어를 정하고, 맞는 [AGENTS.md](AGENTS.md)([한국어](AGENTS.ko.md)) 핸드셰이크를 따르면 자기 머신에 **AI가 다루기 쉬운** 도구 스테이션을 복원할 수 있습니다. 대화는 그 언어로, git 커밋 메시지는 영어입니다.

작업 후 에이전트는 `skills/2026-11-11/station-routers/debugger-review`로 점수를 매기고 `notes/`에 남깁니다. [docs/AGENT_EVOLUTION.md](docs/AGENT_EVOLUTION.md).

> ⚠️ **서드파티 도구 바이너리는 포함하지 않습니다.** `manifests/`와 `scripts/bootstrap.ps1`로 각 공식 소스를 따릅니다. [DISCLAIMER.ko.md](DISCLAIMER.ko.md).

---

## 현재 진입점과 검증 범위

[AI 진입점](docs/AI_ENTRY.md)에서 계약, 현행 스킬, 검증 명령을 확인하세요.[2026-11-11 공개 증거](releases/2026-11-11-full-library/RELEASE-GATE-STATUS.md)의 판정은 `RELEASE_GATE=RED` / `COMPLETENESS_VERDICT=NOT_COMPLETE`입니다. 295행은 당시 주장 목록이며 실행 가능한 도구 수가 아닙니다.[제한된 CLI profile](docs/CURRENT-CLI-PROFILE.md)의 오프라인 PCAP 검증은 패키지 검사, 실제 MCP provider, 전체 제품 승인과 구분해서 보고합니다.

## 이 저장소에 있는 것

표는 영어 [README.md](README.md)와 같습니다. 한국어 에이전트 계약은 [AGENTS.ko.md](AGENTS.ko.md). 언어 설명은 [docs/i18n/ko/I18N.md](docs/i18n/ko/I18N.md). 정적 계약 체크는 영어 [docs/EVAL.md](docs/EVAL.md).

## 빠른 시작

```powershell
pwsh scripts\bootstrap.ps1 -InstallRoot "D:\Tool\debugger"
pwsh scripts\bootstrap.ps1 -Apply -CloneMcp -InstallRoot "D:\Tool\debugger"
powershell -File scripts\download-tools.ps1 -Apply
```

기본은 드라이런입니다. Windows PowerShell 5.1도 됩니다(UTF-8 BOM). PowerShell 7(`pwsh`)을 권장합니다.

## AI 에이전트에게

clone 후 로케일을 정하고 **해당 AGENTS를 먼저 읽으세요**. 질문한 뒤에 `bootstrap.ps1`을 실행합니다. 클라이언트 MCP는 `debugger-router`만. 백엔드 20개를 사용자 전역 MCP에 넣지 마세요.

## MCP

기본은 가벼운 `debugger-router` 하나입니다.[설정 템플릿](mcp/.mcp.json.template)의 백엔드 20개 중 필요한 것을 시작하고 같은 `session_id`의 프로세스를 호출 사이에 재사용합니다. 유휴 시간 초과 또는 명시적인 종료로 회수합니다.[BOOTSTRAP](docs/BOOTSTRAP.md)은 실행 설정과 상위 컴포넌트의 개수를 구분합니다.

## 보안

디버거, 인젝터, 훅, Frida, 캡처, 메모리 분석이 들어 있어 AV/EDR에 걸릴 수 있습니다. 드라이버 / Npcap / 호스트의 의심 샘플은 영향을 짧게 설명한 뒤 의도대로 실행합니다. 보안 테스트, CTF, 리버스 엔지니어링, 연구, 교육용입니다.

## 라이선스

라이선스는 파일 종류에 따라 나뉩니다.

- **코드와 설정 — MIT** ([LICENSE](LICENSE)). `mcp/debugger-router`, `mcp/bin`, `scripts`, `manifests`, `skills`, `templates`, 에이전트 계약(`AGENTS*.md`, `CLAUDE.md`, `GEMINI.md`), 그리고 Markdown이 아닌 모든 파일. 포크를 비공개로 유지할 수 있습니다.
- **문서 본문 — CC BY-SA 4.0** ([LICENSE-docs](LICENSE-docs)). `docs/`(`docs/i18n/` 포함), `README*.md`, `DISCLAIMER*.md`, `notes/` 등. 출처를 표시하면 재사용할 수 있지만 파생 문서도 같은 라이선스를 따릅니다.
- 서드파티 도구와 서드파티 MCP의 권리는 각 업스트림에 남습니다. 이 저장소는 그들의 코드나 바이너리를 재배포하지 않습니다. 자세한 내용은 [DISCLAIMER.md](DISCLAIMER.md).
