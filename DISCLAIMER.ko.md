# 면책

<!-- I18N:START -->
[English](DISCLAIMER.md) · [简体中文](DISCLAIMER.zh-CN.md) · [日本語](DISCLAIMER.ja.md) · **한국어**
<!-- I18N:END -->

## 서드파티 도구

**debugger-workstation**은 **뼈대 / 부트스트랩**입니다. 도구 바이너리는 공식 출처에서 받습니다. 검토한 소스 패치와 별도 라이선스의 보존 소스 자산은 원래 표시를 유지하며 공개 목록에서 식별합니다. 예: Ghidra, IDA Pro, radare2, x64dbg, ImHex, capa, Cheat Engine, JADX, Wireshark, 7-Zip 등(영어 판 목록과 동일).

**IDA Pro는 Hex-Rays 상용 소프트웨어**입니다. 라이선스는 직접 사고 공식에서 설치하세요. 이 저장소는 IDA 본체를 배포하지 않으며 라이선스를 우회하지 않습니다.

저작권·상표·라이선스는 각 공식에 남습니다. 도구 목록은 `manifests/tools.json`의 이름·버전·**공식 URL**을 기록합니다.

## 서드파티 MCP

전체 백엔드는 `manifests/mcp-backends.json`의 업스트림에서 받습니다. 검토한 패치는 원래 라이선스를 유지합니다. bootstrap은 선언된 URL을 clone합니다. **VirusTotal MCP**는 IOC를 VirusTotal 공개 API로 보내며 `VIRUSTOTAL_API_KEY`가 필요합니다. 자신의 조사에만 쓰고 민감 샘플을 올리지 마세요.

## 자체 작성

`mcp/debugger-router/`, `mcp/bin/*.cmd`, 템플릿, `scripts/`, `docs/`, `manifests/`. 코드와 설정은 [LICENSE](LICENSE)(MIT), 문서 본문은 [LICENSE-docs](LICENSE-docs)(CC BY-SA 4.0)를 참조하세요.

## 이용 책임

보안 테스트, CTF, 리버스 엔지니어링, 연구, 방어 분석, 교육용입니다(언팩, 보호·안티치트·DRM 분석 포함). 알 수 없는 샘플이나 악성 샘플은 호스트에서 돌리지 말고 격리 VM을 쓰세요. 저자는 결과에 책임지지 않습니다.
