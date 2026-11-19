# APKTool build → decode: original-wrapper reproducible lab

This extends the previously published **five positive metadata calls and seven
missing-input refusals** with an actual bounded positive **build_apk** and
**decode_apk** pair through the original installed APKTool MCP wrapper.

The runner creates a small, inert text-only project with an Android Manifest,
a Smali class containing `APK_ORACLE_2b9c`, and resource literals including
`APK_ROUNDTRIP_7d41`. The installed Apktool builds a ZIP/APK with manifest,
DEX and resource-table bytes. The installed wrapper decodes it, and an
independent oracle checks those bytes and the decoded Smali, Manifest,
strings, colors and public resource IDs. **No APK is installed, signed,
executed, uploaded or sent to a device.** Existing user projects and
credential files are outside the test.

## Reproduction on an installed Windows station

Prerequisites: Windows client Python with `pywin32`, installed APKTool MCP
source and its **dedicated** venv, the installed APKTool jar and Java, a
pre-existing Android framework resource at the standard Apktool framework
path, and the original `MCP/bin/apktool-mcp.cmd` wrapper preserving the
explicit `APKTOOL_WORKSPACE` variable. Do not replace framework files in
a shared setup without their owner's approval. The framework's existence and
digest are pinned for the run, not provisioned by this script.

From a public repository clone (replace the station path with your own
authorized installed station):

```powershell
$source = (Get-Location).Path
$station = 'C:/Owned/WorkStation'
$results = Join-Path $env:TEMP ('owned-apk-roundtrip-' + [guid]::NewGuid().ToString('N'))
python -X utf8 -B scripts/tool_lab/run_apk_roundtrip.py --station $station --runs-root $results --apktool-version 3.0.3
if ($LASTEXITCODE -ne 0) { throw "APK roundtrip failed; inspect $results" }
```

`3.0.3` is the **version actually observed in the reference run**; supply
your own installed version, do not hardcode an assumed latest version. The
runner creates a unique child run directory under `--runs-root`. Choose a
parent **outside** the source and installed station. The runner does not
write or overwrite a shared top-level RESULT.json; each attempt preserves
its own `RESULT.json`, `PLAN.json`, `session/requests.jsonl`,
`session/responses.jsonl`, `session/RESULTS.json`, and source/fixture
hashes. A repeated run creates a separate run directory and never
silently promotes or discards a prior failed observation.

### Compatibility notes and a preserved negative test

The authored `apktool.yml` intentionally contains
`usesFramework.ids: [1]` because without that declaration the installed
`aapt2 link` fails resolving `android:label`, even when a framework
file exists. The successful `build_apk` call explicitly uses
`debug=false` because the installed Apktool 3.0.3 rejects the wrapper's
current default debug flag (it appends `-d`). That default failure is
kept as a negative case. This is an observed version-specific limitation,
not a claim that all Apktool versions behave alike.

Other adversarial cases include missing projects/APKs, incorrect file
extensions, corrupted APK content, output outside the owned workspace and
missing class/resources. Each negative scenario must return MCP
`isError=true` with the expected rejection, without mutating owned
existing fixture bytes. A successful RPC transport alone is not success.

### Reference acceptance and limits

**2026-11-19 UTC / 2026-11-20 JST reference run**, original installed
Windows wrapper:

- Nine unique methods have selected positive calls, including build and decode;
  the runner also executes ten bounded negative cases.
- The independent checker validates the ZIP member set, AXML/DEX/ARSC magic,
  known resource/Smali literals, decoded Manifest/Smali/resources, and
  source and workspace byte identities.
- Original client retained raw JSON-RPC, an unpolluted protocol stdout,
  the stopped stdout reader and owned Windows Job cleanup; the candidate
  was independently executed again with exit 0 and the same bounded
  semantic result.
- The corrected public runner was then independently rerun with exit 0,
  with an explicit hash check proving the earlier worker RESULT.json was
  not overwritten.

These are *selected* methods, not general APK reverse-engineering quality,
complex dex handling, use on arbitrary APKs, user device access, signing
or installation. Seven other catalog methods were not called in this run.
It does not convert the full 20-backend registry into complete acceptance.

The accompanying portable `tests/test_apk_roundtrip.py` controls fixture
truth, normalization boundaries, corrupt-APK refusal, source containment
and result-output immutability. They do **not** start the provider and
must not be counted as a real MCP invocation. The actual Windows runner
and its result remain a separate acceptance gate.

## 中文说明

新增的是**真实的 Apktool MCP 构建、反编译闭环**，不是仅有元数据
或错误拒绝。使用合成 Smali、Manifest、resources 文件，通过原版
MCP wrapper 构建一个惰性 APK，再解包，独立验证字节与语义。

需要先安装 Java、Apktool、专用 MCP 环境，并且本地已有 framework
资源。已观察到版本 3.0.3 必须对成功构建设置 `debug=false`，
合成 `apktool.yml` 必须声明 framework ID 1。**不执行 APK、
不连接手机、不修改其他项目、也不读取私人数据。** 每次跑都会
建立新的独立证据目录；过去结果不覆盖。
