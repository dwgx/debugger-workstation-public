# VERBATIM. Added 2026-10-05.
#
# This file exists so the capability's probe can leave an artifact. `assert-probes.py` writes a
# registry command byte-for-byte into a .ps1 and runs `powershell -File`, and its own docstring
# records that two earlier designs which sniffed for PowerShell markers and re-wrapped in
# `powershell -Command "..."` missed 8 commands and destroyed every command containing a double
# quote. So the one-liner was NOT re-quoted -- it was MOVED here unchanged, and the registry now
# names this file.
#
# The wrapper that invokes it (scripts/probe_wrapper.py) records the command, the exit code, the
# stdout, the stderr and the duration, and passes the child's exit code through, so adding it
# cannot turn a red into a green. It does not judge the output; that stays with assert-probes.

& '.\Mobile-Android\objection\.venv\Scripts\frida.exe' -f "$env:TEMP\fridaprobe\target.exe" -q -t 6 -e 'var m=Process.mainModule;console.log(`FRIDA_WIN module_base=${m.base}`);console.log(`FRIDA_WIN symbol_main=${DebugSymbol.fromName(`main`)}`);console.log(`FRIDA_WIN export_printf=${Module.getGlobalExportByName(`printf`)}`);console.log(`FRIDA_WIN rebased_main=${m.base.add(0x1080)}`);Interceptor.attach(m.base.add(0x1080),{onEnter:function(){console.log(`FRIDA_WIN HIT main`);}});'
