/* d12payload.c — self-authored lab payload for the D12 forensics lane.
 * NOT malware. No network, no process, no persistence, no evasion.
 * It exists so the lab can embed a REAL, independently-verifiable PE in a
 * synthetic memory image and hand the carved bytes to third-party tools. */
#include <windows.h>

/* The single marker the lab's YARA rule and string search look for. */
__declspec(dllexport) const char D12LAB_PAYLOAD_MARKER[] = "D12LAB-PAYLOAD-v1";

/* A second exported symbol so the PE has a real, checkable export table. */
__declspec(dllexport) int D12LabNoop(void) { return 0xD12; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}
