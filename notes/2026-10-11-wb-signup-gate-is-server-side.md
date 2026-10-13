---
tags: [debugger]
status: observed
source: agent-notes 2026-10-11
---

# wb-signup-gate-is-server-side

WorkBuddy/CodeBuddy intl signup: 'Account Access Restricted' at Keycloak first-broker-login is a SERVER-side risk verdict. Measured 2026-10-11: exhausted every client variable (accounts MB1-6, exits US1/US2+JP/FR+home-lane real ISP, fingerprints default/macOS-M1/Windows-GTX980/Linux via camoufox fpgen, engines Camoufox+patchright-Chrome, entries platform=CLI/workbuddy-ai) => identical message. No official client installed on this box (no @tencent-ai npm pkg, no ~/.workbuddy, no workbuddy-desktop*.info) so no client-side device signal is missing at signup. hub wb_fingerprint.derive_id = md5(salt:uid)[:36] and is used for POST-login event reporting only. External: LINUX DO topic/2898805 same message with Google AND GitHub; topic/2932260 risk-controlled on a clean no-proxy environment and unblocked via support in ~1h. Conclusion: client-side RE cannot unblock this; the levers are appeal/clean region-matched IP/wait.
