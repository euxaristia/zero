## 2023-08-10 - Server ReadHeaderTimeout configuration
**Vulnerability:** Found `http.Server` instances without `ReadHeaderTimeout` set, leaving the application vulnerable to CWE-400 Slowloris attacks.
**Learning:** Default `http.Server` configurations do not timeout reading headers, which can be exploited by an attacker holding connections open indefinitely.
**Prevention:** Always configure `ReadHeaderTimeout` when initializing `http.Server` in Go.
