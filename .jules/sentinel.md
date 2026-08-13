## 2026-08-13 - [CWE-400 Slowloris Prevention]
**Vulnerability:** Missing `ReadHeaderTimeout` in `http.Server` initialization.
**Learning:** The default `http.Server` lacks a read header timeout, leading to potential Slowloris Denial of Service attacks when exposing the server. This often gets flagged as G112 by gosec.
**Prevention:** Always configure `ReadHeaderTimeout` when creating a new `http.Server` instance.
