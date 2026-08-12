## 2026-08-12 - Missing ReadHeaderTimeout in http.Server
**Vulnerability:** Found multiple `http.Server` instances in the codebase missing the `ReadHeaderTimeout` configuration.
**Learning:** This exposes the application to Slowloris Denial of Service (DoS) attacks, where attackers slowly send headers to tie up server connections. Go `http.Server` does not have a default timeout for reading headers.
**Prevention:** Always configure `ReadHeaderTimeout` (e.g., `10 * time.Second`) when initializing `http.Server` in Go to mitigate this risk (CWE-400 / gosec G112).
