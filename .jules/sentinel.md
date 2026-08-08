## 2026-08-06 - Missing ReadHeaderTimeout in http.Server
**Vulnerability:** Found multiple `http.Server` initializations missing the `ReadHeaderTimeout` configuration.
**Learning:** By default, Go's `http.Server` does not enforce a timeout for reading headers, which makes the server vulnerable to Slowloris attacks (CWE-400), as flagged by gosec G112. Attackers can hold connections open by slowly sending headers, exhausting server resources.
**Prevention:** Always set `ReadHeaderTimeout` when initializing `http.Server` (e.g. `ReadHeaderTimeout: 10 * time.Second`).
