## 2026-08-05 - Add `ReadHeaderTimeout` to `http.Server` to prevent Slowloris Attacks (CWE-400)
**Vulnerability:** Found `http.Server` instances in `internal/mcp/oauth.go`, `internal/oauth/loopback.go`, and `internal/provideroauth/openrouter.go` lacking `ReadHeaderTimeout` configuration.
**Learning:** This is a common pattern flagged by gosec as G112 (CWE-400) where an HTTP server is vulnerable to Slowloris attacks because it lacks timeouts for reading request headers, which can lead to resource exhaustion.
**Prevention:** Always configure `ReadHeaderTimeout` when initializing `http.Server` in Go.
