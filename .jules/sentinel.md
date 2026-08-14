## 2026-08-14 - Fix Potential Slowloris Attack Vulnerability (G112)
**Vulnerability:** Found `http.Server` implementations missing `ReadHeaderTimeout` in `internal/provideroauth/openrouter.go`, `internal/oauth/loopback.go`, and `internal/mcp/oauth.go`.
**Learning:** By default, Go's `http.Server` does not have a timeout for reading the request headers. This allows malicious clients to keep connections open indefinitely by sending header data very slowly, leading to resource exhaustion (Slowloris attack).
**Prevention:** Always set `ReadHeaderTimeout` when initializing an `http.Server` instance.
