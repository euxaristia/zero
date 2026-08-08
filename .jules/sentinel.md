## 2025-05-18 - Missing ReadHeaderTimeout in HTTP Server
**Vulnerability:** Found `http.Server` instantiations without `ReadHeaderTimeout` set in multiple files (`internal/provideroauth/openrouter.go`, `internal/mcp/oauth.go`, `internal/tools/bash_tool_test.go`, and `internal/oauth/loopback.go`).
**Learning:** Initializing `http.Server` in Go without `ReadHeaderTimeout` leaves the application vulnerable to Slowloris attacks (CWE-400 / gosec G112).
**Prevention:** Always configure `ReadHeaderTimeout` to at least `3 * time.Second` when setting up `http.Server` to prevent slow client attacks.
