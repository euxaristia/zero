## 2026-08-09 - Missing ReadHeaderTimeout in Local HTTP Servers
**Vulnerability:** Found `http.Server` setups (e.g. for OAuth callbacks and loopback listener) that lacked `ReadHeaderTimeout` configurations, risking Slowloris DoS attacks (CWE-400 / gosec G112).
**Learning:** Even though loopback servers are typically internal-facing, defensive layers are required. They inherit the same vulnerability as public-facing servers.
**Prevention:** Always configure a sensible `ReadHeaderTimeout` (e.g., `5 * time.Second`) when initializing Go's `http.Server`.