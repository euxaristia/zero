## 2026-08-15 - Excessive memory allocation during VP8L decoding in golang.org/x/image
**Vulnerability:** The `golang.org/x/image` package (specifically `v0.44.0`) is vulnerable to excessive memory allocation during VP8L decoding (`GO-2026-6222`). This could be exploited by providing a specially crafted image to trigger a denial of service.
**Learning:** Outdated dependencies with known CVEs pose a significant security risk, especially when processing external inputs like images in `terminalpet.decodeImage`.
**Prevention:** Regularly scan dependencies with `make vulncheck` (which runs `govulncheck`) in CI and locally. Promptly update vulnerable dependencies (e.g., `go get golang.org/x/image@v0.45.0`) to secure versions.
