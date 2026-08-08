## 2025-05-15 - [Gosec G204/String formatting vulnerabilities]
**Vulnerability:** Found multiple instances of formatting dynamic input using `fmt.Errorf("%s", ...)` which can leak sensitive data or alter execution if input contains `%w` verbs.
**Learning:** `fmt.Errorf("%s", string)` is not safe if the string was created using `fmt.Sprintf` with `%w` verbs, as it can be interpreted and cause issues or strip the wrapped error. In context of redactions, it's safer to use custom wrapped errors to preserve the unwrapping of the original error.
**Prevention:** Use `errors.New` when creating errors from raw strings or build a custom `redactedError` wrapper when the original unwrappable error needs to be preserved but its Error() string needs to be redacted.
