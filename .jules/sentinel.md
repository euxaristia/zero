## 2025-05-15 - [Safe String Error Formatting]
**Vulnerability:** Found multiple instances of formatting dynamic input using `fmt.Errorf("%s", ...)`.
**Learning:** `fmt.Errorf("%s", string)` strips the wrapped error of the underlying argument. In the context of redactions, it's safer to use custom wrapped errors to preserve the unwrapping of the original error.
**Prevention:** Use `errors.New` when creating errors from raw strings or build a custom `redactedError` wrapper when the original unwrappable error needs to be preserved but its Error() string needs to be redacted.
