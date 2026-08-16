## 2025-05-15 - [Prefer errors.New for plain string errors]
**Vulnerability:** A streamed explanation error was built with `fmt.Errorf("%s", collected.Error)`. That is not Gosec G204 (command execution) and is not format-string execution: `%` directives inside the `%s` argument are not re-evaluated.
**Learning:** Prefer `errors.New` for a plain string error. When a redacted message must keep the original cause, use a custom-wrapped error (`Error` + `Unwrap`).
**Prevention:** Use `errors.New` when creating errors from raw strings or build a custom `redactedError` wrapper when the original unwrappable error needs to be preserved but its Error() string needs to be redacted.
