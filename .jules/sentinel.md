
## 2025-02-14 - Prevent API key leak in streaming dictation websocket errors
**Vulnerability:** Streaming dictation (Deepgram, OpenAI Realtime) did not redact API keys from connection errors or websocket payload error responses.
**Learning:** API keys are injected into streaming websocket URLs or headers which can leak when transport-level errors occur or when the server responds with a typed error payload echoing the key.
**Prevention:** Apply `providerio.Redact` around all error endpoints and websocket error returns.
