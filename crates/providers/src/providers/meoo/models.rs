//! 见 `docs/superpowers/specs/2026-11-02-meoo-provider.md`。

pub fn default_models() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "id": "qwen3.8-flash",
        "name": "Qwen3.8-Flash",
        "maxInputTokens": 200000,
        "maxOutputTokens": 64000,
        "supportsToolCall": true
    })]
}
