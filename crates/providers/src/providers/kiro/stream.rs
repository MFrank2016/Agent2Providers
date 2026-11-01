//! Kiro 事件帧 → OpenAI Chat SSE 帧。
//!
//! ── 为什么在这里翻译而不是交给网关 ──────────────────────────
//! 网关的 `UpstreamKind` 没有 Event Stream 这一档；插件自己解码二进制帧、
//! 自己产出 OpenAI 帧、报 `UpstreamKind::Chat`，与 `kuku` 同一范式。
//!
//! ── 工具调用的形状 ──────────────────────────────────────────
//! 上游把一次调用拆成多帧：首帧给 `name` + `toolUseId`，中间帧给 `input`
//! 片段（**字符串**，不是对象），末帧带 `stop: true`。本模块把片段拼成完整
//! JSON 后再发一个 `tool_calls` 增量帧 —— 客户端拿到的是完整参数，
//! 而不是需要自己拼接的半截。

use serde_json::{json, Value};

use super::eventstream::KiroFrame;

/// 一次进行中的工具调用。
#[derive(Default)]
struct PendingTool {
    id: String,
    name: String,
    input: String,
}

/// 有状态翻译器：一次响应一个实例。
pub struct FrameTranslator {
    model: String,
    id: String,
    created: i64,
    index: u64,
    pending: Option<PendingTool>,
    finished: bool,
}

impl FrameTranslator {
    pub fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            id: format!("chatcmpl-kiro-{}", crate::http::now_ms()),
            created: crate::http::now_ms() / 1000,
            index: 0,
            pending: None,
            finished: false,
        }
    }

    /// 吃一帧，产出零到多个 SSE 帧。
    pub fn feed(&mut self, frame: &KiroFrame) -> Vec<String> {
        if frame.message_type == "exception" {
            return vec![error_frame(&format!("Kiro 上游返回异常：{}", frame.event))];
        }
        let Ok(payload) = serde_json::from_str::<Value>(&frame.payload) else {
            return Vec::new();
        };
        match frame.event.as_str() {
            "assistantResponseEvent" => payload
                .get("content")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(|text| vec![self.text_frame(text, None)])
                .unwrap_or_default(),
            "reasoningContentEvent" => payload
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(|text| vec![self.text_frame("", Some(text))])
                .unwrap_or_default(),
            "toolUseEvent" => self.tool_frames(&payload),
            "messageMetadataEvent" => {
                self.finished = true;
                let usage = payload.get("tokenUsage").cloned().unwrap_or(Value::Null);
                vec![self.finish_frame("stop", &usage)]
            }
            _ => Vec::new(),
        }
    }

    /// 收尾：没收到 metadata 时补一个 finish 帧，最后一定带 `[DONE]`。
    pub fn finish(&mut self) -> Vec<String> {
        let mut frames = Vec::new();
        if let Some(pending) = self.pending.take() {
            frames.push(self.tool_call_frame(&pending));
        }
        if !self.finished {
            self.finished = true;
            frames.push(self.finish_frame("stop", &Value::Null));
        }
        frames.push("data: [DONE]\n\n".to_string());
        frames
    }

    fn tool_frames(&mut self, payload: &Value) -> Vec<String> {
        let id = payload
            .get("toolUseId")
            .and_then(Value::as_str)
            .unwrap_or("");
        if id.is_empty() {
            return Vec::new();
        }
        let pending = self.pending.get_or_insert_with(PendingTool::default);
        if pending.id.is_empty() {
            pending.id = id.to_string();
        }
        if let Some(name) = payload.get("name").and_then(Value::as_str) {
            if !name.is_empty() {
                pending.name = name.to_string();
            }
        }
        if let Some(fragment) = payload.get("input").and_then(Value::as_str) {
            pending.input.push_str(fragment);
        }
        let stop = payload
            .get("stop")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !stop {
            return Vec::new();
        }
        let done = self.pending.take().unwrap_or_default();
        vec![self.tool_call_frame(&done)]
    }

    fn tool_call_frame(&mut self, tool: &PendingTool) -> String {
        let arguments = if tool.input.trim().is_empty() {
            "{}".to_string()
        } else {
            tool.input.clone()
        };
        let index = self.index;
        self.index += 1;
        sse(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": index,
                        "id": tool.id,
                        "type": "function",
                        "function": { "name": tool.name, "arguments": arguments }
                    }]
                },
                "finish_reason": Value::Null
            }]
        }))
    }

    fn text_frame(&self, content: &str, reasoning: Option<&str>) -> String {
        let mut delta = serde_json::Map::new();
        if !content.is_empty() {
            delta.insert("content".into(), Value::String(content.to_string()));
        }
        if let Some(reasoning) = reasoning.filter(|text| !text.is_empty()) {
            delta.insert(
                "reasoning_content".into(),
                Value::String(reasoning.to_string()),
            );
        }
        sse(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": Value::Object(delta),
                "finish_reason": Value::Null
            }]
        }))
    }

    fn finish_frame(&self, reason: &str, usage: &Value) -> String {
        let mut frame = json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }]
        });
        if let Some(total) = usage.get("totalTokens").and_then(Value::as_i64) {
            let input = usage
                .get("uncachedInputTokens")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let output = usage
                .get("outputTokens")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            frame["usage"] = json!({
                "prompt_tokens": input,
                "completion_tokens": output,
                "total_tokens": total
            });
        }
        sse(&frame)
    }
}

/// 一个 `data: …\n\n` 帧。
fn sse(payload: &Value) -> String {
    format!("data: {payload}\n\n")
}

/// 错误帧：客户端会把它当一次失败的答复。
fn error_frame(message: &str) -> String {
    format!(
        "data: {}\n\n",
        json!({ "error": { "message": message, "type": "upstream_error" } })
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::providers::kiro::eventstream::KiroFrame;

    fn frame(event: &str, payload: &str) -> KiroFrame {
        KiroFrame {
            event: event.to_string(),
            message_type: "event".to_string(),
            payload: payload.to_string(),
        }
    }

    #[test]
    fn assistant_text_becomes_openai_delta() {
        let mut translator = FrameTranslator::new("claude-sonnet-4.5");
        let frames = translator.feed(&frame("assistantResponseEvent", r#"{"content":"你好"}"#));
        assert_eq!(frames.len(), 1);
        assert!(frames[0].starts_with("data: "));
        assert!(frames[0].contains(r#""content":"你好""#));
        assert!(frames[0].contains(r#""model":"claude-sonnet-4.5""#));
    }

    #[test]
    fn metadata_becomes_finish_frame_with_usage() {
        let mut translator = FrameTranslator::new("m");
        let frames = translator.feed(&frame(
            "messageMetadataEvent",
            r#"{"tokenUsage":{"totalTokens":42}}"#,
        ));
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains(r#""finish_reason":"stop""#));
        assert!(frames[0].contains(r#""total_tokens":42"#));
    }

    #[test]
    fn tool_use_events_accumulate_then_emit_one_call() {
        let mut translator = FrameTranslator::new("m");
        assert!(translator
            .feed(&frame(
                "toolUseEvent",
                r#"{"toolUseId":"t1","name":"read_file"}"#
            ))
            .is_empty());
        assert!(translator
            .feed(&frame(
                "toolUseEvent",
                r#"{"toolUseId":"t1","input":"{\"path\":"}"#
            ))
            .is_empty());
        let frames = translator.feed(&frame(
            "toolUseEvent",
            r#"{"toolUseId":"t1","input":"\"a.txt\"}","stop":true}"#,
        ));
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains(r#""tool_calls""#));
        assert!(frames[0].contains(r#""name":"read_file""#));
        assert!(frames[0].contains("a.txt"));
    }

    #[test]
    fn finish_always_ends_with_done() {
        let mut translator = FrameTranslator::new("m");
        let frames = translator.finish();
        assert_eq!(frames.last().map(String::as_str), Some("data: [DONE]\n\n"));
    }

    #[test]
    fn exception_frames_become_an_error_payload() {
        let mut translator = FrameTranslator::new("m");
        let mut exception = frame("ValidationException", "{}");
        exception.message_type = "exception".to_string();
        let frames = translator.feed(&exception);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("ValidationException"));
    }
}
