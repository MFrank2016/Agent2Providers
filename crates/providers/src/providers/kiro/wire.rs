//! OpenAI chat body → Kiro `generateAssistantResponse` 请求体。
//!
//! 四条硬约束（spec 第 3 节，全部实测）：
//!   1. 没有 system 槽位 —— 系统提示词拼进第一条 user turn；
//!   2. 最后一轮 user 是 `currentMessage`，`history` 严格交替，缺档补 padding；
//!   3. history 上限 198 条，超出把最老的折成一条文本 turn；
//!   4. 工具结果挂 user turn，`toolUseId` 必须真实存在（对不上降级成文本）。
//!
//! padding 常量照抄官方客户端：user 用 `Continue`、assistant 用 `understood`。
//! **不要**用形似系统消息的标记 —— 模型会模仿并输出到正文。

use serde_json::{json, Map, Value};

/// history 上限（实测 198 过、200 报 `Input is too long.`）。
pub const MAX_HISTORY_ENTRIES: usize = 198;
/// user turn 的空档填充。
pub const CONTINUE_PADDING: &str = "Continue";
/// assistant turn 的空档填充。
pub const ACKNOWLEDGE_PADDING: &str = "understood";

/// 构造请求体。
pub fn build(body: &Value, model: &str, profile_arn: Option<&str>) -> Result<Value, String> {
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "请求里没有 messages 数组".to_string())?;
    if messages.is_empty() {
        return Err("messages 为空".to_string());
    }

    // ① 拆出 system（可能多条，按顺序拼接）
    let mut system_parts: Vec<String> = Vec::new();
    let mut turns: Vec<(bool, String)> = Vec::new(); // (是否 user, 文本)
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");
        let text = flatten_content(message.get("content"));
        match role {
            "system" | "developer" => system_parts.push(text),
            "assistant" => turns.push((false, text)),
            _ => turns.push((true, text)),
        }
    }
    if turns.is_empty() {
        return Err("messages 里没有 user / assistant 轮次".to_string());
    }

    // ② system 拼进第一条 user turn
    if !system_parts.is_empty() {
        let prefix = system_parts.join("\n\n");
        if let Some(first_user) = turns.iter_mut().find(|(is_user, _)| *is_user) {
            first_user.1 = format!("{prefix}\n\n{}", first_user.1);
        }
    }

    // ③ 拆 currentMessage 与 history
    let (_, current_text) = turns.pop().ok_or_else(|| "messages 为空".to_string())?;
    let mut history: Vec<(bool, String)> = turns;

    // ④ 补 padding 使 history 严格交替（起点必须是 user）
    if history.first().is_some_and(|(is_user, _)| !*is_user) {
        history.insert(0, (true, CONTINUE_PADDING.to_string()));
    }
    let mut normalized: Vec<(bool, String)> = Vec::with_capacity(history.len());
    for (is_user, text) in history {
        if let Some((last_is_user, _)) = normalized.last() {
            if *last_is_user == is_user {
                let filler = if is_user {
                    CONTINUE_PADDING
                } else {
                    ACKNOWLEDGE_PADDING
                };
                normalized.push((!is_user, filler.to_string()));
            }
        }
        normalized.push((is_user, text));
    }
    // 末尾必须是 assistant（currentMessage 是 user）
    if normalized.last().is_some_and(|(is_user, _)| *is_user) {
        normalized.push((false, ACKNOWLEDGE_PADDING.to_string()));
    }

    // ⑤ 超上限：把最老的折成一条文本 turn
    if normalized.len() > MAX_HISTORY_ENTRIES {
        let fold_count = normalized.len() - MAX_HISTORY_ENTRIES + 1;
        let folded: Vec<String> = normalized
            .drain(..fold_count)
            .map(|(is_user, text)| {
                format!("{}: {text}", if is_user { "user" } else { "assistant" })
            })
            .collect();
        normalized.insert(0, (true, folded.join("\n")));
        if normalized.get(1).is_some_and(|(is_user, _)| *is_user) {
            normalized.insert(1, (false, ACKNOWLEDGE_PADDING.to_string()));
        }
    }

    // ⑥ 组装
    let mut current = Map::new();
    current.insert("content".into(), Value::String(current_text));
    current.insert("modelId".into(), Value::String(model.to_string()));
    current.insert("origin".into(), Value::String("AI_EDITOR".to_string()));
    if let Some(context) = user_context(body) {
        current.insert("userInputMessageContext".into(), context);
    }

    let mut conversation = Map::new();
    conversation.insert(
        "chatTriggerType".into(),
        Value::String("MANUAL".to_string()),
    );
    conversation.insert(
        "conversationId".into(),
        Value::String(conversation_id(body)),
    );
    conversation.insert(
        "currentMessage".into(),
        json!({ "userInputMessage": Value::Object(current) }),
    );
    if !normalized.is_empty() {
        let entries: Vec<Value> = normalized
            .into_iter()
            .map(|(is_user, text)| {
                if is_user {
                    json!({ "userInputMessage": {
                        "content": text,
                        "modelId": model,
                        "origin": "AI_EDITOR"
                    }})
                } else {
                    json!({ "assistantResponseMessage": { "content": text } })
                }
            })
            .collect();
        conversation.insert("history".into(), Value::Array(entries));
    }

    let mut request = Map::new();
    if let Some(arn) = profile_arn.filter(|value| !value.is_empty()) {
        request.insert("profileArn".into(), Value::String(arn.to_string()));
    }
    request.insert("conversationState".into(), Value::Object(conversation));
    Ok(Value::Object(request))
}

/// 工具声明挂到 currentMessage 的 `userInputMessageContext.tools`。
fn user_context(body: &Value) -> Option<Value> {
    let tools = body.get("tools").and_then(Value::as_array)?;
    let mut mapped = Vec::new();
    for tool in tools {
        let function = tool.get("function").unwrap_or(tool);
        let name = function.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let description = function
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        let parameters = function
            .get("parameters")
            .cloned()
            .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
        mapped.push(json!({
            "toolSpecification": {
                "name": name,
                "description": description,
                "inputSchema": { "json": parameters }
            }
        }));
    }
    if mapped.is_empty() {
        return None;
    }
    Some(json!({ "tools": mapped }))
}

/// content 可能是字符串，也可能是 `[{type:"text",text:"…"}]` 数组。
fn flatten_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// 会话 id：优先用客户端给的，其次随机一个。
fn conversation_id(body: &Value) -> String {
    if let Some(id) = body
        .get("conversation_id")
        .or_else(|| body.get("conversationId"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return id.to_string();
    }
    let mut raw = [0u8; 16];
    let _ = getrandom::getrandom(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn system_prompt_is_prepended_to_first_user_turn() {
        let body = json!({
            "messages": [
                { "role": "system", "content": "你是助手" },
                { "role": "user", "content": "你好" }
            ]
        });
        let wire = build(&body, "claude-sonnet-4.5", None).expect("应能构造");
        let current = &wire["conversationState"]["currentMessage"]["userInputMessage"];
        assert!(current["content"]
            .as_str()
            .unwrap_or("")
            .contains("你是助手"));
        assert!(current["content"].as_str().unwrap_or("").contains("你好"));
        assert_eq!(current["modelId"], "claude-sonnet-4.5");
    }

    #[test]
    fn last_user_turn_is_current_message_and_not_in_history() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "第一轮" },
                { "role": "assistant", "content": "回答" },
                { "role": "user", "content": "第二轮" }
            ]
        });
        let wire = build(&body, "m", None).expect("应能构造");
        let history = wire["conversationState"]["history"]
            .as_array()
            .expect("应有 history");
        assert_eq!(history.len(), 2);
        assert!(history[0].get("userInputMessage").is_some());
        assert!(history[1].get("assistantResponseMessage").is_some());
        let current = &wire["conversationState"]["currentMessage"]["userInputMessage"]["content"];
        assert_eq!(current, "第二轮");
    }

    #[test]
    fn missing_turns_are_padded_so_history_alternates() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "a" },
                { "role": "user", "content": "b" },
                { "role": "assistant", "content": "c" },
                { "role": "assistant", "content": "d" },
                { "role": "user", "content": "e" }
            ]
        });
        let wire = build(&body, "m", None).expect("应能构造");
        let history = wire["conversationState"]["history"]
            .as_array()
            .expect("应有 history");
        for (index, entry) in history.iter().enumerate() {
            let is_user = entry.get("userInputMessage").is_some();
            assert_eq!(is_user, index % 2 == 0, "第 {index} 条角色不符");
        }
    }

    #[test]
    fn history_is_capped_at_198_entries() {
        let mut messages = Vec::new();
        for index in 0..400 {
            messages.push(json!({
                "role": if index % 2 == 0 { "user" } else { "assistant" },
                "content": format!("m{index}")
            }));
        }
        let body = json!({ "messages": messages });
        let wire = build(&body, "m", None).expect("应能构造");
        let history = wire["conversationState"]["history"]
            .as_array()
            .expect("应有 history");
        assert!(
            history.len() <= MAX_HISTORY_ENTRIES,
            "history 超上限：{}",
            history.len()
        );
    }

    #[test]
    fn tools_are_mapped_to_tool_specifications() {
        let body = json!({
            "messages": [{ "role": "user", "content": "读文件" }],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "读一个文件",
                    "parameters": { "type": "object", "properties": { "path": { "type": "string" } } }
                }
            }]
        });
        let wire = build(&body, "m", None).expect("应能构造");
        let tools = &wire["conversationState"]["currentMessage"]["userInputMessage"]
            ["userInputMessageContext"]["tools"];
        let tools = tools.as_array().expect("应有 tools");
        assert_eq!(tools[0]["toolSpecification"]["name"], "read_file");
        assert_eq!(
            tools[0]["toolSpecification"]["inputSchema"]["json"]["type"],
            "object"
        );
    }

    #[test]
    fn profile_arn_is_only_present_when_given() {
        let body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        let without = build(&body, "m", None).expect("应能构造");
        assert!(without.get("profileArn").is_none());
        let with = build(
            &body,
            "m",
            Some("arn:aws:codewhisperer:us-east-1:1:profile/x"),
        )
        .expect("应能构造");
        assert_eq!(
            with["profileArn"],
            "arn:aws:codewhisperer:us-east-1:1:profile/x"
        );
    }
}
