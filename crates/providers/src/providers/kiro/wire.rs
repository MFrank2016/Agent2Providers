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

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

/// history 上限（实测 198 过、200 报 `Input is too long.`）。
pub const MAX_HISTORY_ENTRIES: usize = 198;
/// user turn 的空档填充。
pub const CONTINUE_PADDING: &str = "Continue";
/// assistant turn 的空档填充。
pub const ACKNOWLEDGE_PADDING: &str = "understood";
/// 只有工具结果、没有用户正文时的占位文案。
pub const TOOL_RESULTS_PADDING: &str = "Tool results provided.";

/// 一轮对话：user 带工具结果，assistant 带工具调用。
#[derive(Default)]
struct Turn {
    is_user: bool,
    text: String,
    tool_uses: Vec<Value>,
    tool_results: Vec<Value>,
    /// 对不上 `toolUseId` 的结果，降级成文本后追加到正文。
    degraded: Vec<String>,
}

impl Turn {
    fn user(text: String) -> Self {
        Self {
            is_user: true,
            text,
            ..Self::default()
        }
    }

    fn assistant(text: String, tool_uses: Vec<Value>) -> Self {
        Self {
            is_user: false,
            text,
            tool_uses,
            ..Self::default()
        }
    }

    fn padding(is_user: bool) -> Self {
        Self {
            is_user,
            text: if is_user {
                CONTINUE_PADDING.to_string()
            } else {
                ACKNOWLEDGE_PADDING.to_string()
            },
            ..Self::default()
        }
    }

    /// 把一组工具结果挂到这一轮上。
    fn attach(&mut self, group: PendingTools) {
        self.tool_results = group.results;
        self.degraded = group.degraded;
    }

    /// 正文 = 原始文本 + 降级成文本的工具结果；只有工具结果时用占位文案。
    fn content(&self) -> String {
        let mut content = self.text.clone();
        for line in &self.degraded {
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(line);
        }
        if content.is_empty() && !self.tool_results.is_empty() {
            return TOOL_RESULTS_PADDING.to_string();
        }
        content
    }
}

/// 连续的 `role:"tool"` 消息累积成一组。
#[derive(Default)]
struct PendingTools {
    results: Vec<Value>,
    degraded: Vec<String>,
}

impl PendingTools {
    /// `toolUseId` 必须是历史里真实发出过的；对不上的降级成文本。
    fn push(&mut self, message: &Value, issued: &BTreeSet<String>) {
        let id = message
            .get("tool_call_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let content = flatten_content(message.get("content"));
        if !id.is_empty() && issued.contains(id) {
            self.results.push(json!({
                "toolUseId": id,
                "content": [{ "text": content }],
                "status": "success"
            }));
        } else {
            self.degraded.push(format!("[tool result] {content}"));
        }
    }
}

/// 构造请求体。
pub fn build(body: &Value, model: &str, profile_arn: Option<&str>) -> Result<Value, String> {
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "请求里没有 messages 数组".to_string())?;
    if messages.is_empty() {
        return Err("messages 为空".to_string());
    }

    // ① 只有真实发出过的 toolUseId 才允许回灌（对不上上游会 400）。
    let issued = issued_tool_ids(messages);

    // ② 拆出 system（可能多条，按顺序拼接）
    let mut system_parts: Vec<String> = Vec::new();
    for message in messages {
        if matches!(role_of(message), "system" | "developer") {
            system_parts.push(flatten_content(message.get("content")));
        }
    }

    // ③ 逐条转成轮次：assistant 的 tool_calls 变 toolUses，
    //    连续的 tool 消息累积成一组，挂到紧随其后的 user turn 上。
    let mut turns: Vec<Turn> = Vec::new();
    let mut pending: Option<PendingTools> = None;
    for message in messages {
        match role_of(message) {
            "system" | "developer" => {}
            "assistant" => {
                // 畸形历史（tool 组后面直接跟 assistant）：结果自成一轮，不丢内容。
                if let Some(group) = pending.take() {
                    let mut turn = Turn::user(String::new());
                    turn.attach(group);
                    turns.push(turn);
                }
                turns.push(Turn::assistant(
                    flatten_content(message.get("content")),
                    tool_uses_of(message),
                ));
            }
            "tool" => pending
                .get_or_insert_with(PendingTools::default)
                .push(message, &issued),
            _ => {
                let mut turn = Turn::user(flatten_content(message.get("content")));
                if let Some(group) = pending.take() {
                    turn.attach(group);
                }
                turns.push(turn);
            }
        }
    }
    // 末尾没有 user turn 承接的工具组属于 currentMessage。
    let trailing_tools = pending.is_some();
    if let Some(group) = pending.take() {
        let mut turn = Turn::user(String::new());
        turn.attach(group);
        turns.push(turn);
    }
    if turns.is_empty() {
        return Err("messages 里没有 user / assistant 轮次".to_string());
    }

    // ④ system 拼进第一条 user turn
    if !system_parts.is_empty() {
        let prefix = system_parts.join("\n\n");
        if let Some(first_user) = turns.iter_mut().find(|turn| turn.is_user) {
            first_user.text = if first_user.text.is_empty() {
                prefix
            } else {
                format!("{prefix}\n\n{}", first_user.text)
            };
        }
    }

    // ⑤ 摘出 currentMessage。挂在末轮上的工具结果留在 history：
    //    currentMessage 只承载用户本轮指令，结果放在紧随 assistant 的 user turn 里，
    //    上游只校验 toolUseId 是否真实存在，不要求结果在 currentMessage。
    let mut current = turns.pop().ok_or_else(|| "messages 为空".to_string())?;
    // ── 末尾是 assistant 时它**不是**本轮指令 ────────────────────
    // 客户端可能把上一轮答复也带回来（预填充 / 重放历史 / 只有 assistant
    // 的摘要），此时无条件 `pop()` 会把它当 `currentMessage`：上游收到的
    // 「用户这句话」其实是它自己的答复，而那条 assistant 轮里的 `tool_calls`
    // 也一起丢了（历史里没有它，工具结果又对不上 → 全部降级成文本）。
    // 正确处置：推回 history，`currentMessage` 用官方客户端的 `Continue` 兜底。
    if !current.is_user {
        turns.push(current);
        current = Turn::user(CONTINUE_PADDING.to_string());
    }
    if !trailing_tools
        && current.is_user
        && (!current.tool_results.is_empty() || !current.degraded.is_empty())
    {
        let mut tool_turn = Turn::user(String::new());
        tool_turn.tool_results = std::mem::take(&mut current.tool_results);
        tool_turn.degraded = std::mem::take(&mut current.degraded);
        turns.push(tool_turn);
    }
    let mut history = turns;

    // ⑥ 补 padding 使 history 严格交替（起点必须是 user）
    if history.first().is_some_and(|turn| !turn.is_user) {
        history.insert(0, Turn::user(CONTINUE_PADDING.to_string()));
    }
    let mut normalized: Vec<Turn> = Vec::with_capacity(history.len());
    for turn in history {
        let same_role = normalized
            .last()
            .is_some_and(|last| last.is_user == turn.is_user);
        if same_role {
            normalized.push(Turn::padding(!turn.is_user));
        }
        normalized.push(turn);
    }
    // 末尾必须是 assistant（currentMessage 是 user）
    if normalized.last().is_some_and(|turn| turn.is_user) {
        normalized.push(Turn::padding(false));
    }

    // ⑦ 超上限：把最老的折成一条文本 turn
    if normalized.len() > MAX_HISTORY_ENTRIES {
        let fold_count = normalized.len() - MAX_HISTORY_ENTRIES + 1;
        let folded: Vec<String> = normalized
            .drain(..fold_count)
            .map(|turn| {
                format!(
                    "{}: {}",
                    if turn.is_user { "user" } else { "assistant" },
                    turn.content()
                )
            })
            .collect();
        normalized.insert(0, Turn::user(folded.join("\n")));
        if normalized.get(1).is_some_and(|turn| turn.is_user) {
            normalized.insert(1, Turn::padding(false));
        }
    }

    // ⑧ 组装
    let mut current_message = Map::new();
    current_message.insert("content".into(), Value::String(current.content()));
    current_message.insert("modelId".into(), Value::String(model.to_string()));
    current_message.insert("origin".into(), Value::String("AI_EDITOR".to_string()));
    if let Some(context) = current_context(body, &current.tool_results) {
        current_message.insert("userInputMessageContext".into(), context);
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
        json!({ "userInputMessage": Value::Object(current_message) }),
    );
    if !normalized.is_empty() {
        let entries: Vec<Value> = normalized
            .iter()
            .map(|turn| serialize_turn(turn, model))
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

fn role_of(message: &Value) -> &str {
    message
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("user")
}

/// 历史里真实发出过的 toolUseId 集合。
fn issued_tool_ids(messages: &[Value]) -> BTreeSet<String> {
    let mut issued = BTreeSet::new();
    for message in messages {
        if role_of(message) != "assistant" {
            continue;
        }
        let Some(calls) = message.get("tool_calls").and_then(Value::as_array) else {
            continue;
        };
        for call in calls {
            if let Some(id) = call
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            {
                issued.insert(id.to_string());
            }
        }
    }
    issued
}

/// OpenAI `tool_calls[]` → Kiro `toolUses[]`。
///
/// `arguments` 是 JSON 字符串，解析成对象；解析失败就原样塞成字符串 ——
/// 宁可让上游拒绝，也不要丢内容。
fn tool_uses_of(message: &Value) -> Vec<Value> {
    let Some(calls) = message.get("tool_calls").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut uses = Vec::with_capacity(calls.len());
    for call in calls {
        let id = call.get("id").and_then(Value::as_str).unwrap_or("");
        let function = call.get("function").unwrap_or(call);
        let name = function.get("name").and_then(Value::as_str).unwrap_or("");
        let input = match function.get("arguments") {
            Some(Value::String(raw)) => {
                serde_json::from_str::<Value>(raw).unwrap_or_else(|_| Value::String(raw.clone()))
            }
            Some(Value::Null) | None => json!({}),
            Some(other) => other.clone(),
        };
        uses.push(json!({ "toolUseId": id, "name": name, "input": input }));
    }
    uses
}

/// 序列化一条 history 轮次。
fn serialize_turn(turn: &Turn, model: &str) -> Value {
    if turn.is_user {
        let mut user = Map::new();
        user.insert("content".into(), Value::String(turn.content()));
        user.insert("modelId".into(), Value::String(model.to_string()));
        user.insert("origin".into(), Value::String("AI_EDITOR".to_string()));
        if !turn.tool_results.is_empty() {
            user.insert(
                "userInputMessageContext".into(),
                json!({ "toolResults": turn.tool_results }),
            );
        }
        json!({ "userInputMessage": Value::Object(user) })
    } else {
        let mut assistant = Map::new();
        assistant.insert("content".into(), Value::String(turn.content()));
        if !turn.tool_uses.is_empty() {
            assistant.insert("toolUses".into(), Value::Array(turn.tool_uses.clone()));
        }
        json!({ "assistantResponseMessage": Value::Object(assistant) })
    }
}

/// currentMessage 的 context：工具声明 + 本轮回灌的工具结果。
fn current_context(body: &Value, tool_results: &[Value]) -> Option<Value> {
    let mut context = user_context(body).unwrap_or_else(|| json!({}));
    if !tool_results.is_empty() {
        context["toolResults"] = Value::Array(tool_results.to_vec());
    }
    if context.as_object().is_some_and(Map::is_empty) {
        return None;
    }
    Some(context)
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
    fn trailing_assistant_turn_goes_to_history_and_current_uses_continue() {
        // 末尾是 assistant（客户端把上一轮答复一起带回来了）：它不是本轮指令，
        // 必须进 history —— 否则它的 tool_calls 会整条丢掉。
        let body = json!({
            "messages": [
                { "role": "user", "content": "读一下 a.txt" },
                { "role": "assistant", "content": "", "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "read_file", "arguments": "{\"path\":\"a.txt\"}" }
                }]}
            ]
        });
        let wire = build(&body, "m", None).expect("应能构造");
        let history = wire["conversationState"]["history"]
            .as_array()
            .expect("应有 history");
        // 起点补 padding user，末尾是那条 assistant（toolUses 保留）
        assert!(history.len() >= 2, "history 至少含 padding + assistant");
        let last = history.last().expect("应有末轮");
        let uses = last["assistantResponseMessage"]["toolUses"]
            .as_array()
            .expect("assistant 轮的工具调用不能丢");
        assert_eq!(uses[0]["toolUseId"], "call_1");
        assert_eq!(
            wire["conversationState"]["currentMessage"]["userInputMessage"]["content"],
            CONTINUE_PADDING
        );
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

    #[test]
    fn assistant_tool_calls_become_tool_uses() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "读文件" },
                { "role": "assistant", "content": "", "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": { "name": "read_file", "arguments": "{\"path\":\"a.txt\"}" }
                }]},
                { "role": "tool", "tool_call_id": "call_1", "content": "文件内容" }
            ]
        });
        let wire = build(&body, "m", None).expect("应能构造");
        let history = wire["conversationState"]["history"]
            .as_array()
            .expect("应有 history");
        let assistant = history
            .iter()
            .find(|entry| entry.get("assistantResponseMessage").is_some())
            .expect("应有 assistant 条目");
        assert_eq!(
            assistant["assistantResponseMessage"]["toolUses"][0]["toolUseId"],
            "call_1"
        );
        assert_eq!(
            assistant["assistantResponseMessage"]["toolUses"][0]["name"],
            "read_file"
        );
        assert_eq!(
            assistant["assistantResponseMessage"]["toolUses"][0]["input"]["path"],
            "a.txt"
        );

        let current = &wire["conversationState"]["currentMessage"]["userInputMessage"];
        assert_eq!(current["content"], "Tool results provided.");
        assert_eq!(
            current["userInputMessageContext"]["toolResults"][0]["toolUseId"],
            "call_1"
        );
        assert_eq!(
            current["userInputMessageContext"]["toolResults"][0]["status"],
            "success"
        );
    }

    #[test]
    fn tool_result_attaches_to_the_following_user_turn() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "读文件" },
                { "role": "assistant", "content": "", "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": { "name": "read_file", "arguments": "{}" }
                }]},
                { "role": "tool", "tool_call_id": "call_1", "content": "文件内容" },
                { "role": "user", "content": "继续" }
            ]
        });
        let wire = build(&body, "m", None).expect("应能构造");
        let history = wire["conversationState"]["history"]
            .as_array()
            .expect("应有 history");
        let user_with_tools = history
            .iter()
            .find(|entry| {
                entry
                    .get("userInputMessage")
                    .is_some_and(|u| u.get("userInputMessageContext").is_some())
            })
            .expect("应有一个带 toolResults 的 user turn");
        assert_eq!(
            user_with_tools["userInputMessage"]["userInputMessageContext"]["toolResults"][0]
                ["toolUseId"],
            "call_1"
        );
        assert_eq!(
            wire["conversationState"]["currentMessage"]["userInputMessage"]["content"],
            "继续"
        );
    }

    #[test]
    fn unknown_tool_use_id_degrades_to_text() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "开始" },
                { "role": "tool", "tool_call_id": "never_issued", "content": "孤儿结果" },
                { "role": "user", "content": "继续" }
            ]
        });
        let wire = build(&body, "m", None).expect("应能构造");
        let history = wire["conversationState"]["history"]
            .as_array()
            .expect("应有 history");
        let joined = history
            .iter()
            .map(|entry| entry.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("孤儿结果"),
            "对不上的工具结果必须降级成文本保留"
        );
        assert!(
            !joined.contains("\"toolResults\""),
            "不得把未知 id 写进 toolResults"
        );
    }
}
