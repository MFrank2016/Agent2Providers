//! Kiro 模型目录：`ListAvailableModels` + `ListAvailableProfiles`。
//!
//! ── 分页陷阱 ────────────────────────────────────────────────
//! 实测上游**每页都返回空 `nextToken`**。必须有三重停止条件：
//! token 为空 / token 已用过 / 本页无新增 —— 否则会无限翻页。
//!
//! ── 图片能力读字段不猜模型名 ─────────────────────────────────
//! 同一账号里 `glm-5` / `minimax-m2.5` 只支持文本，其余多数支持图片。
//! 按模型名猜必然出错。

use serde_json::{json, Value};

use super::auth::KiroCredential;

/// 每页条数。
const PAGE_SIZE: u32 = 50;
/// 最多翻多少页（防上游行为异常）。
const MAX_PAGES: usize = 20;

/// 把一页模型记录归一成网关认的形状。
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let Some(models) = payload.get("models").and_then(Value::as_array) else {
        return Vec::new();
    };
    models
        .iter()
        .filter_map(|model| {
            let id = model.get("modelId").and_then(Value::as_str)?;
            let name = model
                .get("modelName")
                .and_then(Value::as_str)
                .unwrap_or(id);
            let context_length = model
                .get("tokenLimits")
                .and_then(|limits| limits.get("maxInputTokens"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let vision = model
                .get("supportedInputTypes")
                .and_then(Value::as_array)
                .is_some_and(|types| types.iter().any(|kind| kind.as_str() == Some("IMAGE")));
            Some(json!({
                "id": id,
                "name": name,
                "context_length": context_length,
                "vision": vision,
            }))
        })
        .collect()
}

/// 下一页 token；空串与缺失都返回 `None`。
pub fn model_page_token(payload: &Value) -> Option<String> {
    payload
        .get("nextToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

/// 从 `ListAvailableProfiles` 的响应里取第一个 ARN。
pub fn profile_arn_of(payload: &Value) -> Option<String> {
    payload
        .get("profiles")
        .and_then(Value::as_array)?
        .iter()
        .find_map(|profile| {
            profile
                .get("arn")
                .or_else(|| profile.get("profileArn"))
                .and_then(Value::as_str)
                .filter(|arn| !arn.is_empty())
                .map(str::to_string)
        })
}

/// 拉一次完整目录（自动翻页）。
pub async fn fetch_all(
    client: &reqwest::Client,
    cred: &KiroCredential,
) -> Result<Vec<Value>, String> {
    let base = format!("https://q.{}.amazonaws.com", cred.region);
    let headers = super::auth::auth_headers(cred);
    let mut models: Vec<Value> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut next_token: Option<String> = None;
    for page in 0..MAX_PAGES {
        let mut url = format!(
            "{base}/ListAvailableModels?origin=AI_EDITOR&maxResults={PAGE_SIZE}"
        );
        if let Some(token) = &next_token {
            url.push_str("&nextToken=");
            url.push_str(&urlencode(token));
        }
        // `http::get_json` 返回 `(status, Value)`，不是带字段的结构体。
        let (status, payload) = crate::http::get_json(client, &url, &headers).await?;
        if !(200..300).contains(&status) {
            if models.is_empty() {
                return Err(format!(
                    "Kiro 模型目录拉取失败：HTTP {status} {}",
                    head_of(&payload)
                ));
            }
            break;
        }
        let added = parse_models(&payload);
        let mut new_count = 0;
        for model in added {
            let id = model.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            if seen.insert(id) {
                models.push(model);
                new_count += 1;
            }
        }
        next_token = model_page_token(&payload);
        // 只看「有没有下一页」，token 本体已在上面拼进 URL。
        let Some(_token) = next_token.clone() else { break };
        if page > 0 && new_count == 0 {
            break;
        }
    }
    Ok(models)
}

/// 错误体前 240 字符（`get_json` 已把空体 / 非 JSON 归成 `Null`）。
fn head_of(payload: &Value) -> String {
    payload.to_string().chars().take(240).collect()
}

/// 最小 query 编码（token 里可能带 `+` `/` `=`）。
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_model_list_with_capabilities() {
        let payload = json!({
            "models": [
                { "modelId": "claude-sonnet-4.5", "modelName": "Claude Sonnet 4.5",
                  "tokenLimits": { "maxInputTokens": 200000 },
                  "supportedInputTypes": ["TEXT", "IMAGE"] },
                { "modelId": "glm-5", "modelName": "GLM-5",
                  "tokenLimits": { "maxInputTokens": 128000 },
                  "supportedInputTypes": ["TEXT"] }
            ]
        });
        let models = parse_models(&payload);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0]["id"], "claude-sonnet-4.5");
        assert_eq!(models[0]["context_length"], 200000);
        assert_eq!(models[0]["vision"], true);
        assert_eq!(models[1]["vision"], false);
    }

    #[test]
    fn empty_next_token_is_none() {
        assert!(model_page_token(&json!({ "nextToken": "" })).is_none());
        assert!(model_page_token(&json!({})).is_none());
        assert_eq!(
            model_page_token(&json!({ "nextToken": "abc" })),
            Some("abc".to_string())
        );
    }

    #[test]
    fn profile_arn_is_read_from_profiles_list() {
        let payload = json!({ "profiles": [{ "arn": "arn:aws:codewhisperer:us-east-1:1:profile/x" }] });
        assert_eq!(
            profile_arn_of(&payload),
            Some("arn:aws:codewhisperer:us-east-1:1:profile/x".to_string())
        );
    }
}
