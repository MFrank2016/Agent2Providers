//! Meoo 对话：OpenAI 兼容，插件只构造 URL + 头 + body。
//!
//! ── 这一层为什么几乎是空的 ──────────────────────────────────
//! 上游就是 OpenAI Chat Completions（`POST {gateway}/chat/completions`），
//! 网关自己也是 OpenAI 方言，所以 body 原样上行、SSE 原样下发。这里只做
//! 三件格式本身表达不了的事：取**项目服务 AK** 当 Bearer、带上官方 CLI 头、
//! 按 `stream` 选 `Accept`。头的唯一出处是 [`headers::gateway_headers`] ——
//! 别处手拼 `X-Meoo-*` 就会漏掉 `X-Meoo-Request-Id` 这类只在生产暴露的差异。
//!
//! ── 两种 Bearer，别拿错 ────────────────────────────────────
//! 对话必须用 `meoo_project_service_v1.*`（项目服务 AK），**不是** OAuth
//! access token：后者只对控制面有效，拿去打模型网关必然 401。网关在调用
//! `build_chat` 之前已经走过 `ensure_token`（内部会续期并重新解析 AK），
//! 所以这里读到的 AK 为空只可能是账号本身没配好 —— 直接 401，别打空 Bearer
//! 去换一个更难懂的上游错误。
//!
//! ── `stream` 由网关拥有 ─────────────────────────────────────
//! 网关请求上游**恒为 `stream:true`**（客户端要非流式时由网关聚合），所以
//! 本模块不改写 `stream`，只用它决定 `Accept`：SSE 要显式声明
//! `text/event-stream`，非流式只要 `application/json`。
//!
//! ── 错误分类的判定顺序（别重排）──────────────────────────────
//! ```text
//!   1. 401 + SERVICE_AK_FORMAT_INVALID  -> Fatal（AK 类型错，刷新救不了）
//!   2. 401 其余                          -> TokenExpired（刷新后重试一次）
//!   3. 403                               -> Fatal
//!   4. 402 / 429 / quota / 积分不足 / credit -> QuotaLimited（换号 + 冷却）
//!   5. 400 / 422                         -> 共用内容拦截分类
//!   6. 404                               -> Fatal
//!   7. 其余（含 5xx）                     -> Fatal（5xx 归 502）
//! ```
//! `SERVICE_AK_FORMAT_INVALID` 必须排在「401 ⇒ TokenExpired」之前：用户把
//! `meoo_ak_*`（用户 Key）当成项目服务 AK 粘进来时，刷新一万次也还是错的
//! 类型 —— 归成 TokenExpired 只会把一句可操作的提示拖成超时。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use serde_json::Value;

use agent2api_provider_sdk::ChatPlan;

use crate::errors::GatewayError;

use super::{credentials, endpoints, headers};

/// 「AK 类型错了」的统一提示（对话前拒绝与上游 401 共用同一句，避免两处措辞分叉）。
const AK_TYPE_HINT: &str = "Meoo 项目服务 AK 类型不正确：请使用 meoo_project_service_v1.*，\
                           不要用 meoo_ak_* 用户 Key";

/// 项目服务 AK 的固定前缀（用户 API Key 是 `meoo_ak_*`，前缀不同、用途也不同）。
const SERVICE_AK_PREFIX: &str = "meoo_project_service_v1.";

/// 准备一次上游调用。
///
/// `_client_stream` 只保留签名（网关把客户端偏好一并传来），**不参与判断**：
/// `Accept` 必须跟实际上行的 body 一致，见模块头。
pub fn build_plan(
    secret: &Value,
    body: &Value,
    _client_stream: bool,
) -> Result<ChatPlan, GatewayError> {
    let cred = credentials::from_secret(secret);
    if cred.service_ak.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "Meoo 账号缺少项目服务 AK，请重新登录或填写 AK",
        ));
    }
    // 宿主会把上游错误归一成 `{code, message}`，`error.code` 恒不存在 ——
    // `SERVICE_AK_FORMAT_INVALID` 那半条判据在对话链路上可能读不到。所以
    // 「AK 类型不对」必须在这里就拒掉：刷新救不了错误的前缀，只会把一句
    // 可操作的提示拖成一次无意义的重试。
    if !cred.service_ak.starts_with(SERVICE_AK_PREFIX) {
        return Err(GatewayError::with_status(401, AK_TYPE_HINT));
    }
    let mut payload = body.clone();
    if let Some(object) = payload.as_object_mut() {
        if object
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Err(GatewayError::with_status(400, "请求缺少 model 字段"));
        }
    }
    // 网关请求上游**恒为 stream:true**（见 upstream::payload），客户端要非流式
    // 时由网关聚合。因此 Accept 以 body.stream 为准，不能用客户端偏好。
    let upstream_stream = payload
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    Ok(ChatPlan::chat(
        endpoints::chat_url(&endpoints::gateway_base()),
        headers::gateway_headers(&cred.service_ak, &cred.project_url_id, upstream_stream),
        payload,
    ))
}

/// 上游错误分类（判定顺序见模块头，重排会改变编排层的动作）。
pub fn classify(status: u16, body: &Value) -> agent2api_provider_protocol::ErrorClass {
    use agent2api_provider_protocol::ErrorClass;
    let message = body
        .get("error")
        .and_then(|error| error.get("message"))
        .or_else(|| body.get("message"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let text = format!("Meoo 上游返回 {status}: {message}");
    let code = body
        .get("error")
        .and_then(|error| error.get("code"))
        .or_else(|| body.get("code"))
        .and_then(Value::as_i64);
    let code_text = body
        .get("error")
        .and_then(|error| error.get("code"))
        .or_else(|| body.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");

    if status == 401 {
        if message.contains("SERVICE_AK_FORMAT_INVALID")
            || code_text.contains("SERVICE_AK_FORMAT_INVALID")
        {
            return ErrorClass::Fatal {
                status: 401,
                message: AK_TYPE_HINT.to_string(),
                upstream_code: code,
            };
        }
        return ErrorClass::TokenExpired { message: text };
    }
    if status == 403 {
        return ErrorClass::Fatal {
            status: 403,
            message: text,
            upstream_code: code,
        };
    }
    if status == 402
        || status == 429
        || message.to_lowercase().contains("quota")
        || message.contains("积分不足")
        || message.to_lowercase().contains("credit")
    {
        return ErrorClass::QuotaLimited {
            reset_at: None,
            message: format!("{text}（Meoo 积分/额度不足，本网关按限流处理）"),
            upstream_code: code,
            status: 429,
        };
    }
    if status == 400 || status == 422 {
        return crate::content_block::classify_or_fatal(status, body, text, code);
    }
    if status == 404 {
        return ErrorClass::Fatal {
            status: 404,
            message: text,
            upstream_code: code,
        };
    }
    ErrorClass::Fatal {
        status: if status >= 500 { 502 } else { status },
        message: text,
        upstream_code: code,
    }
}

/// 思考档位翻译：只有上游声明支持 `reasoning_effort` 的模型才注入。
///
/// 认不出的模型一律 `Skip`（body 一个字节都不动）—— 给不支持的模型塞一个
/// 它不认识的字段，换来的往往是 400，而不是「想得更久」。
pub fn reasoning_patch(level: &str, model: &str) -> agent2api_provider_protocol::ReasoningPatch {
    use agent2api_provider_protocol::ReasoningPatch;
    let level = level.trim();
    if level.is_empty() {
        return ReasoningPatch::Skip {
            reason: "未配置思考等级".to_string(),
        };
    }
    // `qwen3.8-flash` 是目录里的默认 / 最便宜模型，兜底表里也标了
    // `supportsReasoning: true`：漏掉它等于让用户在最常用的模型上选不动思考档位。
    let supports = model.starts_with("deepseek-v4")
        || model.starts_with("glm-5.2")
        || model.starts_with("qwen3.8-flash")
        || model.starts_with("qwen3.8-max")
        || model == "qwen3.7-max";
    if supports {
        ReasoningPatch::Set {
            field: "reasoning_effort".to_string(),
            value: Value::String(level.to_string()),
        }
    } else {
        ReasoningPatch::Skip {
            reason: format!("Meoo 模型 {model} 没有声明思考等级"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use agent2api_provider_protocol as proto;
    use serde_json::json;

    #[test]
    fn chat_plan_has_cli_headers_and_service_ak() {
        let plan = build_plan(
            &json!({"serviceAk":"meoo_project_service_v1.x","projectUrlId":"p1"}),
            &json!({"model":"qwen3.8-flash","messages":[]}),
            true,
        )
        .expect("应构造");
        assert!(plan.url.ends_with("/chat/completions"));
        assert!(plan.headers.contains(&(
            "Authorization".into(),
            "Bearer meoo_project_service_v1.x".into()
        )));
        assert!(plan
            .headers
            .contains(&("X-Meoo-Client".into(), "cli".into())));
        assert!(plan.headers.contains(&(
            "Accept".into(),
            "text/event-stream, application/json".into()
        )));
    }

    #[test]
    fn service_ak_format_invalid_is_fatal() {
        let class = classify(
            401,
            &json!({"error":{"message":"SERVICE_AK_FORMAT_INVALID"}}),
        );
        match class {
            proto::ErrorClass::Fatal {
                status,
                ref message,
                ..
            } => {
                assert_eq!(status, 401);
                assert!(message.contains("meoo_project_service_v1"));
            }
            other => panic!("AK 类型错误必须是 Fatal 401，实际 {other:?}"),
        }
    }

    #[test]
    fn host_normalized_format_invalid_is_fatal() {
        // 宿主把上游错误归一成 `{code, message}`：`error.code` 恒不存在，
        // 只剩顶层 message 能带出 SERVICE_AK_FORMAT_INVALID。
        let class = classify(
            401,
            &json!({"code": null, "message": "SERVICE_AK_FORMAT_INVALID"}),
        );
        match class {
            proto::ErrorClass::Fatal {
                status,
                ref message,
                ..
            } => {
                assert_eq!(status, 401);
                assert!(message.contains("meoo_project_service_v1"));
            }
            other => panic!("归一后的 AK 类型错误必须是 Fatal 401，实际 {other:?}"),
        }
    }

    #[test]
    fn quota_is_quota_limited() {
        let class = classify(429, &json!({"error":{"message":"积分不足"}}));
        match class {
            proto::ErrorClass::QuotaLimited { status, .. } => assert_eq!(status, 429),
            other => panic!("积分不足必须是 QuotaLimited，实际 {other:?}"),
        }
    }

    #[test]
    fn non_stream_body_only_accepts_json() {
        let plan = build_plan(
            &json!({"serviceAk":"meoo_project_service_v1.x"}),
            &json!({"model":"qwen3.8-flash","stream":false}),
            false,
        )
        .expect("应构造");
        assert!(plan
            .headers
            .contains(&("Accept".into(), "application/json".into())));
        // 空项目不带 OneDay-App-Id（发了也没有意义）
        assert!(!plan.headers.iter().any(|(name, _)| name == "OneDay-App-Id"));
    }

    #[test]
    fn missing_service_ak_is_401() {
        let error = build_plan(
            &json!({"accessToken":"oauth_only"}),
            &json!({"model":"qwen3.8-flash"}),
            true,
        )
        .expect_err("没有项目服务 AK 必须拒绝");
        assert_eq!(error.status_code, 401);
        assert!(error.message.contains("项目服务 AK"));
    }

    #[test]
    fn non_project_service_ak_is_rejected_locally() {
        // 用户 Key（meoo_ak_*）拿去打模型网关只会 401，且宿主归一错误体后
        // 上游那句 SERVICE_AK_FORMAT_INVALID 可能读不到 —— 对话前就拒掉。
        let error = build_plan(
            &json!({"serviceAk":"meoo_ak_123","projectUrlId":"p1"}),
            &json!({"model":"qwen3.8-flash"}),
            true,
        )
        .expect_err("非项目服务 AK 必须拒绝");
        assert_eq!(error.status_code, 401);
        assert!(error.message.contains("meoo_project_service_v1"));
        assert!(error.message.contains("meoo_ak_"));
    }

    #[test]
    fn upstream_5xx_becomes_fatal_502() {
        let class = classify(503, &json!({"message":"服务器内部错误"}));
        match class {
            proto::ErrorClass::Fatal { status, .. } => assert_eq!(status, 502),
            other => panic!("5xx 必须是 Fatal 502，实际 {other:?}"),
        }
    }

    #[test]
    fn reasoning_effort_only_for_declared_models() {
        for model in [
            "deepseek-v4-pro-0813",
            "glm-5.2",
            "qwen3.8-flash",
            "qwen3.8-max-0902",
            "qwen3.7-max",
        ] {
            assert!(
                matches!(
                    reasoning_patch("high", model),
                    proto::ReasoningPatch::Set { ref field, .. } if field == "reasoning_effort"
                ),
                "{model} 应注入 reasoning_effort"
            );
        }
        assert!(matches!(
            reasoning_patch("high", "qwen3.7-plus"),
            proto::ReasoningPatch::Skip { .. }
        ));
        assert!(matches!(
            reasoning_patch("  ", "deepseek-v4-pro-0813"),
            proto::ReasoningPatch::Skip { .. }
        ));
    }

    #[test]
    fn reasoning_effort_reaches_the_default_flash_model() {
        // 目录对 qwen3.8-flash 声明 supportsReasoning: true，而它正是默认 /
        // 最便宜的那条 —— 漏掉它会让用户在最常用的模型上选不动思考档位。
        match reasoning_patch("high", "qwen3.8-flash") {
            proto::ReasoningPatch::Set { field, value } => {
                assert_eq!(field, "reasoning_effort");
                assert_eq!(value, serde_json::json!("high"));
            }
            other => panic!("qwen3.8-flash 应注入 reasoning_effort，实际 {other:?}"),
        }
    }
}
