//! Meoo 模型目录：`GET {gateway}/models` + 静态兜底 + 5 分钟缓存。
//!
//! ── 上游形态（OpenAI 兼容，但比标准多几种）────────────────────
//! ```text
//! GET https://api.meoo.host/meoo-ai/compatible-mode/v1/models
//!   → {"data":[{"id":"qwen3.8-flash","name":"Qwen3.8-Flash",
//!               "context_length":200000,"max_output_tokens":64000,
//!               "capabilities":{"vision":true,"reasoning":true}}, …]}
//! ```
//! 上游可能给三种信封：`{"data":[…]}`、`{"models":[…]}`、裸数组；条目也有两种：
//! 字符串（只有 id）或对象。所以 [`parse`] 对两种信封 × 两种条目都要认。
//!
//! ── 为什么还要一张静态兜底表 ────────────────────────────────
//! 目录是**项目相关**的：AK 没开通云服务、项目刚建、上游抖动时都拿不到清单。
//! 此时给一份常见模型表，比让 `/v1/models` 返回空、客户端报「没有可用模型」
//! 要好 —— 兜底表里的每条都带上下文 / 输出 / 模态位，模型规则层能直接绑定。
//! 远程一旦成功就是权威，兜底只在「从没拉到过 / 拉取失败且无旧清单」时出现。
//!
//! ── 负缓存：失败也要记时刻 ──────────────────────────────────
//! 拉取失败时**保留上一份好清单**（没有就用兜底），并把 `fetched_at` 记成
//! 现在、`remote` 记成 false。少了这一步，AK 失效时每次 `/v1/models` 都会再
//! 打一次上游 —— 客户端的模型探测往往比对话频繁得多。用户手动刷新
//! （`refresh(force = true)`）绕过这层缓存，失败原因会如实回报。
//!
//! ── 401 与其余错误分开 ──────────────────────────────────────
//! 401 = AK 无效 / 过期，用户该换一个；其余（5xx / 网络）是上游或链路问题，
//! 归 502。把 5xx 归成 401 会让一次上游抖动表现为「你的 AK 填错了」。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use crate::errors::GatewayError;
use crate::http;
use crate::store;

use super::{credentials, endpoints, headers};

/// 目录缓存时长：5 分钟（自动路径的 TTL）。
const TTL_MS: i64 = 5 * 60 * 1000;

/// 未知模型的默认上下文窗口（上游没声明时的保守估计）
const DEFAULT_INPUT_TOKENS: i64 = 200_000;

/// 未知模型的默认单次输出上限
const DEFAULT_OUTPUT_TOKENS: i64 = 64_000;

/// 兜底表里一条模型的已知元数据：`(展示名, 上下文, 输出, 图片, 思考)`。
fn fallback_meta(id: &str) -> Option<(&'static str, i64, i64, bool, bool)> {
    let meta = match id {
        "qwen3.8-flash" => ("Qwen3.8-Flash", 200_000, 64_000, true, true),
        "qwen3.8-max-0902" => ("Qwen3.8-Max-0902", 200_000, 64_000, true, true),
        "qwen3.8-max" => ("Qwen3.8-Max", 200_000, 64_000, true, true),
        "qwen3.7-max" => ("Qwen3.7-Max", 200_000, 64_000, false, true),
        "qwen3.7-plus" => ("Qwen3.7-Plus", 200_000, 64_000, true, false),
        "deepseek-v4-pro-0813" => ("DeepSeek V4 Pro", 1_000_000, 384_000, false, true),
        "deepseek-v4-flash-0731" => ("DeepSeek V4 Flash", 1_000_000, 384_000, false, true),
        "glm-5.2-fast-preview" => ("GLM-5.2-Fast", 200_000, 64_000, false, true),
        "glm-5.2" => ("GLM-5.2", 200_000, 64_000, false, true),
        "qwen3-vl-plus" => ("Qwen VL", 200_000, 64_000, true, false),
        _ => return None,
    };
    Some(meta)
}

/// 聚合层认的一条模型记录（键名对照 `core/models/shape.rs::list_item`）。
fn entry(id: &str, name: &str, input: i64, output: i64, images: bool, reasoning: bool) -> Value {
    json!({
        "id": id,
        "name": name,
        "maxInputTokens": input,
        "maxOutputTokens": output,
        "supportsImages": images,
        "supportsReasoning": reasoning,
        "supportsToolCall": true,
        "supportsVideo": false,
    })
}

/// 兜底表里的一条（认不出返回 `None`）。
fn fallback_entry(id: &str) -> Option<Value> {
    let (name, input, output, images, reasoning) = fallback_meta(id)?;
    Some(entry(id, name, input, output, images, reasoning))
}

/// 一条记录的基准形态：兜底表认得就用它，认不出按未知模型默认值。
fn base_entry(id: &str) -> Value {
    fallback_entry(id).unwrap_or_else(|| {
        entry(
            id,
            id,
            DEFAULT_INPUT_TOKENS,
            DEFAULT_OUTPUT_TOKENS,
            false,
            false,
        )
    })
}

/// 静态兜底目录（顺序即界面上默认顺序）。
pub fn default_models() -> Vec<Value> {
    [
        "qwen3.8-flash",
        "qwen3.8-max-0902",
        "qwen3.8-max",
        "qwen3.7-max",
        "qwen3.7-plus",
        "deepseek-v4-pro-0813",
        "deepseek-v4-flash-0731",
        "glm-5.2-fast-preview",
        "glm-5.2",
        "qwen3-vl-plus",
    ]
    .iter()
    .filter_map(|id| fallback_entry(id))
    .collect()
}

/// 读一个正数（数字或数字字符串都认；`<= 0` 视为缺失）。
fn read_number(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_f64().map(|number| number as i64))
        .or_else(|| {
            value
                .as_str()
                .and_then(|text| text.trim().parse::<i64>().ok())
        })
        .filter(|number| *number > 0)
}

/// 把上游的一条条目映射成聚合层形态（认不出返回 `None`）。
///
/// 字符串条目 = 只有 id；对象条目在兜底表（或未知默认）之上，用上游真给了
/// 的字段覆盖 —— **缺字段不覆盖**，避免把「上游没说」写成「不支持」。
fn entry_of(value: &Value) -> Option<Value> {
    if let Some(raw) = value.as_str() {
        let id = raw.trim();
        if id.is_empty() {
            return None;
        }
        return Some(base_entry(id));
    }
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())?;
    let mut mapped = base_entry(id);
    let object = mapped.as_object_mut()?;
    if let Some(name) = value
        .get("name")
        .or_else(|| value.get("display_name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        object.insert("name".to_string(), Value::String(name.to_string()));
    }
    for key in [
        "context_length",
        "context_window",
        "max_input_tokens",
        "max_context_length",
    ] {
        if let Some(number) = value.get(key).and_then(read_number) {
            object.insert("maxInputTokens".to_string(), Value::from(number));
            break;
        }
    }
    for key in ["max_tokens", "max_output_tokens"] {
        if let Some(number) = value.get(key).and_then(read_number) {
            object.insert("maxOutputTokens".to_string(), Value::from(number));
            break;
        }
    }
    if let Some(capabilities) = value.get("capabilities") {
        if let Some(images) = capabilities
            .get("vision")
            .or_else(|| capabilities.get("images"))
            .and_then(Value::as_bool)
        {
            object.insert("supportsImages".to_string(), Value::Bool(images));
        }
        if let Some(reasoning) = capabilities.get("reasoning").and_then(Value::as_bool) {
            object.insert("supportsReasoning".to_string(), Value::Bool(reasoning));
        }
    }
    Some(mapped)
}

/// 解析 `/models` 响应：`{"data":[…]}` / `{"models":[…]}` / 裸数组。
pub fn parse(payload: &Value) -> Vec<Value> {
    let rows: &[Value] = payload
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| payload.get("models").and_then(Value::as_array))
        .or_else(|| payload.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    rows.iter().filter_map(entry_of).collect()
}

/// 进程内目录状态（**只装这一份**：远程清单 / 兜底清单 + 最近一次尝试时刻）。
struct State {
    models: Vec<Value>,
    /// 最近一次**尝试**拉取的时刻（成功或失败都记 —— 负缓存见模块头）
    fetched_at: i64,
    /// 当前清单是否来自远程（`false` = 兜底或负缓存）
    remote: bool,
}

fn state() -> &'static Mutex<Option<State>> {
    static STATE: OnceLock<Mutex<Option<State>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

/// 在锁内执行一段取值（毒锁按「可重建的展示数据」处理）。
fn with_state<R>(f: impl FnOnce(&mut Option<State>) -> R) -> R {
    let mut guard = match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut guard)
}

/// 当前缓存快照 `(models, fetched_at, remote)`。
fn cached() -> Option<(Vec<Value>, i64, bool)> {
    with_state(|slot| {
        slot.as_ref()
            .map(|state| (state.models.clone(), state.fetched_at, state.remote))
    })
}

/// 缓存是否还在 TTL 内（不区分成功 / 失败 —— 失败也记时刻，见模块头）。
fn fresh() -> bool {
    cached()
        .filter(|(_, fetched_at, _)| http::now_ms() - fetched_at < TTL_MS)
        .is_some()
}

/// 落地一份清单。
fn remember(models: Vec<Value>, fetched_at: i64, remote: bool) {
    with_state(|slot| {
        *slot = Some(State {
            models,
            fetched_at,
            remote,
        });
    });
}

/// 负缓存：保留上一份好清单（没有就用兜底），记下失败时刻并返回清单本体。
fn negative_cache(now: i64) -> Vec<Value> {
    with_state(|slot| {
        let models = slot
            .as_ref()
            .map(|state| state.models.clone())
            .unwrap_or_else(default_models);
        *slot = Some(State {
            models: models.clone(),
            fetched_at: now,
            remote: false,
        });
        models
    })
}

/// 最后一次已知的清单（缓存优先，没有则兜底）+ 它自己的元数据。
fn snapshot() -> proto::ModelList {
    match cached() {
        Some((models, fetched_at, remote)) => proto::ModelList {
            models,
            meta: proto::CatalogMeta {
                remote,
                refreshed_at: fetched_at,
            },
        },
        None => proto::ModelList {
            models: default_models(),
            meta: proto::CatalogMeta::default(),
        },
    }
}

/// 发一次目录请求（项目服务 AK + CLI 头），非 2xx 也原样返回。
async fn request(ctx: &PluginCtx, ak: &str, project: &str) -> Result<(u16, Value), GatewayError> {
    let client = http::control_client(None, &ctx.env.proxy);
    http::get_json(
        &client,
        &endpoints::models_url(&endpoints::gateway_base()),
        &headers::gateway_headers(ak, project, false),
    )
    .await
    .map_err(|error| GatewayError::with_status(502, format!("Meoo 模型目录失败：{error}")))
}

/// 非 2xx 的分类：401 = AK 无效 / 过期，其余归 502。
fn status_error(status: u16) -> GatewayError {
    GatewayError::with_status(
        if status == 401 { 401 } else { 502 },
        if status == 401 {
            "Meoo 项目服务 AK 无效或已过期（HTTP 401），请重新登录或更换 AK".to_string()
        } else {
            format!("Meoo 模型目录失败（HTTP {status}）")
        },
    )
}

/// 拉一次目录（`GET {gateway}/models`）。
async fn fetch(ctx: &PluginCtx, ak: &str, project: &str) -> Result<Vec<Value>, GatewayError> {
    let (status, payload) = request(ctx, ak, project).await?;
    if !(200..300).contains(&status) {
        return Err(status_error(status));
    }
    let models = parse(&payload);
    if models.is_empty() {
        return Err(GatewayError::with_status(502, "Meoo 模型目录为空"));
    }
    Ok(models)
}

/// 用 `GET /models` 验证项目服务 AK 是否可用。
///
/// 与目录共用 [`request`]，但**只按状态码判定**：200 就算 AK 可用 ——
/// 「项目还没开通任何模型」不该表现成「你的 AK 填错了」（Task 4 的口径）。
/// 响应不是 JSON（例如反代返回的 HTML 错误页）仍然判 502。
pub async fn validate_service_ak(
    ctx: &PluginCtx,
    ak: &str,
    project: Option<&str>,
) -> Result<(), GatewayError> {
    let (status, payload) = request(ctx, ak, project.unwrap_or("")).await?;
    if !(200..300).contains(&status) {
        return Err(status_error(status));
    }
    if payload.is_null() {
        return Err(GatewayError::with_status(502, "Meoo 模型目录响应不是 JSON"));
    }
    Ok(())
}

/// 当前模型清单（TTL 内直接用缓存；过期则拉一次，失败沿用旧清单）。
pub async fn list(ctx: &PluginCtx, account: &str) -> proto::ModelList {
    if let Some((models, fetched_at, remote)) =
        cached().filter(|(_, fetched_at, _)| http::now_ms() - fetched_at < TTL_MS)
    {
        return proto::ModelList {
            models,
            meta: proto::CatalogMeta {
                remote,
                refreshed_at: fetched_at,
            },
        };
    }
    let record = match store::record(ctx, super::ID, account).await {
        Ok(record) => record,
        // 读不到账号不是「没有模型」：沿用最后一次已知清单（含远程那份）。
        Err(_) => return snapshot(),
    };
    let cred = credentials::from_secret(&store::secret_view(&record));
    if cred.service_ak.is_empty() {
        return snapshot();
    }
    match fetch(ctx, &cred.service_ak, &cred.project_url_id).await {
        Ok(models) => {
            let now = http::now_ms();
            remember(models.clone(), now, true);
            proto::ModelList {
                models,
                meta: proto::CatalogMeta {
                    remote: true,
                    refreshed_at: now,
                },
            }
        }
        Err(_) => {
            // 失败也记 fetched_at：TTL 内不再重复打上游（否则 AK 失效时
            // 每次 /v1/models 都会再打一次）。手动刷新 force=true 会绕过。
            let now = http::now_ms();
            let models = negative_cache(now);
            proto::ModelList {
                models,
                meta: proto::CatalogMeta {
                    remote: false,
                    refreshed_at: now,
                },
            }
        }
    }
}

/// 刷新目录：成功落地并返回条数；失败保留旧清单、如实回报原因。
///
/// `force = false`（自动路径）时 TTL 内早退为 `unchanged()`；
/// `force = true`（用户手动刷新）真打上游，并绕过负缓存 —— 失败**不**记
/// 失败时刻，否则刚刷过一次的账号接下来 5 分钟的自动刷新会被自己抑制掉。
pub async fn refresh(ctx: &PluginCtx, account: &str, force: bool) -> proto::RefreshOutcome {
    if !force && fresh() {
        return proto::RefreshOutcome::unchanged();
    }
    let record = match store::record(ctx, super::ID, account).await {
        Ok(record) => record,
        Err(error) => return proto::RefreshOutcome::failed(error.message),
    };
    let cred = credentials::from_secret(&store::secret_view(&record));
    if cred.service_ak.is_empty() {
        return proto::RefreshOutcome::failed("Meoo 账号没有项目服务 AK，请重新登录");
    }
    match fetch(ctx, &cred.service_ak, &cred.project_url_id).await {
        Ok(models) => {
            let now = http::now_ms();
            let count = models.len();
            remember(models, now, true);
            proto::RefreshOutcome::refreshed(count)
        }
        Err(error) => {
            // 只有**自动**路径（`force = false`）才记负缓存：用户手动刷新失败后
            // 还写 `remote = false` + 5 分钟 TTL，等于把「我刚刷过一次」的证据
            // 抹掉，接下来 5 分钟的自动刷新全被抑制，界面停在一份旧清单上。
            // 手动刷新的结果如实回报，缓存保持原样。
            if !force {
                negative_cache(http::now_ms());
            }
            proto::RefreshOutcome::failed(error.message)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_openai_style_models() {
        let models = parse(&json!({
            "data": [
                {"id":"qwen3.8-flash","name":"Qwen3.8-Flash","context_length":200000,"max_output_tokens":64000},
                {"id":"deepseek-v4-pro-0813","context_length":1000000,"max_tokens":384000}
            ]
        }));
        assert_eq!(models.len(), 2);
        assert_eq!(models[0]["id"], "qwen3.8-flash");
        assert_eq!(models[0]["maxInputTokens"], 200000);
        assert_eq!(models[1]["maxInputTokens"], 1000000);
        assert_eq!(models[1]["maxOutputTokens"], 384000);
    }

    #[test]
    fn parses_string_models_and_falls_back_to_table() {
        let models = parse(&json!({"models": ["qwen3.8-flash", "qwen3-vl-plus"]}));
        assert_eq!(models.len(), 2);
        assert_eq!(models[1]["id"], "qwen3-vl-plus");
        assert_eq!(models[1]["supportsImages"], true);
    }

    #[test]
    fn fallback_contains_vision_model() {
        let models = default_models();
        assert!(models.iter().any(|item| item["id"] == "qwen3-vl-plus"));
        assert!(models
            .iter()
            .any(|item| item["id"] == "deepseek-v4-pro-0813"));
    }

    #[test]
    fn parses_bare_array_and_object_capabilities() {
        let models = parse(&json!([
            {
                "id": "qwen3-vl-plus",
                "display_name": "Qwen VL Plus",
                "context_window": "131072",
                "max_output_tokens": 8192,
                "capabilities": {"vision": true, "reasoning": true}
            }
        ]));
        assert_eq!(models.len(), 1);
        assert_eq!(models[0]["name"], "Qwen VL Plus");
        assert_eq!(models[0]["maxInputTokens"], 131072);
        assert_eq!(models[0]["maxOutputTokens"], 8192);
        assert_eq!(models[0]["supportsImages"], true);
        assert_eq!(models[0]["supportsReasoning"], true);
        // 工具调用位按 OpenAI 兼容网关的既有能力给 true
        assert_eq!(models[0]["supportsToolCall"], true);
    }

    #[test]
    fn unknown_model_gets_defaults() {
        let models = parse(&json!({"data": ["brand-new-model"]}));
        assert_eq!(models.len(), 1);
        let model = &models[0];
        assert_eq!(model["name"], "brand-new-model");
        assert_eq!(model["maxInputTokens"], DEFAULT_INPUT_TOKENS);
        assert_eq!(model["maxOutputTokens"], DEFAULT_OUTPUT_TOKENS);
        assert_eq!(model["supportsImages"], false);
        assert_eq!(model["supportsReasoning"], false);
        assert_eq!(model["supportsToolCall"], true);
        assert_eq!(model["supportsVideo"], false);
    }

    #[test]
    fn empty_or_malformed_entries_are_dropped() {
        assert!(parse(&json!({"data": ["", "   ", {"name": "no id"}, 42]})).is_empty());
        assert!(parse(&json!({"unexpected": []})).is_empty());
        assert!(parse(&json!(null)).is_empty());
    }

    #[test]
    fn fallback_table_carries_context_and_modalities() {
        let models = default_models();
        assert_eq!(models.len(), 10);
        let deepseek = models
            .iter()
            .find(|model| model["id"] == "deepseek-v4-pro-0813")
            .expect("兜底表必须含 deepseek-v4-pro-0813");
        assert_eq!(deepseek["maxInputTokens"], 1_000_000);
        assert_eq!(deepseek["maxOutputTokens"], 384_000);
        assert_eq!(deepseek["supportsImages"], false);
        assert_eq!(deepseek["supportsReasoning"], true);
        assert_eq!(deepseek["supportsToolCall"], true);
        assert_eq!(deepseek["supportsVideo"], false);
    }

    #[test]
    fn status_errors_split_401_from_the_rest() {
        assert_eq!(status_error(401).status_code, 401);
        assert_eq!(status_error(500).status_code, 502);
        assert_eq!(status_error(429).status_code, 502);
    }
}
