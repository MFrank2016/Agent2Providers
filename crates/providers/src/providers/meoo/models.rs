//! Meoo 模型目录：默认模型占位 + 项目服务 AK 探活。
//!
//! ── 本文件此刻只做探活 ──────────────────────────────────────
//! 完整目录（拉取 / 缓存 / 元数据映射）在 Task 7 落地；Task 4 只需要一个
//! 「这个 AK 到底能不能用」的判据，供添加账号时立即失败。
//!
//! ── 探活走网关，不走控制面 ──────────────────────────────────
//! `GET {gateway_base}/models` 认的是**项目服务 AK**（Bearer），控制面 token
//! 在这里无效。头一律由 [`headers::gateway_headers`] 构造（含 `X-Meoo-*`
//! 三件套与可选 `OneDay-App-Id`）。
//!
//! ── 401 与其余错误分开 ──────────────────────────────────────
//! 401 = AK 无效 / 过期，用户该换一个；其余（5xx / 网络）是上游或链路问题，
//! 归 502。把 5xx 归成 401 会让一次上游抖动表现为「你的 AK 填错了」。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_provider_sdk::PluginCtx;

use crate::errors::GatewayError;

use super::{endpoints, headers};

/// 默认模型（Task 7 换成真实目录前的占位）。
pub fn default_models() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "id": "qwen3.8-flash",
        "name": "Qwen3.8-Flash",
        "maxInputTokens": 200000,
        "maxOutputTokens": 64000,
        "supportsToolCall": true
    })]
}

/// 用 `GET /models` 验证项目服务 AK 是否可用。
///
/// Task 5 接线前暂无调用方，故此处关掉未使用告警（与 `endpoints.rs` /
/// `headers.rs` 同一条口径）。
#[allow(dead_code)]
pub async fn validate_service_ak(
    ctx: &PluginCtx,
    ak: &str,
    project: Option<&str>,
) -> Result<(), GatewayError> {
    let client = crate::http::client(None, &ctx.env.proxy);
    let (status, _payload) = crate::http::get_json(
        &client,
        &endpoints::models_url(&endpoints::gateway_base()),
        &headers::gateway_headers(ak, project.unwrap_or(""), false),
    )
    .await
    .map_err(|error| GatewayError::with_status(502, format!("Meoo 模型目录失败：{error}")))?;
    if !(200..300).contains(&status) {
        return Err(GatewayError::with_status(
            if status == 401 { 401 } else { 502 },
            format!("Meoo 项目服务 AK 验证失败（HTTP {status}）"),
        ));
    }
    Ok(())
}
