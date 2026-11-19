//! 在控制面、会话的 String 错误通道与 RPC 之间保留 HTTP 状态和业务元数据。

use agent2api_provider_protocol as proto;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const CONTROL_ERROR_PREFIX: &str = "CONTROL_ERROR:";
const HTTP_CODE_PREFIX: &str = "provider_http:";
const MAX_SAFE_INTEGER: i64 = (1_i64 << 53) - 1;
const MAX_FUTURE_RESET_MS: i64 = 366 * 86_400_000;
const MAX_RETRY_AFTER_SECS: u64 = 604_800;

#[derive(Serialize, Deserialize)]
struct ControlError {
    message: String,
    #[serde(flatten)]
    metadata: ErrorMetadata,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorMetadata {
    status: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream_code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sign_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_scope: Option<String>,
    #[serde(default, alias = "reset_at", skip_serializing_if = "Option::is_none")]
    reset_at: Option<i64>,
    #[serde(default, alias = "retry_after_secs", skip_serializing_if = "Option::is_none")]
    retry_after_secs: Option<u64>,
}

pub fn control_error(
    status: i32,
    message: impl Into<String>,
    code: Option<String>,
    upstream_code: Option<i64>,
) -> String {
    control_error_with_sign_in(status, message, code, upstream_code, None, None)
}

/// 供 helper 桥接控制面或 head 前的会话错误；公开入口在 `sdk::serve`。
/// `sign_in` / `credential_scope` 只保留上游明确给出的语义，不推断或修改账号状态。
/// 元数据仍放在 `provider_http:` JSON 内，旧宿主忽略新增字段。
pub fn control_error_with_sign_in(
    status: i32,
    message: impl Into<String>,
    code: Option<String>,
    upstream_code: Option<i64>,
    sign_in: Option<String>,
    credential_scope: Option<String>,
) -> String {
    control_error_with_timing(status, message, code, upstream_code, sign_in, credential_scope, None, None)
}

/// 兼容扩展：reset_at 只表示 Unix 毫秒，retry_after_secs 只表示整数秒。
/// 仅输出 resetAt/retryAfterSecs；None/0/非法 timing 不改变旧信封，也不授权分类或冷却。
pub fn control_error_with_timing(
    status: i32,
    message: impl Into<String>,
    code: Option<String>,
    upstream_code: Option<i64>,
    sign_in: Option<String>,
    credential_scope: Option<String>,
    reset_at: Option<i64>,
    retry_after_secs: Option<u64>,
) -> String {
    let (reset_at, retry_after_secs) = safe_timing(status, code.as_deref(), reset_at, retry_after_secs);
    let error = ControlError {
        message: message.into(),
        metadata: ErrorMetadata { status, code, upstream_code, sign_in, credential_scope, reset_at, retry_after_secs },
    };
    if !(400..600).contains(&status) {
        return error.message;
    }
    match serde_json::to_string(&error) {
        Ok(payload) => format!("{CONTROL_ERROR_PREFIX}{payload}"),
        Err(_) => error.message,
    }
}

fn safe_timing(
    status: i32, code: Option<&str>, reset_at: Option<i64>, retry_after_secs: Option<u64>,
) -> (Option<i64>, Option<u64>) {
    // 无 timing 的旧 API 不增加时钟读取或其他行为。
    if reset_at.is_none() && retry_after_secs.is_none() { return (None, None); }
    let code = code.unwrap_or("").to_ascii_lowercase();
    if !(400..600).contains(&status) || matches!(status, 499 | 504 | 556)
        || code.contains("cleanup") || matches!(code.as_str(), "499" | "504" | "556" | "local_precondition"
            | "aborted" | "abort_err" | "cancelled" | "canceled" | "login_cancelled"
            | "timeout" | "network_timeout" | "upstream_timeout" | "login_timeout") {
        return (None, None);
    }
    // SDK 不新增 chrono 依赖；helper 已做 chrono 校验，这里再限制真实 future 的 366 天窗口。
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok());
    let reset_at = reset_at.filter(|reset| *reset > 0 && *reset <= MAX_SAFE_INTEGER
        && now.is_some_and(|now| *reset > now && now.checked_add(MAX_FUTURE_RESET_MS).is_some_and(|ceiling| *reset <= ceiling)));
    let retry_after_secs = retry_after_secs.filter(|seconds| *seconds > 0 && *seconds <= MAX_RETRY_AFTER_SECS);
    (reset_at, retry_after_secs)
}

pub(crate) fn is_unauthorized(message: &str) -> bool {
    message.strip_prefix(CONTROL_ERROR_PREFIX)
        .and_then(|payload| serde_json::from_str::<ControlError>(payload).ok())
        .is_some_and(|error| error.metadata.status == 401
            && error.metadata.code.as_deref() != Some("checkin_auth_retry_exhausted"))
}

pub(crate) fn to_wire_error(message: String) -> proto::WireError {
    if let Some(detail) = crate::provider::split_local_precondition(&message) {
        proto::WireError::with_code(detail, proto::WireError::LOCAL_PRECONDITION)
    } else if let Some(detail) = crate::provider::split_unsupported(&message) {
        proto::WireError::with_code(detail, proto::WireError::UNSUPPORTED)
    } else if let Some(error) = split_control_error(&message) {
        error
    } else {
        proto::WireError::with_code(message, proto::WireError::INTERNAL)
    }
}

fn split_control_error(message: &str) -> Option<proto::WireError> {
    let payload = message.strip_prefix(CONTROL_ERROR_PREFIX)?;
    let mut error: ControlError = serde_json::from_str(payload).ok()?;
    if !(400..600).contains(&error.metadata.status) {
        return None;
    }
    let (reset_at, retry_after_secs) = safe_timing(
        error.metadata.status, error.metadata.code.as_deref(), error.metadata.reset_at, error.metadata.retry_after_secs,
    );
    error.metadata.reset_at = reset_at;
    error.metadata.retry_after_secs = retry_after_secs;
    let metadata = serde_json::to_string(&error.metadata).ok()?;
    Some(proto::WireError::with_code(error.message, format!("{HTTP_CODE_PREFIX}{metadata}")))
}

#[cfg(test)]
mod control_roundtrip {
    //! 控制面错误过线时**状态码不许丢**。
    //!
    //! ── 这条为什么值得单独立个测试 ────────────────────────────
    //! 插件侧的 `GatewayError` 带 `status_code`，但控制面的错误通道只有一个
    //! `String`。丢掉状态码的后果不是「文案不好看」，而是网关那条按状态码分支
    //! 的链路**静默失效**：`core::usage_query::query_usage_inner` 靠
    //! `status_code == 401` 决定「刷新后重试一次」，靠刷新也失败来决定落
    //! `usage_credential_dead` 并按 1 小时退避。状态码一丢（比如误用
    //! `into_message` 而不是 `into_control_message`），两条分支都永不触发，
    //! 死凭证会被按 60 秒间隔无限重打 —— 生产实测一晚上几十条告警。
    //!
    //! 所以这里钉住的是**往返**：状态码 → 信封 → 网关可还原的 `provider_http:`
    //! 元数据。插件作者改错映射时，这条会立刻红。

    use super::*;

    /// 网关 `plugin_host::errors::control_error` 读的就是这个前缀与形状。
    fn gateway_metadata(error: &proto::WireError) -> Option<ErrorMetadata> {
        let payload = error.code.as_deref()?.strip_prefix(HTTP_CODE_PREFIX)?;
        serde_json::from_str(payload).ok()
    }

    #[test]
    fn a_401_survives_the_wire_and_stays_a_401() {
        let message = control_error(401, "Trae 积分接口返回 401", None, None);
        let wire = to_wire_error(message);
        let metadata = gateway_metadata(&wire).expect("控制面错误必须带 provider_http 元数据");
        assert_eq!(401, metadata.status, "网关靠这个数走「刷新后重试一次」");
        assert!(
            !wire.code.as_deref().unwrap_or("").starts_with(CONTROL_ERROR_PREFIX),
            "信封必须是网关认识的 provider_http，不是插件内部的 CONTROL_ERROR"
        );
    }

    #[test]
    fn the_upstream_code_and_business_code_are_carried_along() {
        let message = control_error(429, "额度用尽", Some("usage_not_configured".to_string()), Some(1005));
        let wire = to_wire_error(message);
        let metadata = gateway_metadata(&wire).expect("同上");
        assert_eq!(429, metadata.status);
        assert_eq!(Some("usage_not_configured".to_string()), metadata.code, "前端按 code 判定「未配置」");
        assert_eq!(Some(1005), metadata.upstream_code, "限额事件要记上游真码");
    }

    #[test]
    fn a_message_without_an_envelope_is_still_internal() {
        // 反面：`into_message` 那条路（只留文案）过线后只能是 INTERNAL ——
        // 这正是本次修复的 bug 的形态。留着它当对照，免得有人「简化」回
        // 只传文案的写法。
        let wire = to_wire_error("Trae 积分接口返回 401: …".to_string());
        assert_eq!(
            Some(proto::WireError::INTERNAL),
            wire.code.as_deref(),
            "裸文案过线没有状态码"
        );
        assert!(gateway_metadata(&wire).is_none(), "裸文案不带任何状态信息");
    }
}
