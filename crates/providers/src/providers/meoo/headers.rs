//! Meoo 请求头：CLI 头 + Bearer 的唯一构造入口。
//!
//! ── 为什么必须有 `X-Meoo-*` 三件套 ────────────────────────────
//! 上游把「是不是官方 CLI」当作准入条件之一，官方 CLI 每条请求都带：
//!
//! ```text
//!   X-Meoo-Client        cli
//!   X-Meoo-CLI-Version   0.5.6（随官方 CLI 升级）
//!   X-Meoo-Request-Id    cli_req_<uuid>（每请求唯一）
//! ```
//!
//! 本模块是这三条头的**唯一出处**：OAuth / 控制面 / 目录 / 对话 / 积分都从这里取，
//! 别处手拼就会出现「某条链路少了 Request-Id」这类只在生产才暴露的差异。
//!
//! ── 两种 Bearer，别混 ────────────────────────────────────────
//! - [`control_headers`]：`Authorization: Bearer <OAuth access_token>`（控制面）
//! - [`gateway_headers`]：`Authorization: Bearer <项目服务 AK>`（模型网关）
//!
//! 网关那侧还要按项目带 `OneDay-App-Id`；**空项目不带** —— 调用方在「还没
//! 解析出项目」时可能传空串，发一个空的 `OneDay-App-Id` 没有意义。
//!
//! ── 两个开关 ────────────────────────────────────────────────
//! - `MEOO_CLI_VERSION`：覆盖上报的 CLI 版本（非 ASCII / 超长一律忽略）
//! - `MEOO_CLI_HEADERS=0`：整组 `X-Meoo-*` 不发（排查「是不是头导致的问题」用）
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

// ── 为什么整份 `allow(dead_code)` ───────────────────────────
// 本模块是「Meoo 请求头」的唯一入口，先于各条链路（OAuth / 控制面 / 目录 /
// 对话 / 积分）落地，因此此刻部分构造函数还没有调用方。它们正是为了
// **避免各链路各自手拼** `X-Meoo-*` 才存在，不能因为暂时没人用就删掉。
#![allow(dead_code)]

use std::sync::OnceLock;

use super::endpoints::DEFAULT_CLI_VERSION;

/// 上报的 CLI 版本：`MEOO_CLI_VERSION` 可覆盖，非法值忽略；进程内只解析一次
pub fn cli_version() -> String {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            std::env::var("MEOO_CLI_VERSION")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty() && value.len() <= 32 && value.is_ascii())
                .unwrap_or_else(|| DEFAULT_CLI_VERSION.to_string())
        })
        .clone()
}

/// 是否发送 `X-Meoo-*` 头（`MEOO_CLI_HEADERS=0|false|off` 关闭）
pub fn cli_headers_enabled() -> bool {
    !matches!(
        std::env::var("MEOO_CLI_HEADERS").ok().as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

/// 新的请求 id：`cli_req_<uuid v4>`
pub fn request_id() -> String {
    request_id_with(&crate::ids::uuid_v4())
}

/// 用给定 uuid 拼请求 id（单测注入固定 uuid 用）
pub fn request_id_with(uuid: &str) -> String {
    format!("cli_req_{uuid}")
}

/// 三条 CLI 头（给定版本与请求 id，单测可注入）
pub fn cli_headers_with(version: &str, request_id: &str) -> Vec<(String, String)> {
    vec![
        ("X-Meoo-Client".to_string(), "cli".to_string()),
        ("X-Meoo-CLI-Version".to_string(), version.to_string()),
        ("X-Meoo-Request-Id".to_string(), request_id.to_string()),
    ]
}

/// 三条 CLI 头（真实版本与每请求唯一的 id）；开关关闭时为空
pub fn cli_headers() -> Vec<(String, String)> {
    if !cli_headers_enabled() {
        return Vec::new();
    }
    cli_headers_with(&cli_version(), &request_id())
}

/// 控制面请求头：`Bearer <OAuth access_token>` + CLI 头
pub fn control_headers(access_token: &str) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "application/json".to_string()),
        (
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        ),
    ];
    headers.extend(cli_headers());
    headers
}

/// 模型网关请求头：`Bearer <项目服务 AK>` + CLI 头 + 可选 `OneDay-App-Id`
///
/// `stream` 决定 `Accept`：SSE 要显式声明 `text/event-stream`，非流式只要
/// `application/json`。
pub fn gateway_headers(service_ak: &str, project: &str, stream: bool) -> Vec<(String, String)> {
    gateway_headers_with(service_ak, project, stream, &cli_version(), &request_id())
}

/// [`gateway_headers`] 的可注入版本（单测用固定版本 / 请求 id）
pub fn gateway_headers_with(
    service_ak: &str,
    project: &str,
    stream: bool,
    version: &str,
    request_id: &str,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Accept".to_string(),
            if stream {
                "text/event-stream, application/json".to_string()
            } else {
                "application/json".to_string()
            },
        ),
        ("Authorization".to_string(), format!("Bearer {service_ak}")),
    ];
    if cli_headers_enabled() {
        headers.extend(cli_headers_with(version, request_id));
    }
    if !project.trim().is_empty() {
        headers.push(("OneDay-App-Id".to_string(), project.trim().to_string()));
    }
    headers
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cli_headers_match_official_cli() {
        let headers = cli_headers_with("0.5.6", "cli_req_test");
        assert!(headers.contains(&("X-Meoo-Client".into(), "cli".into())));
        assert!(headers.contains(&("X-Meoo-CLI-Version".into(), "0.5.6".into())));
        assert!(headers.contains(&("X-Meoo-Request-Id".into(), "cli_req_test".into())));
    }

    #[test]
    fn control_headers_carry_cli_and_bearer() {
        let headers = control_headers("token");
        // 控制面必须带全 CLI 三件套 + Bearer + JSON 声明
        assert!(headers.contains(&("X-Meoo-Client".into(), "cli".into())));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "X-Meoo-CLI-Version" && !value.trim().is_empty()));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "X-Meoo-Request-Id" && value.starts_with("cli_req_")));
        assert!(headers.contains(&("Authorization".into(), "Bearer token".into())));
        assert!(headers.contains(&("Content-Type".into(), "application/json".into())));
    }

    #[test]
    fn gateway_headers_include_cli_and_bearer() {
        let headers = gateway_headers_with(
            "meoo_project_service_v1.x",
            "proj_1",
            true,
            "0.5.6",
            "cli_req_x",
        );
        assert!(headers.contains(&(
            "Authorization".into(),
            "Bearer meoo_project_service_v1.x".into()
        )));
        assert!(headers.contains(&(
            "Accept".into(),
            "text/event-stream, application/json".into()
        )));
        assert!(headers.contains(&("X-Meoo-Client".into(), "cli".into())));
        assert!(headers.contains(&("OneDay-App-Id".into(), "proj_1".into())));
    }

    #[test]
    fn request_id_is_unique_and_prefixed() {
        let a = request_id_with("00000000-0000-4000-8000-000000000001");
        let b = request_id_with("00000000-0000-4000-8000-000000000002");
        assert!(a.starts_with("cli_req_"));
        assert_ne!(a, b);
    }
}
