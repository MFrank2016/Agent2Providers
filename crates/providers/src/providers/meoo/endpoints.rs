//! Meoo 端点、client ID、CLI 版本常量 —— 所有 Meoo 请求地址的唯一出处。
//!
//! ── 两条完全不同的链路 ──────────────────────────────────────
//!
//! ```text
//!   控制面（OAuth / 身份 / 项目 / 积分）  https://meoo.com
//!   模型网关（OpenAI 兼容 / 对话 / 目录）  https://api.meoo.host/meoo-ai/compatible-mode/v1
//! ```
//!
//! 控制面走 **OAuth access token**，网关走**项目服务 AK**（`meoo_project_service_v1.*`）；
//! 两者的 Bearer 由 `headers.rs` 分别构造，本文件只管地址。
//!
//! ── client ID 由 host 决定，不是配置项 ────────────────────────
//! 官方 CLI 只在两个正式 host 上用生产 client ID，其余（本地联调 / 灰度以外的
//! 域名）用测试 client ID。写成「按 host 选」而不是环境变量，是为了让
//! `MEOO_API_BASE` 指到测试环境时 client ID 自动跟着换 —— 两者不匹配时
//! 授权与换码都会被拒。
//!
//! ── 基址覆盖必须过 host 白名单 ────────────────────────────────
//! `MEOO_API_BASE` / `MEOO_GATEWAY_BASE` 只接受正式 host，且**非 loopback 必须是
//! `https`**（OAuth code / token 不能明文出网）；填错域名 / 协议时**回落到
//! 默认值**而不是照单全收，避免一个手滑的环境变量把 OAuth token 发到陌生主机。
//! 单测要打本地假服务器时设 `MEOO_ALLOW_INSECURE_BASE=1` 放行 loopback ——
//! 这是唯一的例外，只放行 `127.0.0.1` / `localhost`，且允许其用 `http`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

// ── 为什么整份 `allow(dead_code)` ───────────────────────────
// 这份常量表是**后续接入（OAuth / 控制面 / 目录 / 对话 / 积分）的公共入口**，
// 按「先定地址、再接链路」的顺序落地，所以此刻调用方还没接上。删掉未用项
// 等于每接一条链路都要把地址重写一遍 —— 而地址恰恰是最不该分散在多处的
// 东西。故保留，只关掉未使用告警。
#![allow(dead_code)]

/// 控制面（OAuth / 身份 / 项目 / 积分）默认基址
pub const DEFAULT_API_BASE: &str = "https://meoo.com";

/// 模型网关（OpenAI 兼容）默认基址，**含** `/v1` 后缀
pub const DEFAULT_GATEWAY_BASE: &str = "https://api.meoo.host/meoo-ai/compatible-mode/v1";

/// 冒充官方 CLI 时上报的版本号（`MEOO_CLI_VERSION` 可覆盖）
pub const DEFAULT_CLI_VERSION: &str = "0.5.6";

/// OAuth 授权 scope（官方 CLI 只申请这一个）
pub const OAUTH_SCOPE: &str = "cli.compat";

/// loopback 回调路径
pub const CALLBACK_PATH: &str = "/oauth/callback";

/// 正式环境的 OAuth client ID
pub const PROD_CLIENT_ID: &str = "meoo_app_tdWlRbpvAxN1EjmZ8XICxdTh";

/// 测试 / 联调环境的 OAuth client ID
pub const TEST_CLIENT_ID: &str = "meoo_app_SFNvmHUFNePxyyfGjCd9hyaE";

/// 正式环境 hostname（与官方 CLI 逐字一致）
const PROD_HOSTS: &[&str] = &["meoo.com", "gray-meoo.aliyun-inc.com"];

/// 解析 URL，返回（scheme 小写，hostname 小写）。解析失败或无 host 时返回 `None`。
fn scheme_and_host(value: &str) -> Option<(String, String)> {
    let url = url::Url::parse(value).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    Some((url.scheme().to_ascii_lowercase(), host))
}

/// 取 URL 的 hostname（小写）。解析失败或无 host 时返回 `None`。
fn host_of(value: &str) -> Option<String> {
    scheme_and_host(value).map(|(_, host)| host)
}

/// 非回环基址是否走了加密传输。
///
/// 只查 host 不查 scheme 会让 `http://meoo.com` 过关 —— OAuth code 与 token
/// 都会明文出网，所以正式域名**必须** https。loopback 例外见
/// [`loopback_allowed`]。
fn is_https(value: &str) -> bool {
    scheme_and_host(value).is_some_and(|(scheme, _)| scheme == "https")
}

/// 单测打本地假服务器时是否放行 loopback 基址（`MEOO_ALLOW_INSECURE_BASE=1`）
fn insecure_test_base_allowed() -> bool {
    matches!(
        std::env::var("MEOO_ALLOW_INSECURE_BASE").ok().as_deref(),
        Some("1") | Some("true")
    )
}

/// loopback 且显式放行时才允许（此时允许 http：本机回环不出网）
fn loopback_allowed(value: &str) -> bool {
    insecure_test_base_allowed()
        && host_of(value)
            .as_deref()
            .is_some_and(|host| host == "127.0.0.1" || host == "localhost")
}

/// `MEOO_API_BASE` 是否可接受：https 的正式 host，或显式放行的 loopback
fn allowed_api_base(value: &str) -> bool {
    (is_https(value)
        && host_of(value)
            .as_deref()
            .is_some_and(|host| PROD_HOSTS.contains(&host)))
        || loopback_allowed(value)
}

/// `MEOO_GATEWAY_BASE` 是否可接受：https 的 `api.meoo.host`，或显式放行的 loopback
fn allowed_gateway_base(value: &str) -> bool {
    (is_https(value) && host_of(value).as_deref() == Some("api.meoo.host"))
        || loopback_allowed(value)
}

/// 读环境变量覆盖（空值视为未设置），去掉首尾空白与尾部斜杠
fn env_base(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
}

/// 控制面基址：`MEOO_API_BASE` 可覆盖，但必须过 host 白名单
pub fn api_base() -> String {
    match env_base("MEOO_API_BASE") {
        Some(value) if allowed_api_base(&value) => value,
        _ => DEFAULT_API_BASE.to_string(),
    }
}

/// 模型网关基址：`MEOO_GATEWAY_BASE` 可覆盖，但必须过 host 白名单
pub fn gateway_base() -> String {
    match env_base("MEOO_GATEWAY_BASE") {
        Some(value) if allowed_gateway_base(&value) => value,
        _ => DEFAULT_GATEWAY_BASE.to_string(),
    }
}

/// 按控制面 host 选 OAuth client ID（正式 host → 生产 ID，其余 → 测试 ID）
pub fn client_id(api_base: &str) -> &'static str {
    let host = host_of(api_base).unwrap_or_default();
    if PROD_HOSTS.contains(&host.as_str()) {
        PROD_CLIENT_ID
    } else {
        TEST_CLIENT_ID
    }
}

/// 授权页 URL（PKCE S256；`redirect_uri` / `state` / `challenge` 由调用方生成）
///
/// 拼不出来时回落到正式环境的裸授权地址 —— 这里不能用 expect/unwrap
/// （release 是 `panic=abort`）。
pub fn authorize_url(api_base: &str, redirect_uri: &str, state: &str, challenge: &str) -> String {
    let Ok(mut url) = url::Url::parse(&format!(
        "{}/oauth/authorize",
        api_base.trim_end_matches('/')
    )) else {
        return format!("{DEFAULT_API_BASE}/oauth/authorize");
    };
    url.query_pairs_mut()
        .append_pair("client_id", client_id(api_base))
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", OAUTH_SCOPE)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    url.to_string()
}

/// 授权码换令牌
pub fn token_url(api_base: &str) -> String {
    format!("{}/oauth/token", api_base.trim_end_matches('/'))
}

/// 控制面身份
pub fn identity_url(api_base: &str) -> String {
    format!(
        "{}/open/v1/cli-compat/account/identity",
        api_base.trim_end_matches('/')
    )
}

/// 项目列表（一页 50 条，够用且与官方 CLI 同形）
pub fn projects_url(api_base: &str) -> String {
    format!(
        "{}/open/v1/cli-compat/projects?page_size=50",
        api_base.trim_end_matches('/')
    )
}

/// 项目云环境（解析项目服务 AK 的地方）
pub fn environment_url(api_base: &str, project: &str) -> String {
    format!(
        "{}/open/v1/cli-compat/projects/{}/cloud/environment",
        api_base.trim_end_matches('/'),
        project
    )
}

/// 项目云资源
pub fn cloud_url(api_base: &str, project: &str) -> String {
    format!(
        "{}/open/v1/cli-compat/projects/{}/cloud",
        api_base.trim_end_matches('/'),
        project
    )
}

/// 积分余额
pub fn points_url(api_base: &str) -> String {
    format!(
        "{}/open/v1/cli-compat/account/points",
        api_base.trim_end_matches('/')
    )
}

/// 账号权益
pub fn entitlement_url(api_base: &str) -> String {
    format!(
        "{}/open/v1/cli-compat/account/entitlement",
        api_base.trim_end_matches('/')
    )
}

/// 模型目录
pub fn models_url(gateway_base: &str) -> String {
    format!("{}/models", gateway_base.trim_end_matches('/'))
}

/// 对话（OpenAI 兼容）
pub fn chat_url(gateway_base: &str) -> String {
    format!("{}/chat/completions", gateway_base.trim_end_matches('/'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn production_host_uses_production_client_id() {
        assert_eq!(client_id("https://meoo.com"), PROD_CLIENT_ID);
        assert_eq!(
            client_id("https://gray-meoo.aliyun-inc.com"),
            PROD_CLIENT_ID
        );
    }

    #[test]
    fn other_host_uses_test_client_id() {
        assert_eq!(client_id("https://example.com"), TEST_CLIENT_ID);
    }

    #[test]
    fn env_base_allowlist_rejects_unknown_hosts() {
        assert!(allowed_api_base("https://meoo.com"));
        assert!(!allowed_api_base("https://evil.example"));
        assert!(allowed_gateway_base(
            "https://api.meoo.host/meoo-ai/compatible-mode/v1"
        ));
        assert!(!allowed_gateway_base("https://evil.example/meoo-ai"));
    }

    #[test]
    fn plaintext_base_is_rejected_outside_loopback() {
        // 非回环基址必须是 https：OAuth code / token 不能明文出网
        assert!(!allowed_api_base("http://meoo.com"));
        assert!(!allowed_api_base("http://gray-meoo.aliyun-inc.com"));
        assert!(!allowed_gateway_base(
            "http://api.meoo.host/meoo-ai/compatible-mode/v1"
        ));
        // 同 host 的 https 仍然放行
        assert!(allowed_api_base("https://meoo.com"));
        assert!(allowed_gateway_base(
            "https://api.meoo.host/meoo-ai/compatible-mode/v1"
        ));
    }
}
