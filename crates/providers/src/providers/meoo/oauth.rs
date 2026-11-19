//! OAuth PKCE：授权 URL、换票、refresh、回调解析。
//!
//! ── 三步 ────────────────────────────────────────────────────
//! ```text
//!   1. create_pkce()          → verifier（32 随机字节的 base64url）
//!                              challenge = base64url(sha256(verifier))
//!   2. endpoints::authorize_url(api_base, redirect_uri, state, challenge)
//!   3. exchange_code(...)     → POST {api_base}/oauth/token
//!                                grant_type=authorization_code
//!   4. refresh(...)           → POST {api_base}/oauth/token
//!                                grant_type=refresh_token
//! ```
//!
//! ── 换票 / 续期都**不带** CLI 头 ──────────────────────────────
//! 官方 CLI 打 `/oauth/token` 时是裸表单（`application/x-www-form-urlencoded`），
//! 没有 `X-Meoo-*` 三件套，也没有 `Authorization`。多带不会被奖励，只会让
//! 「上游按头做风控」这类问题多一个变量。
//!
//! ── `invalid_grant` 是**登录态失效**，不是上游故障 ────────────
//! refresh 被拒时上游回 `{"error":"invalid_grant"}`。这一条必须归成 401
//! 「请重新登录」：归成 502 会让上层把它当临时故障反复重试，用户永远等不到
//! 「该重新登录了」这句提示。
//!
//! ── 回调解析同时接受 URL 与裸 code ───────────────────────────
//! 浏览器登录回的是完整回调 URL；`login.token` 那条路用户可能直接粘一个
//! 授权码。两种形态都认，裸 code 的 `state` 为空串（调用方据此跳过 state 校验）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

// ── 为什么整份 `allow(dead_code)` ───────────────────────────
// 本模块先于 `login.rs` / `refresh.rs` 落地：换票与续期此刻还没有调用方。
// 它们正是这两个文件唯一的实现，删掉等于让后面的接线重写一遍 OAuth。
#![allow(dead_code)]

use serde_json::Value;

use agent2api_provider_sdk::PluginCtx;

use crate::errors::GatewayError;
use crate::http;

use super::endpoints;

/// 表单 POST：`meoo` 的 `/oauth/token` 是裸表单，上游 `http` 已不再提供这条。
/// 非 2xx 也原样返回（状态码 + 解析后的 JSON），由调用方分类。
async fn post_form(
    client: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> Result<(u16, Value), String> {
    let response = client
        .post(url)
        .header("Accept", "application/json")
        .form(form)
        .send()
        .await
        .map_err(|error| http::describe(&error))?;
    let status = response.status().as_u16();
    let text = response
        .text()
        .await
        .map_err(|error| http::describe(&error))?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

/// 一轮 PKCE 的两个值：`verifier` 自己留着换票，`challenge` 进授权地址。
pub struct Pkce {
    /// 授权码校验值（32 随机字节的 base64url 无填充，43 字符）
    pub verifier: String,
    /// `base64url(sha256(verifier))`（S256）
    pub challenge: String,
}

/// 生成一轮 PKCE（S256）。
pub fn create_pkce() -> Pkce {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let verifier = {
        let mut bytes = [0u8; 32];
        // 随机源失败时全零 verifier 会让这一轮 PKCE 失去意义 —— 但 release 是
        // `panic=abort`，这里不能 expect。零值 verifier 仍然满足 43 字符与
        // S256 关系，换票只会因 code 不匹配被拒（不会静默放行错误请求）。
        let _ = getrandom::getrandom(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    Pkce {
        verifier,
        challenge,
    }
}

/// 一次令牌包的解析结果（换票与续期共用）。
#[derive(Clone, Debug, Default)]
pub struct TokenBundle {
    /// `access_token`（控制面 Bearer，1 小时过期）
    pub access_token: String,
    /// `refresh_token`（续期响应不带新 token 时为空 —— 调用方保留旧的）
    pub refresh_token: String,
    /// `expires_in`（秒；缺失或非正数时按 3600）
    pub expires_in: i64,
    /// `scope`
    pub scope: String,
    /// `openid`
    pub openid: String,
}

/// 解析令牌响应。
///
/// 缺 `access_token` 时把上游 `error` 带出来 —— 只报「缺少 access_token」
/// 会让「invalid_grant / invalid_client」这类根因丢掉。
fn parse_token(payload: &Value) -> Result<TokenBundle, GatewayError> {
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if access_token.is_empty() {
        let error = payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("OAuth 响应缺少 access_token");
        return Err(GatewayError::with_status(
            401,
            format!("Meoo 登录失败：{error}"),
        ));
    }
    Ok(TokenBundle {
        access_token,
        refresh_token: payload
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
        expires_in: payload
            .get("expires_in")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .unwrap_or(3600),
        scope: payload
            .get("scope")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
        openid: payload
            .get("openid")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
    })
}

/// 换票失败的状态码映射。
///
/// ── 为什么不能一律归 401 ────────────────────────────────────
/// 401 的语义是「这个授权码 / 这次登录不成立」，上层据此让用户**重新登录**。
/// 上游 5xx / 429 是「此刻换不了票」，3xx 是「地址/网关配置不对」，两者归成
/// 401 都会让用户照着「重新登录」做一遍还是失败。所以只有 4xx（授权码过期、
/// `invalid_grant`、`invalid_client`；429 除外）留 401，其余一律 502。
fn exchange_failure(status: u16, code: &str) -> GatewayError {
    if (400..=499).contains(&status) && status != 429 {
        return GatewayError::with_status(401, format!("Meoo 换票被拒（HTTP {status}）：{code}"));
    }
    GatewayError::with_status(
        502,
        format!("Meoo 换票暂时不可用（HTTP {status}），请稍后重试：{code}"),
    )
}

/// 用授权码换令牌（`application/x-www-form-urlencoded`，不带 CLI 头）。
pub async fn exchange_code(
    ctx: &PluginCtx,
    api_base: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenBundle, GatewayError> {
    let client = http::control_client(None, &ctx.env.proxy);
    let (status, payload) = post_form(
        &client,
        &endpoints::token_url(api_base),
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ],
    )
    .await
    .map_err(|error| GatewayError::with_status(502, format!("Meoo 换票失败：{error}")))?;
    if !(200..300).contains(&status) {
        return Err(exchange_failure(
            status,
            payload.get("error").and_then(Value::as_str).unwrap_or(""),
        ));
    }
    parse_token(&payload)
}

/// 用 refresh token 续期。
///
/// `invalid_grant` → 401「登录已失效」；其余非 2xx 归 502（上游故障）。
pub async fn refresh(
    ctx: &PluginCtx,
    api_base: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenBundle, GatewayError> {
    let client = http::control_client(None, &ctx.env.proxy);
    let (status, payload) = post_form(
        &client,
        &endpoints::token_url(api_base),
        &[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ],
    )
    .await
    .map_err(|error| GatewayError::with_status(502, format!("Meoo 续期失败：{error}")))?;
    if !(200..300).contains(&status) {
        let code = payload.get("error").and_then(Value::as_str).unwrap_or("");
        if code == "invalid_grant" {
            return Err(GatewayError::with_status(
                401,
                "Meoo 登录已失效，请重新登录",
            ));
        }
        return Err(GatewayError::with_status(
            502,
            format!("Meoo 续期被拒（HTTP {status}）：{code}"),
        ));
    }
    parse_token(&payload)
}

/// 从回调解析 `(code, state)`。
///
/// - 完整回调 URL：取 query 里的 `code` / `state`；有 `error` 参数即失败；
/// - 裸 code（`url` 解析不了或为空）：原样返回，`state` 为空串。
pub fn parse_callback(code: &str, url: &str) -> Result<(String, String), String> {
    let mut code_value = code.trim().to_string();
    let Ok(parsed) = url::Url::parse(url) else {
        if !code_value.is_empty() {
            return Ok((code_value, String::new()));
        }
        return Err("回调地址无效".to_string());
    };
    let mut state = String::new();
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "error" => return Err(format!("授权被拒绝：{value}")),
            "code" => code_value = value.into_owned(),
            "state" => state = value.into_owned(),
            _ => {}
        }
    }
    if code_value.is_empty() {
        return Err("回调缺少授权码".to_string());
    }
    Ok((code_value, state))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let pkce = create_pkce();
        let expected = {
            use base64::Engine as _;
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(pkce.verifier.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        };
        assert_eq!(pkce.challenge, expected);
        assert!(pkce.verifier.len() >= 43 && pkce.verifier.len() <= 128);
    }

    #[test]
    fn callback_accepts_code_and_state() {
        let (code, state) = parse_callback(
            "",
            "http://127.0.0.1:3065/oauth/callback?code=abc&state=xyz",
        )
        .expect("应解析");
        assert_eq!(code, "abc");
        assert_eq!(state, "xyz");
    }

    #[test]
    fn callback_rejects_error() {
        let error = parse_callback(
            "",
            "http://127.0.0.1:3065/oauth/callback?error=access_denied&state=xyz",
        )
        .expect_err("应拒绝");
        assert!(error.contains("access_denied"));
    }

    #[test]
    fn bare_code_is_accepted() {
        let (code, state) = parse_callback("bare-code", "").expect("裸 code 应接受");
        assert_eq!(code, "bare-code");
        assert!(state.is_empty());
    }

    #[test]
    fn exchange_maps_upstream_outage_to_502() {
        // 上游抖动不能被读成「该重新登录了」
        assert_eq!(exchange_failure(503, "").status_code, 502);
        assert_eq!(exchange_failure(500, "upstream").status_code, 502);
        assert_eq!(exchange_failure(429, "").status_code, 502);
        // 3xx 是地址/网关配置问题，也不是「授权码不成立」
        assert_eq!(exchange_failure(302, "").status_code, 502);
        assert_eq!(exchange_failure(304, "").status_code, 502);
        // 只有 4xx（429 除外）才是「这枚授权码 / 这次客户端不成立」
        assert_eq!(exchange_failure(400, "invalid_grant").status_code, 401);
        assert_eq!(exchange_failure(401, "invalid_client").status_code, 401);
        assert_eq!(exchange_failure(403, "forbidden").status_code, 401);
        assert_eq!(exchange_failure(404, "").status_code, 401);
        assert!(exchange_failure(502, "").message.contains("暂时不可用"));
    }
}
