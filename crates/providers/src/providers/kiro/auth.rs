//! Kiro 凭证：API Key 解析、鉴权头、Builder ID 设备授权登录、续期。
//!
//! ── 两种凭证形态 ────────────────────────────────────────────
//! `ApiKey`（`ksk_…`）：不续期、不需要 profileArn、走 `runtime.{region}.kiro.dev`。
//! `OAuth`：access/refresh token，走 `q.{region}` 或 `codewhisperer.{region}`，
//! 登录见 [`register_client`] → [`start_device`] → [`poll_device`]，续期见
//! [`refresh`]。
//!
//! ── 为什么 API Key 也要记 region ─────────────────────────────
//! `runtime.{region}.kiro.dev` 的 region 是数据面，不是鉴权面；用户粘贴的
//! `ksk_…|eu-west-1` 后半段就是它。缺省 `us-east-1`。
//!
//! ── 设备授权的四步（AWS OIDC，RFC 8628）─────────────────────
//! ```text
//!   ① POST {oidc}/client/register       → clientId + clientSecret
//!   ② POST {oidc}/device_authorization  → deviceCode + verificationUri(+interval)
//!   ③ 用户在浏览器里确认                （网关打开 verificationUri）
//!   ④ POST {oidc}/token (device_code)   → accessToken + refreshToken（轮询）
//! ```
//! 第 ① 步每个流程做一次就够：clientId / clientSecret 与用户身份无关，但
//! **续期要用同一个**，所以 `mod.rs` 把三个值一起存进流程状态。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use serde_json::Value;

use super::endpoints::DEFAULT_REGION;

/// 协议常量：不点名官方 IDE 的 UA 会被拒（spec 第 1 节）。
pub const KIRO_USER_AGENT: &str = "aws-sdk-js/3.738.0 KiroIDE";

/// 凭证种类。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialKind {
    ApiKey,
    OAuth,
}

/// 一份 Kiro 凭证。
#[derive(Clone, Debug)]
pub struct KiroCredential {
    /// 真正放进 `Authorization: Bearer` 的令牌。
    pub access_token: String,
    /// API Key 本体（`CredentialKind::ApiKey` 时与 `access_token` 相同；
    /// OAuth 时为空串）。
    pub api_key: String,
    /// OAuth refresh token（`CredentialKind::OAuth` 时才有）。
    pub refresh_token: Option<String>,
    /// 数据面 region。
    pub region: String,
    /// 凭证种类。
    pub kind: CredentialKind,
}

/// 解析用户粘贴的 API Key（`ksk_…` 或 `ksk_…|region`）。
pub fn parse_api_key(raw: &str) -> Result<KiroCredential, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Kiro API Key 不能为空".to_string());
    }
    let (key, region) = match trimmed.split_once('|') {
        Some((key, region)) => (key.trim(), region.trim()),
        None => (trimmed, ""),
    };
    if key.is_empty() {
        return Err("Kiro API Key 不能为空".to_string());
    }
    if !key.starts_with("ksk_") {
        return Err("Kiro API Key 应以 `ksk_` 开头".to_string());
    }
    Ok(KiroCredential {
        access_token: key.to_string(),
        api_key: key.to_string(),
        refresh_token: None,
        region: if region.is_empty() {
            DEFAULT_REGION.to_string()
        } else {
            region.to_string()
        },
        kind: CredentialKind::ApiKey,
    })
}

/// 鉴权与身份头（不含 `content-type` / `accept`，那两个由调用方按用途给）。
pub fn auth_headers(cred: &KiroCredential) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "authorization".to_string(),
            format!("Bearer {}", cred.access_token),
        ),
        ("user-agent".to_string(), KIRO_USER_AGENT.to_string()),
        ("x-amz-user-agent".to_string(), KIRO_USER_AGENT.to_string()),
        ("x-amzn-kiro-agent-mode".to_string(), "vibe".to_string()),
    ];
    match cred.kind {
        CredentialKind::ApiKey => {
            headers.push(("tokentype".to_string(), "API_KEY".to_string()));
            headers.push((
                "x-amz-target".to_string(),
                "AmazonCodeWhispererStreamingService.GenerateAssistantResponse".to_string(),
            ));
            headers.push(("origin".to_string(), "KIRO_CLI".to_string()));
        }
        CredentialKind::OAuth => {}
    }
    headers
}

/// 账号稳定身份：由凭证派生，**不含密钥本体**。
///
/// ── OAuth 为什么用 refresh token 算 ──────────────────────────
/// access token 每次续期都会换，拿它算身份会让同一个账号在续期后变成
/// 「另一个账号」（去重失效、列表里出现两条）。refresh token 是这一份
/// 授权里稳定的那一段；它自己也会轮换，但频率远低于 access token。
pub fn identity_of(cred: &KiroCredential) -> String {
    let (prefix, material) = match cred.kind {
        CredentialKind::ApiKey => ("kiro-api-", cred.access_token.as_str()),
        CredentialKind::OAuth => (
            "kiro-oauth-",
            cred.refresh_token
                .as_deref()
                .filter(|token| !token.is_empty())
                .unwrap_or(cred.access_token.as_str()),
        ),
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in material.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{prefix}{hash:016x}")
}

// ─── OAuth：Builder ID 设备授权 + 续期 ────────────────────────

/// OIDC 基址。
pub fn oidc_base(region: &str) -> String {
    format!("https://oidc.{region}.amazonaws.com")
}

/// 注册 OIDC 客户端（device code 流程第一步）。
pub async fn register_client(
    client: &reqwest::Client,
    region: &str,
) -> Result<(String, String), String> {
    let url = format!("{}/client/register", oidc_base(region));
    let body = serde_json::json!({
        "clientName": "Kiro",
        "clientType": "public",
        "scopes": ["codewhisperer:completions", "codewhisperer:analysis"],
        "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
        "issuerUrl": "https://view.awsapps.com/start"
    });
    let (status, payload) = crate::http::post_json(client, &url, &[], &body).await?;
    if !(200..300).contains(&status) {
        return Err(format!("Kiro 客户端注册失败：HTTP {status} {}", head_of(&payload)));
    }
    let client_id = payload.get("clientId").and_then(|v| v.as_str()).unwrap_or("");
    let client_secret = payload.get("clientSecret").and_then(|v| v.as_str()).unwrap_or("");
    if client_id.is_empty() || client_secret.is_empty() {
        return Err("Kiro 客户端注册响应缺少 clientId / clientSecret".to_string());
    }
    Ok((client_id.to_string(), client_secret.to_string()))
}

/// 发起设备授权，返回 `(deviceCode, verificationUri, interval_ms)`。
pub async fn start_device(
    client: &reqwest::Client,
    region: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<(String, String, u64), String> {
    let url = format!("{}/device_authorization", oidc_base(region));
    let body = serde_json::json!({
        "clientId": client_id,
        "clientSecret": client_secret,
        "startUrl": "https://view.awsapps.com/start"
    });
    let (status, payload) = crate::http::post_json(client, &url, &[], &body).await?;
    if !(200..300).contains(&status) {
        return Err(format!("Kiro 设备授权失败：HTTP {status} {}", head_of(&payload)));
    }
    let device_code = payload
        .get("deviceCode")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let verification_uri = payload
        .get("verificationUriComplete")
        .or_else(|| payload.get("verificationUri"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // AWS 给的是**秒**；协议里要毫秒。缺失时按 RFC 8628 的建议 5 秒。
    let interval = payload.get("interval").and_then(|v| v.as_u64()).unwrap_or(5) * 1000;
    if device_code.is_empty() || verification_uri.is_empty() {
        return Err("Kiro 设备授权响应缺少 deviceCode / verificationUri".to_string());
    }
    Ok((device_code, verification_uri, interval))
}

/// 轮询 `/token`；`Ok(None)` = 还在等用户授权。
pub async fn poll_device(
    client: &reqwest::Client,
    region: &str,
    client_id: &str,
    client_secret: &str,
    device_code: &str,
) -> Result<Option<KiroCredential>, String> {
    let url = format!("{}/token", oidc_base(region));
    let form = [
        ("clientId", client_id),
        ("clientSecret", client_secret),
        ("deviceCode", device_code),
        ("grantType", "urn:ietf:params:oauth:grant-type:device_code"),
    ];
    let (status, payload) = crate::http::post_form(client, &url, &form).await?;
    if (200..300).contains(&status) {
        let access = payload.get("accessToken").and_then(|v| v.as_str()).unwrap_or("");
        let refresh = payload.get("refreshToken").and_then(|v| v.as_str()).unwrap_or("");
        if access.is_empty() {
            return Err("Kiro 授权成功但没拿到 accessToken".to_string());
        }
        return Ok(Some(KiroCredential {
            access_token: access.to_string(),
            api_key: String::new(),
            refresh_token: (!refresh.is_empty()).then(|| refresh.to_string()),
            region: region.to_string(),
            kind: CredentialKind::OAuth,
        }));
    }
    let error = payload.get("error").and_then(|v| v.as_str()).unwrap_or("");
    // `slow_down` 不失败：上游只是要求放慢，下一轮照常问（间隔由网关按
    // `poll_interval_ms` 决定，插件侧没有跨调用的可变状态 —— 与 Cline 同一降级）。
    if matches!(error, "authorization_pending" | "slow_down") {
        return Ok(None);
    }
    Err(format!("Kiro 授权失败：{error}"))
}

/// 用 refresh token 换新 access token。
///
/// ── 为什么手拼表单体（而不是用 `http::post_form`）───────────
/// 这里要复用调用方给的 client（登录 / 续期共用一份出口），并且要把
/// [`urlencode`] 的编码结果原样发出去；`post_form` 走 `reqwest` 的 `.form()`
/// 编码，重复编码会让 refresh token 里的 `+` `/` `=` 变形。
pub async fn refresh(
    client: &reqwest::Client,
    cred: &KiroCredential,
) -> Result<KiroCredential, String> {
    let Some(refresh_token) = cred.refresh_token.as_deref() else {
        return Err("这个 Kiro 账号没有 refresh token，无法续期".to_string());
    };
    let url = format!("{}/token", oidc_base(&cred.region));
    let form = [
        ("clientId", "kiro"),
        ("grantType", "refresh_token"),
        ("refreshToken", refresh_token),
    ];
    let body: String = form
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let response = client
        .post(&url)
        .header("Accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|error| crate::http::describe(&error))?;
    let status = response.status().as_u16();
    let text = response.text().await.map_err(|error| crate::http::describe(&error))?;
    let payload: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(format!("Kiro 续期失败：HTTP {status} {}", head_of(&payload)));
    }
    let access = payload.get("accessToken").and_then(|v| v.as_str()).unwrap_or("");
    if access.is_empty() {
        return Err("Kiro 续期响应里没有 accessToken".to_string());
    }
    Ok(KiroCredential {
        access_token: access.to_string(),
        api_key: String::new(),
        // 上游通常会轮换 refresh token；没给就沿用旧的。
        refresh_token: payload
            .get("refreshToken")
            .and_then(|v| v.as_str())
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .or_else(|| cred.refresh_token.clone()),
        region: cred.region.clone(),
        kind: CredentialKind::OAuth,
    })
}

/// 最小表单编码（`application/x-www-form-urlencoded` 的 unreserved 集合）。
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

/// 错误体前 240 字符（`post_json` / `post_form` 已把空体归成 `Null`）。
fn head_of(payload: &Value) -> String {
    payload.to_string().chars().take(240).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_api_key_with_default_region() {
        let cred = parse_api_key("ksk_abc123").expect("应能解析");
        assert_eq!(cred.api_key, "ksk_abc123");
        assert_eq!(cred.region, "us-east-1");
    }

    #[test]
    fn parses_api_key_with_region_suffix() {
        let cred = parse_api_key("ksk_abc123|eu-west-1").expect("应能解析");
        assert_eq!(cred.api_key, "ksk_abc123");
        assert_eq!(cred.region, "eu-west-1");
    }

    #[test]
    fn rejects_empty_key() {
        assert!(parse_api_key("   ").is_err());
    }

    #[test]
    fn rejects_non_ksk_prefix() {
        assert!(parse_api_key("sk-other").is_err());
    }

    #[test]
    fn api_key_headers_carry_token_type_and_ua() {
        let cred = parse_api_key("ksk_abc").expect("应能解析");
        let headers = auth_headers(&cred);
        let find = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(find("tokentype"), Some("API_KEY"));
        assert_eq!(find("user-agent"), Some(KIRO_USER_AGENT));
        assert_eq!(find("authorization"), Some("Bearer ksk_abc"));
    }

    #[test]
    fn identity_is_stable_and_does_not_leak_the_key() {
        let cred = parse_api_key("ksk_abc").expect("应能解析");
        let identity = identity_of(&cred);
        assert!(identity.starts_with("kiro-api-"));
        assert!(!identity.contains("ksk_abc"));
        assert_eq!(
            identity,
            identity_of(&parse_api_key("ksk_abc").expect("应能解析"))
        );
    }

    fn oauth(access: &str, refresh: Option<&str>) -> KiroCredential {
        KiroCredential {
            access_token: access.to_string(),
            api_key: String::new(),
            refresh_token: refresh.map(str::to_string),
            region: "us-east-1".to_string(),
            kind: CredentialKind::OAuth,
        }
    }

    #[test]
    fn oauth_credential_uses_q_endpoint() {
        let cred = KiroCredential {
            access_token: "at".into(),
            api_key: String::new(),
            refresh_token: Some("rt".into()),
            region: "us-east-1".into(),
            kind: CredentialKind::OAuth,
        };
        assert!(crate::providers::kiro::endpoints::chat_url(&cred)
            .contains("q.us-east-1.amazonaws.com"));
        assert!(auth_headers(&cred)
            .iter()
            .all(|(key, _)| key != "tokentype"));
    }

    #[test]
    fn oauth_identity_follows_refresh_token_not_access_token() {
        // access token 续期后会变，身份不能跟着变（否则同账号会重复落库）。
        let before = identity_of(&oauth("at-old", Some("rt")));
        let after = identity_of(&oauth("at-new", Some("rt")));
        assert_eq!(before, after);
        assert!(before.starts_with("kiro-oauth-"));
        assert!(!before.contains("rt"));
    }

    #[test]
    fn urlencode_escapes_reserved_bytes_only() {
        assert_eq!(urlencode("aZ0-_.~"), "aZ0-_.~");
        assert_eq!(urlencode("a+b/c=d"), "a%2Bb%2Fc%3Dd");
        assert_eq!(urlencode(" "), "%20");
    }
}
