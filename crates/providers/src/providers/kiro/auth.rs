//! Kiro 凭证：API Key 解析、鉴权头、续期。
//!
//! ── 两种凭证形态 ────────────────────────────────────────────
//! `ApiKey`（`ksk_…`）：不续期、不需要 profileArn、走 `runtime.{region}.kiro.dev`。
//! `OAuth`：access/refresh token，走 `q.{region}` 或 `codewhisperer.{region}`，
//! 续期见 `refresh`（Task 10 实现）。
//!
//! ── 为什么 API Key 也要记 region ─────────────────────────────
//! `runtime.{region}.kiro.dev` 的 region 是数据面，不是鉴权面；用户粘贴的
//! `ksk_…|eu-west-1` 后半段就是它。缺省 `us-east-1`。

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
pub fn identity_of(cred: &KiroCredential) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in cred.access_token.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("kiro-api-{hash:016x}")
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
}
