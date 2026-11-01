//! Kiro（AWS CodeWhisperer / Amazon Q Developer）接入。
//!
//! ── 上游形态 ────────────────────────────────────────────────
//! 非 OpenAI 兼容：请求体是自有 JSON，响应是 `vnd.amazon.eventstream`
//! 二进制帧。完整协议见 `docs/superpowers/specs/2026-11-01-kiro-provider.md`。
//!
//! ── 为什么自己翻译帧 ────────────────────────────────────────
//! 网关的 `UpstreamKind` 只有 Chat / Anthropic / Ndjson / Gemini /
//! ChatglmSnapshot 五种，没有 Event Stream。插件自己解码、自己产 OpenAI 帧、
//! 报 `UpstreamKind::Chat` —— 与 `kuku` 同一范式。
//!
//! ── 签到 / 领取：确认为 ✗ ───────────────────────────────────
//! 三份公开实现（Kiro-Go / kiro2cc-proxy / dsh-kiro）都没有签到接口；
//! `getUsageLimits` 是**查询**不是签到。`freeTrialInfo` 与 bonus 由上游
//! 被动发放，没有可调用的领取动作。故 `checkin` / `claims` 两位恒 false。
//! 排除过程记录于此，不是「还没做」。

mod auth;
mod endpoints;
mod eventstream;
mod models;
mod stream;
mod usage;
mod wire;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{Provider, ProviderMeta};

/// provider id（`pack.json` 里必须写同一个）。
pub const ID: &str = "kiro";

/// Kiro 的默认模型清单（没拉过远程目录时的兜底）。
///
/// 取值依据：`ListAvailableModels` 在免费档账号上的实测返回，
/// 只保留当前主力 Claude 系；远程刷新会覆盖这份。
fn default_models() -> Vec<serde_json::Value> {
    use serde_json::json;
    vec![
        json!({ "id": "claude-sonnet-4.5", "name": "Claude Sonnet 4.5", "context_length": 200000 }),
        json!({ "id": "claude-haiku-4.5", "name": "Claude Haiku 4.5", "context_length": 200000 }),
    ]
}

pub struct KiroProvider;

impl Provider for KiroProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "Kiro")
            .with_capabilities(proto::Capabilities {
                chat: true,
                // 上游是「一次请求一个 conversationState」的会话式协议
                stateful: true,
                // API Key 不续期；OAuth 账号支持，见 auth::refresh
                refresh: true,
                model_refresh: true,
                usage: true,
                // 见模块头：上游没有签到 / 领取动作
                checkin: false,
                claims: false,
                web_login: false,
                sse_model_rewrite: true,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![proto::LoginMethod::Token {
                label: "Kiro API Key".into(),
                placeholder: "ksk_…（可带 |region 后缀，如 ksk_abc|us-east-1）".into(),
                extra_fields: vec![],
            }])
            .with_models(default_models())
            .with_account_features(proto::AccountFeatures {
                usage: true,
                credit_detail: false,
                identifier: vec!["email".to_string()],
                expiry: vec!["expiresAt".to_string()],
                ..Default::default()
            })
    }

    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a agent2api_provider_sdk::PluginCtx,
        input: proto::NormalizeInput,
    ) -> agent2api_provider_sdk::SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            let payload = match &input.source {
                proto::NormalizeSource::Manual { payload } => payload.clone(),
                proto::NormalizeSource::FileText { content, .. } => serde_json::from_str::<serde_json::Value>(content)
                    .map_err(|e| format!("文件不是合法 JSON: {e}"))?,
                proto::NormalizeSource::FileBase64 { .. } => {
                    return Err("Kiro 不支持二进制文件导入".to_string())
                }
                proto::NormalizeSource::Desktop => {
                    return Err("Kiro 不支持读取本机客户端登录态".to_string())
                }
            };
            let raw = payload
                .get("apiKey")
                .or_else(|| payload.get("token"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let cred = auth::parse_api_key(raw)?;
            let identity = auth::identity_of(&cred);
            Ok(proto::NormalizedAccount {
                secret: serde_json::json!({
                    "accessToken": cred.access_token,
                    "apiKey": cred.api_key,
                    "region": cred.region,
                    "kind": "api_key",
                }),
                public: serde_json::json!({
                    "name": input.name.clone().unwrap_or_else(|| "Kiro".to_string()),
                    "email": identity,
                    "tokenTail": tail_of(&cred.access_token),
                    "hasToken": true,
                }),
                identity,
                desktop: false,
            })
        })
    }

    fn account_identity(&self, secret: &serde_json::Value) -> Result<String, String> {
        let cred = credential_from_secret(secret)?;
        Ok(auth::identity_of(&cred))
    }

    fn ensure_token<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        account: &'a str,
    ) -> agent2api_provider_sdk::SendFuture<'a, String> {
        Box::pin(async move {
            let stored = ctx.store_get(ID, account).await.map_err(String::from)?;
            let cred = credential_from_secret(&stored.secret)?;
            Ok(cred.access_token)
        })
    }

    fn token_expiring<'a>(
        &'a self,
        _ctx: &'a agent2api_provider_sdk::PluginCtx,
        _account: &'a str,
    ) -> agent2api_provider_sdk::SendFuture<'a, bool> {
        // 判不出来就 false：宁可漏刷，也不要凭猜测打上游。
        Box::pin(async move { Ok(false) })
    }
}

/// 从落盘 secret 还原凭证。
fn credential_from_secret(secret: &serde_json::Value) -> Result<auth::KiroCredential, String> {
    let token = secret
        .get("accessToken")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if token.is_empty() {
        return Err("账号里没有 Kiro 令牌，请重新添加".to_string());
    }
    let region = secret
        .get("region")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(endpoints::DEFAULT_REGION)
        .to_string();
    Ok(auth::KiroCredential {
        access_token: token.to_string(),
        api_key: secret
            .get("apiKey")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(token)
            .to_string(),
        refresh_token: secret
            .get("refreshToken")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        region,
        kind: auth::CredentialKind::ApiKey,
    })
}

/// 令牌尾部四位（界面显示用，绝不回显本体）。
fn tail_of(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}
