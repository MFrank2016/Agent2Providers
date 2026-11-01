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

    fn conversation<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        req: proto::ConversationRequest,
        sink: agent2api_provider_sdk::ConversationSink<'a>,
    ) -> agent2api_provider_sdk::SendFuture<'a, ()> {
        Box::pin(async move { run_chat(ctx, req, sink).await })
    }

    fn models<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        account: &'a str,
    ) -> agent2api_provider_sdk::SendFuture<'a, proto::ModelList> {
        Box::pin(async move {
            let stored = ctx.store_get(ID, account).await.map_err(String::from)?;
            let cred = credential_from_secret(&stored.secret)?;
            let client = crate::http::client(None, "");
            match models::fetch_all(&client, &cred).await {
                Ok(list) if !list.is_empty() => Ok(proto::ModelList {
                    models: list,
                    meta: proto::CatalogMeta {
                        remote: true,
                        refreshed_at: crate::http::now_ms(),
                    },
                }),
                _ => Ok(proto::ModelList {
                    models: default_models(),
                    meta: proto::CatalogMeta { remote: false, refreshed_at: 0 },
                }),
            }
        })
    }

    fn refresh_models<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        account: &'a str,
        _force: bool,
    ) -> agent2api_provider_sdk::SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            let stored = ctx.store_get(ID, account).await.map_err(String::from)?;
            let cred = credential_from_secret(&stored.secret)?;
            let client = crate::http::client(None, "");
            let list = models::fetch_all(&client, &cred).await?;
            Ok(proto::RefreshOutcome::refreshed(list.len()))
        })
    }

    fn usage<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        account: &'a str,
    ) -> agent2api_provider_sdk::SendFuture<'a, proto::UsageReport> {
        Box::pin(async move {
            let stored = ctx.store_get(ID, account).await.map_err(String::from)?;
            let cred = credential_from_secret(&stored.secret)?;
            let client = crate::http::client(None, "");
            usage::fetch(&client, &cred).await
        })
    }

    fn classify(&self, status: u16, body: &serde_json::Value) -> proto::ErrorClass {
        let message = body
            .get("message")
            .or_else(|| body.get("Message"))
            .or_else(|| body.get("error"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Kiro 上游返回错误")
            .to_string();
        let lower = message.to_lowercase();
        let upstream_code = body.get("code").and_then(serde_json::Value::as_i64);

        // ① 封号：不是限额，必须让账号停下来
        if lower.contains("temporarily_suspended")
            || lower.contains("temporarily is suspended")
            || lower.contains("account suspended")
        {
            return proto::ErrorClass::Fatal {
                status,
                message: "Kiro 账号已被上游暂停，请在官方客户端确认账号状态".to_string(),
                upstream_code,
            };
        }

        // ② 上下文过长：客户端自己的问题，绝不能罚账号
        if lower.contains("input is too long") || lower.contains("too many tokens") {
            return proto::ErrorClass::Fatal {
                status,
                message: "本次请求的上下文超过 Kiro 上限（history 最多 198 条），请开启新会话".to_string(),
                upstream_code,
            };
        }

        // ③ 加量包耗尽：与订阅耗尽分开表述
        if status == 402 && lower.contains("overage") {
            return proto::ErrorClass::QuotaLimited {
                status,
                message: "Kiro 加量包额度已用完（订阅额度可能仍在）".to_string(),
                upstream_code,
                reset_at: None,
            };
        }

        // ④ 凭证失效
        if status == 401
            || lower.contains("invalid_grant")
            || lower.contains("token expired")
            || lower.contains("unauthorized")
        {
            return proto::ErrorClass::TokenExpired {
                message: "Kiro 凭证不可用，请重新添加账号".to_string(),
            };
        }

        // ⑤ 额度 / 速率
        if status == 429 || lower.contains("quota") || lower.contains("rate limit") {
            return proto::ErrorClass::QuotaLimited {
                status,
                message: "Kiro 账号额度或速率已达上限".to_string(),
                upstream_code,
                reset_at: None,
            };
        }

        proto::ErrorClass::Fatal { status, message, upstream_code }
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

/// 一次对话：取凭证 → 拼请求 → 发上游 → 解码帧 → 翻译 → 推 sink。
async fn run_chat(
    ctx: &agent2api_provider_sdk::PluginCtx,
    req: proto::ConversationRequest,
    mut sink: agent2api_provider_sdk::ConversationSink<'_>,
) -> Result<(), String> {
    let account = ctx
        .store_get(ID, &req.account)
        .await
        .map_err(String::from)?;
    let cred = credential_from_secret(&account.secret)?;
    let client_model = req
        .body
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("claude-sonnet-4.5")
        .to_string();
    let wire_model = if req.wire_model.is_empty() {
        client_model.clone()
    } else {
        req.wire_model.clone()
    };
    let body = wire::build(&req.body, &wire_model, None)?;
    let url = endpoints::chat_url(&cred);
    let mut headers = auth::auth_headers(&cred);
    headers.push(("content-type".to_string(), "application/json".to_string()));

    let client = crate::http::client(req.proxy.as_ref(), "");
    let response = crate::http::post_stream(
        &client,
        &url,
        &headers,
        &body,
        "application/vnd.amazon.eventstream",
    )
    .await?;

    if !response.is_success() {
        let status = response.status;
        let body = response.error_body.clone().unwrap_or_default();
        return Err(classify_error_text(status, &body));
    }

    sink.head(proto::StreamHead {
        status: 200,
        headers: [(
            "content-type".to_string(),
            "text/event-stream".to_string(),
        )]
        .into_iter()
        .collect(),
        upstream: proto::UpstreamKind::Chat,
    })
    .await?;

    let Some(upstream) = response.response else {
        return Err("Kiro 上游没有返回响应体".to_string());
    };
    let mut decoder = eventstream::FrameDecoder::new();
    let mut translator = stream::FrameTranslator::new(&client_model);
    let mut source = upstream.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk) = source.next().await {
        let bytes = chunk.map_err(|error| format!("读 Kiro 上游失败：{error}"))?;
        for frame in decoder.push(&bytes)? {
            for text in translator.feed(&frame) {
                sink.send(text.as_bytes()).await?;
            }
        }
    }
    decoder.finish()?;
    for text in translator.finish() {
        sink.send(text.as_bytes()).await?;
    }
    Ok(())
}

/// 把上游错误体折成一句可读的失败原因（分类在 `classify` 里做）。
fn classify_error_text(status: u16, body: &str) -> String {
    let head: String = body.chars().take(240).collect();
    format!("Kiro 上游返回 HTTP {status}：{head}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn classify(status: u16, message: &str) -> proto::ErrorClass {
        KiroProvider.classify(status, &json!({ "message": message }))
    }

    #[test]
    fn quota_429_is_quota_limited() {
        assert!(matches!(classify(429, "quota exceeded"), proto::ErrorClass::QuotaLimited { .. }));
    }

    #[test]
    fn overage_402_is_quota_limited_with_overage_wording() {
        match classify(402, "overage limit reached") {
            proto::ErrorClass::QuotaLimited { message, .. } => {
                assert!(message.contains("加量包"), "文案应区分加量包：{message}");
            }
            other => panic!("期望 QuotaLimited，得到 {other:?}"),
        }
    }

    #[test]
    fn suspended_account_is_fatal() {
        assert!(matches!(
            classify(403, "account temporarily_suspended"),
            proto::ErrorClass::Fatal { .. }
        ));
    }

    #[test]
    fn input_too_long_is_fatal_and_not_quota() {
        assert!(matches!(
            classify(400, "Input is too long."),
            proto::ErrorClass::Fatal { .. }
        ));
    }

    #[test]
    fn auth_errors_are_token_expired() {
        assert!(matches!(classify(401, "unauthorized"), proto::ErrorClass::TokenExpired { .. }));
        assert!(matches!(classify(403, "invalid_grant"), proto::ErrorClass::TokenExpired { .. }));
    }
}
