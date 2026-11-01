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
//! ── 两种凭证形态 ────────────────────────────────────────────
//! **API Key**（`ksk_…`）：Kiro CLI 的形态，不续期、不带 profileArn。
//! **OAuth**（AWS Builder ID）：设备授权登录（`login_start` → 网关按间隔
//! 调 `login_poll`），401 后由 `refresh_token` 换新。两种凭证走的上游主机
//! 与请求头都不同，见 `auth::auth_headers` 与 `endpoints::chat_url`。
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
                // Builder ID 设备授权登录（见 login_start / login_poll）
                web_login: true,
                sse_model_rewrite: true,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![
                proto::LoginMethod::Browser {
                    button: "Builder ID 登录".into(),
                    hint: Some(
                        "会打开 AWS Builder ID 授权页：确认授权后自动收下账号（本机不需要回调端口）"
                            .into(),
                    ),
                },
                proto::LoginMethod::Token {
                    label: "Kiro API Key".into(),
                    placeholder: "ksk_…（可带 |region 后缀，如 ksk_abc|us-east-1）".into(),
                    extra_fields: vec![],
                },
            ])
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
                .unwrap_or("")
                .trim();
            // ── 两条入口 ────────────────────────────────────────────
            // 有 `apiKey` / `token` = API Key 形态（`ksk_…`）；
            // 没有但有 `refreshToken` / `accessToken` = OAuth 形态（Builder ID
            // 登录产出的那份，或 `~/.aws/sso/cache/*.json` 直接粘贴）。
            if raw.is_empty() {
                return oauth_account_of_payload(&payload, input.name.clone());
            }
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
            let cred = usable_credential(ctx, &stored).await?;
            Ok(cred.access_token)
        })
    }

    /// 401 之后的无条件续期（OAuth 账号）。
    ///
    /// API Key 没有续期接口 —— 直接报错而不是静默返回同一个被拒的 token，
    /// 免得网关把「令牌不可用」当成上游抖动反复重试。
    fn refresh_token<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        account: &'a str,
    ) -> agent2api_provider_sdk::SendFuture<'a, String> {
        Box::pin(async move {
            let stored = ctx.store_get(ID, account).await.map_err(String::from)?;
            let cred = credential_from_secret(&stored.secret)?;
            if cred.kind != auth::CredentialKind::OAuth {
                return Err("Kiro API Key 不续期：请重新添加账号".to_string());
            }
            let next = refresh_and_persist(ctx, &stored, &cred).await?;
            Ok(next.access_token)
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
            let cred = usable_credential(ctx, &stored).await?;
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
            let cred = usable_credential(ctx, &stored).await?;
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
            let cred = usable_credential(ctx, &stored).await?;
            let client = crate::http::client(None, "");
            usage::fetch(&client, &cred).await
        })
    }

    // ── 登录（Builder ID 设备授权，轮询型）─────────────────────

    /// 发起一次 Builder ID 设备授权登录。
    ///
    /// 两段 HTTP 都真发：注册 OIDC 客户端（拿 clientId/clientSecret）→ 要
    /// 设备码。四个值一起写进 `settings`（键 `login-flow:{flow}`），
    /// `login_poll` 只凭 `flow` 读回来继续问 —— 插件进程内不留状态，重启后
    /// 已发起的流程会失效（网关侧会重新发起）。
    fn login_start<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        method: &'a str,
        payload: &'a serde_json::Value,
    ) -> agent2api_provider_sdk::SendFuture<'a, proto::LoginStart> {
        Box::pin(async move {
            if !method.is_empty() && method != "browser" {
                return Err(format!("Kiro 不支持这种登录方式：{method}"));
            }
            let region = payload
                .get("region")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(endpoints::DEFAULT_REGION)
                .to_string();
            let client = crate::http::client(None, &ctx.env.proxy);
            let (client_id, client_secret) = auth::register_client(&client, &region).await?;
            let (device_code, url, interval_ms) =
                auth::start_device(&client, &region, &client_id, &client_secret).await?;
            let flow = crate::ids::random_id("kiro");
            let state = serde_json::json!({
                "clientId": client_id,
                "clientSecret": client_secret,
                "deviceCode": device_code,
                "region": region,
            });
            ctx.settings_set(ID, &flow_key(&flow), &state)
                .await
                .map_err(String::from)?;
            Ok(proto::LoginStart {
                flow,
                url,
                instructions:
                    "在打开的页面里确认 Kiro（AWS Builder ID）授权；确认后会自动收下账号"
                        .to_string(),
                // 轮询型（> 0）：网关按这个间隔反复调 `login.poll`
                poll_interval_ms: interval_ms,
                // 设备授权页走系统浏览器更稳（Builder ID 的登录页会用第三方密码管理器）
                external_browser: true,
                // 设备授权全程只碰 AWS 的登录域（`device.sso.*.amazonaws.com`
                // 与 `view.awsapps.com` 都在下面两条的覆盖范围内）
                allowed_hosts: vec![
                    "view.awsapps.com".to_string(),
                    "awsapps.com".to_string(),
                    "amazonaws.com".to_string(),
                    "amazon.com".to_string(),
                ],
            })
        })
    }

    /// 轮询一次登录进度：`Pending` 继续等，`Done` 交出账号，`Failed` 收摊。
    fn login_poll<'a>(
        &'a self,
        ctx: &'a agent2api_provider_sdk::PluginCtx,
        flow: &'a str,
    ) -> agent2api_provider_sdk::SendFuture<'a, proto::LoginPoll> {
        Box::pin(async move {
            let key = flow_key(flow);
            let state = match ctx.settings_get(ID, &key).await {
                Ok(value) if value.is_object() => value,
                _ => {
                    return Ok(proto::LoginPoll::Failed {
                        message: "这次 Kiro 登录流程已失效（插件进程重启过？），请重新发起"
                            .to_string(),
                    })
                }
            };
            let text = |name: &str| {
                state
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let client_id = text("clientId");
            let client_secret = text("clientSecret");
            let device_code = text("deviceCode");
            let region = text("region");
            if client_id.is_empty() || client_secret.is_empty() || device_code.is_empty() {
                let _ = ctx.settings_set(ID, &key, &serde_json::Value::Null).await;
                return Ok(proto::LoginPoll::Failed {
                    message: "Kiro 登录状态不完整，请重新发起".to_string(),
                });
            }
            let region = if region.is_empty() {
                endpoints::DEFAULT_REGION.to_string()
            } else {
                region
            };
            let client = crate::http::client(None, &ctx.env.proxy);
            match auth::poll_device(&client, &region, &client_id, &client_secret, &device_code).await {
                Ok(Some(cred)) => {
                    // 终态：把这轮流程状态清掉（用户已经拿到账号）
                    let _ = ctx.settings_set(ID, &key, &serde_json::Value::Null).await;
                    Ok(proto::LoginPoll::Done {
                        account: oauth_account_of(&cred),
                    })
                }
                Ok(None) => Ok(proto::LoginPoll::Pending {
                    hint: Some("等待你在浏览器里完成 Kiro 授权…".to_string()),
                }),
                // 上游明确拒绝 = 这一轮结束；传输 / 解析失败则原样上报，让
                // 网关下一轮再问（不清状态，一次网络抖动不该作废整轮登录）。
                Err(message) if message.starts_with("Kiro 授权失败：") => {
                    let _ = ctx.settings_set(ID, &key, &serde_json::Value::Null).await;
                    let friendly = if message.contains("expired_token") {
                        "Kiro 登录超时（授权码已过期），请重新发起".to_string()
                    } else if message.contains("access_denied") {
                        "Kiro 登录被拒绝（在授权页取消了）".to_string()
                    } else {
                        message
                    };
                    Ok(proto::LoginPoll::Failed { message: friendly })
                }
                Err(message) => Err(message),
            }
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
///
/// ── `kind` 为什么必须读出来 ────────────────────────────────
/// 以前这里恒给 `ApiKey`，OAuth 账号因此会多发 `tokentype` / `origin` /
/// `x-amz-target` 三个 **API Key 专有头** —— 上游按这三条判定「这是 CLI
/// 走 runtime 主机」，配 OAuth 的 `q.{region}` 端点必被拒。
fn credential_from_secret(secret: &serde_json::Value) -> Result<auth::KiroCredential, String> {
    let kind = match secret.get("kind").and_then(serde_json::Value::as_str) {
        Some("oauth") => auth::CredentialKind::OAuth,
        _ => auth::CredentialKind::ApiKey,
    };
    let token = secret
        .get("accessToken")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let refresh_token = secret
        .get("refreshToken")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    // OAuth 账号允许先没有 accessToken（手动只导入 refreshToken 的形态），
    // 真正发请求前由 `usable_credential` 换一次。
    let refreshable = kind == auth::CredentialKind::OAuth && refresh_token.is_some();
    if token.is_empty() && !refreshable {
        return Err("账号里没有 Kiro 令牌，请重新添加".to_string());
    }
    let region = secret
        .get("region")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(endpoints::DEFAULT_REGION)
        .to_string();
    let api_key = secret
        .get("apiKey")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let api_key = match kind {
        // API Key 账号里两个字段同源；老记录只有 `accessToken` 时补上。
        auth::CredentialKind::ApiKey if api_key.is_empty() => token.to_string(),
        _ => api_key.to_string(),
    };
    Ok(auth::KiroCredential {
        access_token: token.to_string(),
        api_key,
        refresh_token,
        region,
        kind,
    })
}

/// 流程状态在 `settings` 里的键（每个流程一条，互不覆盖）。
fn flow_key(flow: &str) -> String {
    format!("login-flow:{flow}")
}

/// OAuth 凭证 → 网关落库形态（登录成功时用）。
fn oauth_account_of(cred: &auth::KiroCredential) -> proto::NormalizedAccount {
    let identity = auth::identity_of(cred);
    proto::NormalizedAccount {
        secret: serde_json::json!({
            "accessToken": cred.access_token,
            "refreshToken": cred.refresh_token,
            "region": cred.region,
            "kind": "oauth",
        }),
        public: serde_json::json!({
            "name": "Kiro",
            "email": identity,
            "tokenTail": tail_of(&cred.access_token),
            "hasToken": true,
        }),
        identity,
        desktop: false,
    }
}

/// 手动 / 文件导入的 OAuth 形态（`payload` 里没有 `apiKey`）。
///
/// `accessToken` 可以为空：那份 secret 靠 `refreshToken` 在首次使用时换出
/// access token（见 [`usable_credential`]）。
fn oauth_account_of_payload(
    payload: &serde_json::Value,
    name: Option<String>,
) -> Result<proto::NormalizedAccount, String> {
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let access = text("accessToken");
    let refresh = text("refreshToken");
    if access.is_empty() && refresh.is_empty() {
        return Err(
            "请填写 Kiro API Key（ksk_…），或粘贴含 accessToken / refreshToken 的 OAuth 凭据"
                .to_string(),
        );
    }
    let region = {
        let given = text("region");
        if given.is_empty() {
            endpoints::DEFAULT_REGION.to_string()
        } else {
            given
        }
    };
    let cred = auth::KiroCredential {
        access_token: access.clone(),
        api_key: String::new(),
        refresh_token: (!refresh.is_empty()).then(|| refresh.clone()),
        region: region.clone(),
        kind: auth::CredentialKind::OAuth,
    };
    let identity = auth::identity_of(&cred);
    Ok(proto::NormalizedAccount {
        secret: serde_json::json!({
            "accessToken": access,
            "refreshToken": (!refresh.is_empty()).then(|| refresh.clone()),
            "region": region,
            "kind": "oauth",
        }),
        public: serde_json::json!({
            "name": name.unwrap_or_else(|| "Kiro".to_string()),
            "email": identity,
            "tokenTail": tail_of(&access),
            "hasToken": true,
        }),
        identity,
        desktop: false,
    })
}

/// 一份「现在就能用」的凭证：OAuth 账号 access token 为空时先换一次。
///
/// ── 为什么只在空的时候换 ────────────────────────────────────
/// 本家没有存 `expiresAt`（AWS 的 `/token` 只给 `expiresIn`），判不出临期；
/// 「过期但非空」的令牌交给上游 401 → 网关调 [`refresh_token`] 那条既有链路。
/// 空令牌则连一次请求都发不出去，只能在这里先换。
async fn usable_credential(
    ctx: &agent2api_provider_sdk::PluginCtx,
    stored: &agent2api_provider_sdk::StoreAccount,
) -> Result<auth::KiroCredential, String> {
    let cred = credential_from_secret(&stored.secret)?;
    if cred.kind == auth::CredentialKind::OAuth && cred.access_token.is_empty() {
        return refresh_and_persist(ctx, stored, &cred).await;
    }
    Ok(cred)
}

/// 续期并尽力写回（写回失败不阻断：手里这份令牌仍然可用）。
async fn refresh_and_persist(
    ctx: &agent2api_provider_sdk::PluginCtx,
    stored: &agent2api_provider_sdk::StoreAccount,
    cred: &auth::KiroCredential,
) -> Result<auth::KiroCredential, String> {
    let client = crate::http::client(None, &ctx.env.proxy);
    let next = auth::refresh(&client, cred).await?;
    let mut fields: Vec<(&str, serde_json::Value)> = vec![
        ("accessToken", serde_json::json!(next.access_token)),
        ("region", serde_json::json!(next.region)),
        ("kind", serde_json::json!("oauth")),
    ];
    if let Some(token) = &next.refresh_token {
        fields.push(("refreshToken", serde_json::json!(token)));
    }
    let secret = crate::store::with_fields(&stored.secret, &fields);
    // `false` = 另一个刷新先落盘了（值已变）。那不是错误 —— 本份仍可用。
    let _ = ctx.store_update(&stored.id, &stored.secret, &secret).await;
    Ok(next)
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
    let cred = usable_credential(ctx, &account).await?;
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

    let client = crate::http::client(req.proxy.as_ref(), "");
    // ── profileArn 只对 OAuth 账号有意义 ────────────────────────
    // API Key（Kiro CLI）走 runtime 主机，请求体里不带 profileArn；OAuth 走
    // `q.{region}`，部分账号缺这个字段会 400。拿不到就给 `None` ——
    // best-effort，绝不因为「查不到 profile」把整条对话判失败。
    let profile_arn = match cred.kind {
        auth::CredentialKind::OAuth => models::fetch_profile_arn(&client, &cred).await,
        auth::CredentialKind::ApiKey => None,
    };
    let body = wire::build(&req.body, &wire_model, profile_arn.as_deref())?;
    let url = endpoints::chat_url(&cred);
    let mut headers = auth::auth_headers(&cred);
    headers.push(("content-type".to_string(), "application/json".to_string()));

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

    #[test]
    fn oauth_secret_keeps_kind_and_drops_api_key_headers() {
        let secret = json!({
            "accessToken": "at",
            "refreshToken": "rt",
            "region": "us-east-1",
            "kind": "oauth",
        });
        let cred = credential_from_secret(&secret).expect("应能还原");
        assert_eq!(cred.kind, auth::CredentialKind::OAuth);
        // 三个 API Key 专有头一个都不能出现，否则 q.{region} 端点必被拒。
        for banned in ["tokentype", "origin", "x-amz-target"] {
            assert!(
                auth::auth_headers(&cred)
                    .iter()
                    .all(|(key, _)| key != banned),
                "OAuth 账号不该带 {banned} 头"
            );
        }
    }

    #[test]
    fn oauth_secret_without_access_token_is_still_usable() {
        // 手动只导入 refreshToken 的形态：先空着，首用时换。
        let secret = json!({ "accessToken": "", "refreshToken": "rt", "kind": "oauth" });
        let cred = credential_from_secret(&secret).expect("有 refreshToken 就应能还原");
        assert_eq!(cred.kind, auth::CredentialKind::OAuth);
        assert!(cred.access_token.is_empty());
    }

    #[test]
    fn secret_without_kind_stays_api_key() {
        let secret = json!({ "accessToken": "ksk_abc", "apiKey": "ksk_abc", "region": "us-east-1" });
        let cred = credential_from_secret(&secret).expect("应能还原");
        assert_eq!(cred.kind, auth::CredentialKind::ApiKey);
    }

    #[test]
    fn oauth_payload_normalizes_to_oauth_secret() {
        let account = oauth_account_of_payload(&json!({ "refreshToken": "rt" }), None)
            .expect("应能归一化");
        assert_eq!(account.secret["kind"], "oauth");
        assert_eq!(account.secret["refreshToken"], "rt");
        assert!(account.identity.starts_with("kiro-oauth-"));
    }

    #[test]
    fn empty_payload_is_rejected_with_actionable_wording() {
        assert!(oauth_account_of_payload(&json!({}), None).is_err());
    }
}
