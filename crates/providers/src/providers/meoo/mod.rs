//! Meoo（秒悟）接入：OAuth PKCE + 项目服务 AK + OpenAI 兼容转发 + 积分余额。
//!
//! ── 凭证模型（最容易混的一处）────────────────────────────────
//! - 对话 / 模型目录：`Authorization: Bearer meoo_project_service_v1.*`
//! - 控制面 / 积分：`Authorization: Bearer <OAuth access_token>`
//! - OAuth access token 1 小时过期；项目服务 AK 按项目解析、可轮换
//!
//! ── 所有请求都带官方 CLI 头 ─────────────────────────────────
//! `X-Meoo-Client: cli` / `X-Meoo-CLI-Version` / `X-Meoo-Request-Id`
//! 统一由 `headers.rs` 构造，禁止别处手拼。
//!
//! ── 签到 / 领取：确认为 ✗ ───────────────────────────────────
//! 官方 CLI 的 `meoo account` 只有积分/权益查询；没有每日签到或领取动作。
//! 故 `checkin` / `claims` 恒 false，这不是「还没做」。

pub mod chat;
pub mod control;
pub mod credentials;
pub mod endpoints;
pub mod headers;
pub mod login;
pub mod models;
pub mod oauth;
pub mod refresh;
pub mod usage;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::Value;

use crate::errors::GatewayError;

/// provider id（`pack.json` 必须写同一个）。
pub const ID: &str = "meoo";

pub struct MeooProvider;

impl Provider for MeooProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "Meoo 秒悟")
            .with_capabilities(proto::Capabilities {
                chat: true,
                stateful: false,
                refresh: true,
                model_refresh: true,
                usage: true,
                checkin: false,
                claims: false,
                web_login: true,
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![
                proto::LoginMethod::Browser {
                    button: "浏览器登录".into(),
                    hint: Some("打开 Meoo 授权页，授权后自动解析项目服务 AK".into()),
                },
                proto::LoginMethod::Token {
                    label: "项目服务 AK".into(),
                    placeholder: "meoo_project_service_v1....".into(),
                    extra_fields: vec![],
                },
            ])
            .with_models(models::default_models())
            .with_account_features(proto::AccountFeatures {
                usage: true,
                credit_detail: true,
                identifier: vec!["projectUrlId".into(), "userId".into()],
                expiry: vec!["expiresAt".into()],
                ..Default::default()
            })
    }

    fn provider_id(&self) -> String {
        ID.to_string()
    }

    // ── 数据面 ────────────────────────────────────────────────

    /// 构造一次对话请求：Bearer 取**项目服务 AK**（不是 OAuth token）。
    ///
    /// 网关在调用前已走 `ensure_token`（续期 + 重新解析 AK），所以这里读到
    /// 空 AK 说明账号本身没配好，直接 401 比发空 Bearer 更好懂。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, agent2api_provider_sdk::ChatPlan> {
        Box::pin(async move {
            let record = crate::store::record(ctx, ID, &req.account)
                .await
                .map_err(GatewayError::into_message)?;
            chat::build_plan(&crate::store::secret_view(&record), &req.body, req.stream)
                .map_err(GatewayError::into_message)
        })
    }

    /// 上游错误分类（判定顺序是契约，见 `chat.rs` 模块头）。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        chat::classify(status, body)
    }

    /// 思考档位：只有声明支持 `reasoning_effort` 的模型才注入。
    fn reasoning_patch(&self, level: &str, model: &str, _body: &Value) -> proto::ReasoningPatch {
        chat::reasoning_patch(level, model)
    }

    // ── 账号 ──────────────────────────────────────────────────

    /// 添加账号：手填项目服务 AK / 文本 JSON / 旧 meoo-proxy 配置导入。
    ///
    /// 三种来源最后都收敛到同一份 secret 形状（`credentials::account_view` /
    /// `identity_of` 认的那套字段），所以「从哪儿来」只影响解析，不影响落库。
    /// 手填与文本导入都会**立即探活**：一个打不通的 AK 落进账号库，只会在
    /// 第一次对话时变成一个看不懂的上游错误。
    fn normalize_account<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            match &input.source {
                proto::NormalizeSource::Manual { payload } => {
                    let manual = credentials::parse_manual(payload)?;
                    models::validate_service_ak(
                        ctx,
                        &manual.service_ak,
                        manual.project_url_id.as_deref(),
                    )
                    .await
                    .map_err(GatewayError::into_message)?;
                    let project = manual.project_url_id.clone().unwrap_or_default();
                    let tail = crate::store::token_tail(&manual.service_ak);
                    let name = account_name(input.name.as_deref(), manual.name, &tail);
                    let secret = serde_json::json!({
                        "serviceAk": manual.service_ak,
                        "projectUrlId": project.clone(),
                        "serviceAkProjectId": project,
                        "accessToken": "",
                        "refreshToken": "",
                        "expiresAt": 0,
                    });
                    // 备注名（表单里的「备注名」/ 导入时指定的名字）要进公开视图：
                    // 网关优先用 `public.name` 作为账号显示名，缺了它这一步，
                    // 用户填的备注名会被 `account_view` 的派生名盖掉。
                    let mut public = credentials::account_view(&secret);
                    if let Some(object) = public.as_object_mut() {
                        object.insert("name".to_string(), Value::String(name));
                    }
                    Ok(proto::NormalizedAccount {
                        public,
                        identity: credentials::identity_of(&secret),
                        secret,
                        desktop: false,
                    })
                }
                // 文本文件既可能是「整份 JSON」，也可能只是裸 AK 一行。
                // 先按 JSON 解析，失败就当成 AK 文本 —— 两种形态用户都会给。
                proto::NormalizeSource::FileText { content, .. } => {
                    let payload = serde_json::from_str::<Value>(content.trim())
                        .unwrap_or_else(|_| serde_json::json!({ "serviceAk": content.trim() }));
                    let input = proto::NormalizeInput {
                        source: proto::NormalizeSource::Manual { payload },
                        ..input.clone()
                    };
                    self.normalize_account(ctx, input).await
                }
                proto::NormalizeSource::FileBase64 { .. } => {
                    Err("Meoo 不支持二进制文件导入，请粘贴项目服务 AK 或 JSON".to_string())
                }
                proto::NormalizeSource::Desktop => login::normalize_legacy(ctx, &input).await,
            }
        })
    }

    fn account_view(&self, secret: &Value) -> Result<Value, String> {
        Ok(credentials::account_view(secret))
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(credentials::identity_of(secret))
    }

    // ── 凭证 ──────────────────────────────────────────────────

    /// 取对话 / 目录用的 Bearer：**项目服务 AK**，不是 OAuth access token。
    ///
    /// 网关把这里的返回值当上游 `Authorization` 用，所以绝不能返回控制面令牌
    /// （它只对 Meoo 控制面有效，拿去打模型网关必然 401）。临期 / AK 缺失时
    /// 内部会续期并重新解析 AK（见 `refresh::ensure_service_ak`）。
    fn ensure_token<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, String> {
        Box::pin(async move {
            refresh::ensure_service_ak(ctx, account, false)
                .await
                .map_err(GatewayError::into_message)
        })
    }

    /// 401 之后的强制刷新：跳过临期判定续期一次，并重新解析项目服务 AK。
    ///
    /// **只刷一轮**：网关重试一次、插件刷新一次，两边都不循环 —— `invalid_grant`
    /// 归 401「请重新登录」，重试只会把 401 拖成超时。
    fn refresh_token<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, String> {
        Box::pin(async move {
            refresh::ensure_service_ak(ctx, account, true)
                .await
                .map_err(GatewayError::into_message)
        })
    }

    /// 临期判定：与 [`refresh::ensure_service_ak`] 用同一个判据（AK 缺失 / 项目
    /// 不匹配 / access token 进入 5 分钟窗口）。
    ///
    /// 读不到账号时返回 `false`（与 `Provider` 的约定一致：判不出来宁可漏刷，
    /// 也不要凭猜测去打上游或把维护链路变成一条稳定失败）。
    fn token_expiring<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, bool> {
        Box::pin(async move {
            let Ok(record) = crate::store::record(ctx, ID, account).await else {
                return Ok(false);
            };
            let cred = credentials::from_secret(&crate::store::secret_view(&record));
            Ok(credentials::should_refresh(&cred, crate::http::now_ms()))
        })
    }

    // ── 目录 ──────────────────────────────────────────────────

    /// 当前模型清单：远程 `/models` 优先，5 分钟 TTL；失败沿用旧清单
    /// （没有则静态兜底），见 `models.rs` 的负缓存说明。
    fn models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move { Ok(models::list(ctx, account).await) })
    }

    /// 刷新目录：`force = false` 时 TTL 内跳过；失败保留旧清单并回报原因。
    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move { Ok(models::refresh(ctx, account, force).await) })
    }

    // ── 积分 ──────────────────────────────────────────────────

    /// 积分余额：`/account/points` 是主读数（失败即失败），套餐 / 身份只降级。
    ///
    /// 手动 AK 账号没有 OAuth 身份，查不了积分 —— 这里给可操作的 400，
    /// 见 `usage.rs` 模块头。签到 / 领取恒 false（官方 CLI 没有这两个动作）。
    fn usage<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::UsageReport> {
        Box::pin(async move {
            usage::query(ctx, account)
                .await
                .map_err(GatewayError::into_message)
        })
    }

    // ── 登录（回调型）──────────────────────────────────────────

    /// 发起登录。`poll_interval_ms = 0`：这是**回调型**流程，网关不该起轮询
    /// （回调由 `/oauth/callback` 或用户粘贴地址送达，见 `login.rs`）。
    fn login_start<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        _method: &'a str,
        payload: &'a Value,
    ) -> SendFuture<'a, proto::LoginStart> {
        Box::pin(async move { login::begin_login(ctx, payload) })
    }

    /// 回调换票（浏览器落在网关 `/oauth/callback`，或用户粘贴整条回调 URL）。
    fn login_callback<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        callback: proto::LoginCallback,
    ) -> SendFuture<'a, proto::LoginPoll> {
        Box::pin(async move { login::exchange_callback(ctx, callback).await })
    }

    /// 回调型流程没有「轮询」语义：等回调本身，永远是 Pending。
    fn login_poll<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _flow: &'a str,
    ) -> SendFuture<'a, proto::LoginPoll> {
        Box::pin(async { Ok(proto::LoginPoll::Pending { hint: None }) })
    }

    /// 取消：清掉待回调表项，同一 state 不能再换票。
    fn login_cancel<'a>(&'a self, _ctx: &'a PluginCtx, flow: &'a str) -> SendFuture<'a, ()> {
        Box::pin(async move {
            login::cancel(flow);
            Ok(())
        })
    }

    // ── 管理动作 ──────────────────────────────────────────────

    /// `auth.methods`：把登录方式交给网关动态渲染（不在网关里写死 Meoo 的表单）。
    fn admin_action<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
        action: &'a str,
        _payload: &'a Value,
    ) -> SendFuture<'a, Value> {
        Box::pin(async move {
            if action == "auth.methods" {
                return Ok(login::auth_methods());
            }
            Err(format!("Meoo 没有实现管理动作「{action}」"))
        })
    }
}

/// 账号显示名：用户备注（非空白）> 表单里的备注 > 「Meoo 秒悟 <AK 尾号>」。
///
/// 空串 / 全空白必须当成「没填」：`Some("")` 会被当成用户指定的名字，账号
/// 列表里就会出现一个没有名字的账号。
fn account_name(input_name: Option<&str>, manual_name: Option<String>, tail: &str) -> String {
    input_name
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string)
        .or(manual_name)
        .unwrap_or_else(|| format!("Meoo 秒悟 {tail}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn meta_declares_meoo_capabilities() {
        let meta = MeooProvider.meta();
        assert_eq!(meta.id, "meoo");
        assert_eq!(meta.label, "Meoo 秒悟");
        assert!(meta.capabilities.chat);
        assert!(!meta.capabilities.stateful);
        assert!(meta.capabilities.refresh);
        assert!(meta.capabilities.model_refresh);
        assert!(meta.capabilities.usage);
        assert!(meta.capabilities.web_login);
        assert!(!meta.capabilities.checkin);
        assert!(!meta.capabilities.claims);
        assert!(!meta.default_models.is_empty());
    }

    #[test]
    fn blank_remark_name_falls_back() {
        // 空白备注名不能把账号显示名清空
        assert_eq!(account_name(Some("   "), None, "abcd"), "Meoo 秒悟 abcd");
        assert_eq!(account_name(Some(""), None, "abcd"), "Meoo 秒悟 abcd");
        assert_eq!(account_name(None, None, "abcd"), "Meoo 秒悟 abcd");
        // 有备注名时用备注名；表单里的备注优先于自动名
        assert_eq!(account_name(Some("我的项目"), None, "abcd"), "我的项目");
        assert_eq!(
            account_name(Some(" "), Some("表单名".to_string()), "abcd"),
            "表单名"
        );
    }
}
