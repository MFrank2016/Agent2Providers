//! Meoo 登录：OAuth PKCE + 手动 AK + 旧 meoo-proxy 配置导入。
//!
//! ── 三条入口 ────────────────────────────────────────────────
//! ```text
//!   begin_login / exchange_callback   浏览器登录（PKCE + 手动回调兜底）
//!   normalize_legacy                  旧 ~/.meoo-proxy/config.json 导入
//!   auth_methods                      动态登录方式（OAuth / 项目服务 AK）
//! ```
//!
//! ── 浏览器登录为什么要「手动回调」兜底 ────────────────────────
//! `redirect_uri` 是 `http://127.0.0.1:<网关端口>/oauth/callback`（与官方 CLI
//! 逐字一致）。Docker / 远程部署时用户的浏览器与本机回环不同源，跳转回不来，
//! 于是界面把「粘贴地址栏整条 URL」当成第二条路 —— 所以 [`parse_callback_url`]
//! 同时接受完整 URL 与裸授权码。
//!
//! ── 一次性 state 存在哪 ─────────────────────────────────────
//! 插件进程内的进程级表（[`pending`]），键是授权地址里的 `state`。换票用的
//! PKCE `verifier` / `redirect_uri` / `api_base` 都随表项一起保存，回调到达时
//! **取走即删**（[`exchange_callback`] 的 `remove`）—— 同一枚授权码不能被换
//! 第二次，同一枚 state 也不该在 6 分钟内可重放。
//!
//! ── 不开通云服务是默认 ──────────────────────────────────────
//! 开通云服务是**有副作用的写操作**。只有用户在登录表单里显式选了
//! `allowCloudEnable=true` 才会替他去开通（见 `control::resolve_service_ak`）。
//! 旧配置导入更是永远不自动开通。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use super::{control, credentials, endpoints, models, oauth};

/// 一轮待回调登录的有效期：6 分钟（官方 CLI 的授权页停留时长同量级）。
const PENDING_TTL_MS: i64 = 6 * 60 * 1000;

/// 一轮「已发起、等回调」的登录。
struct Pending {
    /// PKCE 校验值（换票时回传）
    verifier: String,
    /// 发起时交给授权页的 redirect_uri（换票必须逐字相同）
    redirect_uri: String,
    /// 控制面基址（登录期间固定，避免换环境后旧 state 打到新域名）
    api_base: String,
    /// 用户指定的项目 id（空 = 登录后自动挑账号下第一个项目）
    project_url_id: String,
    /// 用户是否显式允许「项目没开通 AI 服务时自动开通」
    allow_cloud_enable: bool,
    /// 创建时刻（毫秒，用于过期清理）
    created_at: i64,
}

/// 进程级待回调表（键 = OAuth `state`）。
fn pending() -> &'static Mutex<HashMap<String, Pending>> {
    static TABLE: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 取表锁；中毒时用内部值继续（一条坏掉的登录不该让整家 provider 不可用）。
fn lock() -> std::sync::MutexGuard<'static, HashMap<String, Pending>> {
    match pending().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// 表项是否已超过 [`PENDING_TTL_MS`]（纯函数：换票前的那道闸门）。
fn expired(created_at: i64, now: i64) -> bool {
    now - created_at >= PENDING_TTL_MS
}

/// 清掉超过 [`PENDING_TTL_MS`] 的表项。
fn sweep(table: &mut HashMap<String, Pending>) {
    let now = crate::http::now_ms();
    table.retain(|_, item| !expired(item.created_at, now));
}

/// 只接受 OAuth 方式（`methodIndex` 0 / 缺省）。
///
/// `methodIndex == 1` 是「项目服务 AK」——那条路不经过浏览器，直接提交 AK
/// 即可。走到这里说明前端把方式选错了，报一句能照着做的话，而不是生成一个
/// 用户根本用不上的授权地址。
fn ensure_oauth_method(payload: &Value) -> Result<(), String> {
    let method_index = payload
        .get("methodIndex")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if method_index != 0 {
        return Err("Meoo 的 API 方式请直接提交项目服务 AK，不要走浏览器登录".to_string());
    }
    Ok(())
}

/// 发起浏览器登录：生成 PKCE + state，登记待回调表，返回授权地址。
pub fn begin_login(ctx: &PluginCtx, payload: &Value) -> Result<proto::LoginStart, String> {
    ensure_oauth_method(payload)?;
    let inputs = payload.get("inputs").unwrap_or(payload);
    let project_url_id = inputs
        .get("projectUrlId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let allow_cloud_enable = inputs
        .get("allowCloudEnable")
        .and_then(Value::as_str)
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let port = ctx.env.loopback_port;
    if port == 0 {
        return Err("网关尚未报告监听端口，无法生成 Meoo 授权地址".to_string());
    }
    let redirect_uri = format!("http://127.0.0.1:{port}{}", endpoints::CALLBACK_PATH);
    let api_base = endpoints::api_base();
    let pkce = oauth::create_pkce();
    let state = {
        let mut bytes = [0u8; 32];
        // 随机源失败必须中止：全零 state 是可预测的，而 state 是公开回调
        // 端点唯一的所有权凭证 —— 常量 state 等于让任何人把**自己的** Meoo
        // 账号绑到这台网关的登录任务上。
        getrandom::getrandom(&mut bytes).map_err(|error| format!("无法生成登录 state：{error}"))?;
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let url = endpoints::authorize_url(&api_base, &redirect_uri, &state, &pkce.challenge);
    let mut table = lock();
    sweep(&mut table);
    table.insert(
        state.clone(),
        Pending {
            verifier: pkce.verifier,
            redirect_uri,
            api_base,
            project_url_id,
            allow_cloud_enable,
            created_at: crate::http::now_ms(),
        },
    );
    Ok(proto::LoginStart {
        flow: state,
        url,
        instructions: "在打开的 Meoo 授权页完成登录；如果页面跳回本机地址后账号没有出现，\
                       把地址栏里的完整回调地址粘贴回来即可。"
            .to_string(),
        poll_interval_ms: 0,
        external_browser: true,
        allowed_hosts: Vec::new(),
    })
}

/// 用回调换票，并解析出「可落库的账号」。
///
/// 表项**取走即删**：无论后面换票成功还是失败，这一轮都不能再被重放。
pub async fn exchange_callback(
    ctx: &PluginCtx,
    callback: proto::LoginCallback,
) -> Result<proto::LoginPoll, String> {
    let Some(pending) = lock().remove(&callback.flow) else {
        return Ok(proto::LoginPoll::Failed {
            message: "这次登录已取消或已过期，请重新发起".to_string(),
        });
    };
    // 表项可能躲过了 `sweep`（sweep 只在 begin_login 时跑），也可能回调来得太
    // 晚：超过 TTL 的 state 不能换票，否则「6 分钟有效」只是一句注释。
    if expired(pending.created_at, crate::http::now_ms()) {
        return Ok(proto::LoginPoll::Failed {
            message: "这次登录已超过 6 分钟有效期，请重新发起登录".to_string(),
        });
    }
    let raw = if callback.url.trim().is_empty() {
        callback.code.clone()
    } else {
        callback.url.clone()
    };
    let (code, state) = match parse_callback_url(&raw) {
        Ok(value) => value,
        Err(message) => return Ok(proto::LoginPoll::Failed { message }),
    };
    if !state.is_empty() && state != callback.flow {
        return Ok(proto::LoginPoll::Failed {
            message: "回调 state 与当前登录任务不匹配，请重新发起登录".to_string(),
        });
    }
    let token = match oauth::exchange_code(
        ctx,
        &pending.api_base,
        endpoints::client_id(&pending.api_base),
        &pending.redirect_uri,
        &code,
        &pending.verifier,
    )
    .await
    {
        Ok(token) => token,
        Err(error) => {
            return Ok(proto::LoginPoll::Failed {
                message: error.message,
            })
        }
    };
    let identity = match control::identity(ctx, &pending.api_base, &token.access_token).await {
        Ok(value) => value,
        Err(error) => {
            return Ok(proto::LoginPoll::Failed {
                message: error.message,
            })
        }
    };
    let user_id = identity
        .get("user_id")
        .or_else(|| identity.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let username = identity
        .get("name")
        .or_else(|| identity.get("username"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let mut project = pending.project_url_id;
    if project.is_empty() {
        project = identity
            .get("project_url_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
    }
    if project.is_empty() {
        let projects =
            match control::list_projects(ctx, &pending.api_base, &token.access_token).await {
                Ok(value) => value,
                Err(error) => {
                    return Ok(proto::LoginPoll::Failed {
                        message: error.message,
                    })
                }
            };
        project = projects
            .first()
            .and_then(|item| {
                item.get("url_id")
                    .or_else(|| item.get("urlId"))
                    .or_else(|| item.get("id"))
            })
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
    }
    if project.is_empty() {
        return Ok(proto::LoginPoll::Failed {
            message: "账号下没有可用项目：请先在 Meoo 创建一个项目，再重新登录".to_string(),
        });
    }
    let service_ak = match control::resolve_service_ak(
        ctx,
        &pending.api_base,
        &token.access_token,
        &project,
        pending.allow_cloud_enable,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            return Ok(proto::LoginPoll::Failed {
                message: error.message,
            })
        }
    };
    if let Err(error) = models::validate_service_ak(ctx, &service_ak, Some(&project)).await {
        return Ok(proto::LoginPoll::Failed {
            message: error.message,
        });
    }
    let now = crate::http::now_ms();
    let secret = json!({
        "accessToken": token.access_token,
        "refreshToken": token.refresh_token,
        "expiresAt": now + token.expires_in.max(1) * 1000,
        "scope": token.scope,
        "openid": token.openid,
        "userId": user_id,
        "username": username,
        "projectUrlId": project.clone(),
        "serviceAk": service_ak,
        "serviceAkProjectId": project,
        "apiBaseUrl": pending.api_base,
        "gatewayBaseUrl": endpoints::gateway_base(),
        "allowCloudEnable": pending.allow_cloud_enable,
    });
    Ok(proto::LoginPoll::Done {
        account: proto::NormalizedAccount {
            public: credentials::account_view(&secret),
            identity: credentials::identity_of(&secret),
            secret,
            desktop: false,
        },
    })
}

/// 动态登录方式（`admin_action("auth.methods")` 的返回体）。
///
/// 两条路是**并列**的，不是「先 OAuth 再 AK」：只想要项目服务 AK 的用户
/// 不必先登录控制面。
pub fn auth_methods() -> Value {
    json!({
        "methods": [
            {
                "methodIndex": 0,
                "type": "oauth",
                "label": "浏览器登录",
                "instructions": "打开 Meoo 授权页，授权后自动解析项目服务 AK。",
                "prompts": [
                    {"key":"projectUrlId","type":"text","label":"项目 URL ID（可选）","placeholder":"留空使用账号默认项目","optional":true},
                    {"key":"allowCloudEnable","type":"select","label":"项目未开通 AI 服务时","options":[
                        {"value":"false","label":"不开通（推荐）"},
                        {"value":"true","label":"自动开通（会消耗额度）"}
                    ],"default":"false"}
                ],
                "manualCallback": true,
                "callbackInput": "url"
            },
            {
                "methodIndex": 1,
                "type": "api",
                "label": "项目服务 AK",
                "prompts": [
                    {"key":"serviceAk","type":"text","label":"项目服务 AK","placeholder":"meoo_project_service_v1....","secret":true},
                    {"key":"projectUrlId","type":"text","label":"项目 URL ID（可选）","optional":true},
                    {"key":"name","type":"text","label":"备注名（可选）","optional":true}
                ]
            }
        ]
    })
}

/// 从回调解析 `(code, state)`：完整 URL 或裸授权码都认。
///
/// 两种形态都传 `raw`：URL 会被解析出 `code` / `state`，裸 code 走
/// [`oauth::parse_callback`] 的兜底分支（`state` 为空串）。
pub fn parse_callback_url(raw: &str) -> Result<(String, String), String> {
    oauth::parse_callback(raw, raw)
}

/// 取消一轮登录：清掉 pending，避免 6 分钟内同一 state 残留。
pub fn cancel(flow: &str) {
    let _ = lock().remove(flow);
}

/// 旧配置里的 `apiBaseUrl` 是否可信：只允许正式 host，且必须 https。
///
/// 旧 `~/.meoo-proxy/config.json` 是用户可改的普通文件，里面的地址不能当成
/// 授权依据 —— 一个被改过的 `http://evil.example` 会把 OAuth token 送去陌生
/// 主机。
fn is_allowed_api_base(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    matches!(
        url.host_str()
            .map(|host| host.to_ascii_lowercase())
            .as_deref(),
        Some("meoo.com") | Some("gray-meoo.aliyun-inc.com")
    )
}

/// 旧 `~/.meoo-proxy/config.json` 导入。
///
/// 两种旧形态都认：只存了项目服务 AK 的（直接落库），以及存了 refresh token
/// 的（续期 → 查身份 → 解析项目服务 AK）。**永远不自动开通云服务**：导入是
/// 只读动作，不能顺手产生副作用。
pub async fn normalize_legacy(
    ctx: &PluginCtx,
    _input: &proto::NormalizeInput,
) -> Result<proto::NormalizedAccount, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    if home.is_empty() {
        return Err("找不到用户目录，无法读取 ~/.meoo-proxy/config.json".to_string());
    }
    let path = std::path::Path::new(&home)
        .join(".meoo-proxy")
        .join("config.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("未找到旧 meoo-proxy 配置：{}", path.display()))?;
    let config: Value =
        serde_json::from_str(&text).map_err(|_| "旧 meoo-proxy 配置不是合法 JSON".to_string())?;
    let configured_base = config
        .get("apiBaseUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if !configured_base.is_empty() && !is_allowed_api_base(configured_base) {
        return Err(
            "旧 meoo-proxy 配置的 apiBaseUrl 不在允许列表（只允许 https://meoo.com / \
             https://gray-meoo.aliyun-inc.com）"
                .to_string(),
        );
    }
    let service_ak = config
        .get("serviceAk")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let project = config
        .get("projectUrlId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if service_ak.starts_with("meoo_project_service_v1.") {
        models::validate_service_ak(ctx, service_ak, Some(project))
            .await
            .map_err(|error| error.message)?;
        let secret = json!({
            "serviceAk": service_ak,
            "projectUrlId": project,
            "serviceAkProjectId": project,
            "accessToken": "",
            "refreshToken": "",
            "expiresAt": 0,
        });
        return Ok(proto::NormalizedAccount {
            public: credentials::account_view(&secret),
            identity: credentials::identity_of(&secret),
            secret,
            desktop: false,
        });
    }
    let refresh_token = config
        .get("refreshToken")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if refresh_token.is_empty() {
        return Err("旧 meoo-proxy 配置里没有可用的 serviceAk 或 refreshToken".to_string());
    }
    let api_base = if configured_base.is_empty() {
        endpoints::api_base()
    } else {
        configured_base.to_string()
    };
    let token = oauth::refresh(
        ctx,
        &api_base,
        endpoints::client_id(&api_base),
        refresh_token,
    )
    .await
    .map_err(|error| error.message)?;
    let identity = control::identity(ctx, &api_base, &token.access_token)
        .await
        .map_err(|error| error.message)?;
    let user_id = identity
        .get("user_id")
        .or_else(|| identity.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let username = identity
        .get("name")
        .or_else(|| identity.get("username"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let project = if project.is_empty() {
        identity
            .get("project_url_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    } else {
        project.to_string()
    };
    if project.is_empty() {
        return Err("旧 meoo-proxy 配置没有项目 URL ID，且账号身份里也没有".to_string());
    }
    let service_ak =
        control::resolve_service_ak(ctx, &api_base, &token.access_token, &project, false)
            .await
            .map_err(|error| error.message)?;
    let now = crate::http::now_ms();
    let secret = json!({
        "accessToken": token.access_token,
        "refreshToken": token.refresh_token,
        "expiresAt": now + token.expires_in.max(1) * 1000,
        "scope": token.scope,
        "openid": token.openid,
        "userId": user_id,
        "username": username,
        "projectUrlId": project.clone(),
        "serviceAk": service_ak,
        "serviceAkProjectId": project,
        "apiBaseUrl": api_base,
        "gatewayBaseUrl": endpoints::gateway_base(),
        "allowCloudEnable": false,
    });
    Ok(proto::NormalizedAccount {
        public: credentials::account_view(&secret),
        identity: credentials::identity_of(&secret),
        secret,
        desktop: false,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn auth_methods_declares_oauth_and_api() {
        let value = auth_methods();
        let methods = value
            .get("methods")
            .and_then(serde_json::Value::as_array)
            .expect("methods");
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0]["type"], "oauth");
        assert_eq!(methods[0]["methodIndex"], 0);
        assert_eq!(methods[0]["manualCallback"], true);
        assert_eq!(methods[0]["prompts"][1]["default"], "false");
        assert_eq!(methods[1]["type"], "api");
        assert_eq!(methods[1]["methodIndex"], 1);
    }

    #[test]
    fn callback_rejects_error_param() {
        let error =
            parse_callback_url("http://127.0.0.1:3065/oauth/callback?error=access_denied&state=x")
                .expect_err("应拒绝");
        assert!(error.contains("access_denied"));
    }

    #[test]
    fn callback_accepts_full_url_and_bare_code() {
        let (code, state) =
            parse_callback_url("http://127.0.0.1:3065/oauth/callback?code=abc&state=xyz")
                .expect("完整回调 URL 应解析");
        assert_eq!(code, "abc");
        assert_eq!(state, "xyz");
        // 远程部署时用户粘贴的是裸授权码（回环地址回不到网关）
        let (code, state) = parse_callback_url("bare-code").expect("裸 code 应接受");
        assert_eq!(code, "bare-code");
        assert!(state.is_empty());
    }

    #[test]
    fn api_method_is_rejected_by_oauth_start() {
        let error = ensure_oauth_method(&serde_json::json!({ "methodIndex": 1 }))
            .expect_err("API 方式不该走浏览器登录");
        assert!(error.contains("项目服务 AK"));
        // 缺省 / 0 都按 OAuth 处理
        assert!(ensure_oauth_method(&serde_json::json!({})).is_ok());
        assert!(ensure_oauth_method(&serde_json::json!({ "methodIndex": 0 })).is_ok());
    }

    #[test]
    fn pending_expires_after_six_minutes() {
        let created = 1_000_000;
        // 5:59 还在窗口内
        assert!(!expired(created, created + PENDING_TTL_MS - 1));
        // 正好 6 分钟起作废（>=，不是 >）
        assert!(expired(created, created + PENDING_TTL_MS));
        assert!(expired(created, created + PENDING_TTL_MS + 60_000));
    }

    #[test]
    fn legacy_api_base_requires_https_prod_host() {
        assert!(is_allowed_api_base("https://meoo.com"));
        assert!(is_allowed_api_base("https://gray-meoo.aliyun-inc.com"));
        // 明文、非正式 host、坏 URL 一律拒绝
        assert!(!is_allowed_api_base("http://meoo.com"));
        assert!(!is_allowed_api_base("https://evil.example"));
        assert!(!is_allowed_api_base("not-a-url"));
    }
}
