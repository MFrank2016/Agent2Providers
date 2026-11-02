//! Meoo secret / public / identity / 手动 AK 解析。
//!
//! ── 一个账号记录里同时躺着两套凭证 ──────────────────────────
//! ```text
//!   accessToken / refreshToken   控制面（身份 / 项目 / 积分）用，1 小时过期
//!   serviceAk                    模型网关（对话 / 目录）用，按项目解析、可轮换
//! ```
//! 两套都可能单独存在：手动粘贴 AK 的账号没有 OAuth token（[`account_view`]
//! 里 `longLived` 就是这个意思），只登录没开通云服务的账号则反过来。
//!
//! ── 公开视图只留尾号 ────────────────────────────────────────
//! [`account_view`] 会进列表 / 详情接口，**任何 token 都不能出现**（只给
//! `tokenTail`）。这不是「顺手脱敏」，而是这条边界唯一的防线：一旦把
//! `serviceAk` 塞进视图，等于把项目密钥发给所有能看账号列表的人。
//!
//! ── 手动 AK 只认项目服务 AK ─────────────────────────────────
//! 用户很容易把 `meoo_ak_*`（用户 API Key）当成项目服务 AK 粘进来 —— 两者
//! 前缀不同、用途也不同。 [`parse_manual`] 对前者给一句**可操作**的提示
//! （去哪儿拿对的），而不是笼统的「格式错误」。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

// ── 为什么整份 `allow(dead_code)` ───────────────────────────
// 本模块已由 `login.rs` / `refresh.rs` / `mod.rs` 接线，但凭证快照里仍有几个
// 字段（`gateway_base`、`username` 的部分用法）要等目录 / 对话链路（Task 7-8）
// 才会被读。整份关掉告警，是为了让「快照字段」保持完整一套 —— 缺字段会让
// 后面那条链路各自再解析一遍 secret，而「哪些字段进公开视图」正是最不该重写
// 的地方。
#![allow(dead_code)]

use serde_json::{json, Value};

use crate::store;

/// 一次转发 / 查询用的 Meoo 凭证快照
pub struct MeooCredentials {
    /// OAuth access token（控制面用；手动 AK 账号为空）
    pub access_token: String,
    /// OAuth refresh token（续期用；手动 AK 账号为空）
    pub refresh_token: String,
    /// access token 过期时刻（毫秒）。0 = 判不出来
    pub expires_at: i64,
    /// 控制面基址（落盘时固定，避免换环境后旧账号打到新域名）
    pub api_base: String,
    /// 模型网关基址
    pub gateway_base: String,
    /// 当前项目 id（`projectUrlId`）
    pub project_url_id: String,
    /// 项目服务 AK（`meoo_project_service_v1.*`）
    pub service_ak: String,
    /// 这个 AK 属于哪个项目（与 [`Self::project_url_id`] 不一致 = 需要重解析）
    pub service_ak_project_id: String,
    /// 上游用户 id
    pub user_id: String,
    /// 展示名
    pub username: String,
    /// 登录时是否勾选了「自动开通云服务」
    pub allow_cloud_enable: bool,
}

/// 从账号 secret 里取出凭证快照（字段缺失一律给空 / 0，不猜）。
pub fn from_secret(secret: &Value) -> MeooCredentials {
    MeooCredentials {
        access_token: store::pick(secret, &["accessToken", "access_token"]),
        refresh_token: store::pick(secret, &["refreshToken", "refresh_token"]),
        expires_at: secret.get("expiresAt").and_then(Value::as_i64).unwrap_or(0),
        api_base: store::pick(secret, &["apiBaseUrl"]),
        gateway_base: store::pick(secret, &["gatewayBaseUrl"]),
        project_url_id: store::pick(secret, &["projectUrlId", "serviceAkProjectId"]),
        service_ak: store::pick(secret, &["serviceAk", "apiKey"]),
        service_ak_project_id: store::pick(secret, &["serviceAkProjectId"]),
        user_id: store::pick(secret, &["userId", "openid"]),
        username: store::pick(secret, &["username", "name"]),
        allow_cloud_enable: secret
            .get("allowCloudEnable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// 提前刷新的窗口：access token 剩不到 5 分钟就当作临期。
///
/// 5 分钟是「一次对话可能跑得比它久」与「别把刷新打成轮询」之间的折中：
/// 窗口太小，长对话会在半途撞上 401；窗口太大，每次转发前都在续期。
const REFRESH_MARGIN_MS: i64 = 5 * 60 * 1000;

/// 这个账号此刻需不需要动网络（续期 / 重新解析 AK）。
///
/// ── 三条判据 ────────────────────────────────────────────────
/// 1. 项目服务 AK 为空 —— 没有能拿去对话的 Bearer；
/// 2. AK 属于的项目与当前项目不一致 —— 换了项目，旧 AK 打不动新项目；
/// 3. access token 进入 5 分钟窗口（`expiresAt = 0` 表示判不出来，**不算**临期，
///    宁可漏刷也不要凭猜测打上游）。
///
/// 三条都不成立时调用方一次请求都不该发 —— 这是转发路径上唯一的「省网络」
/// 闸门。
pub fn should_refresh(cred: &MeooCredentials, now: i64) -> bool {
    if cred.service_ak.is_empty() || cred.service_ak_project_id != cred.project_url_id {
        return true;
    }
    cred.expires_at > 0 && cred.expires_at - now < REFRESH_MARGIN_MS
}

/// 公开账号视图：**只**含展示字段与 `tokenTail`，不含任何 token / AK。
pub fn account_view(secret: &Value) -> Value {
    let cred = from_secret(secret);
    let tail = if !cred.service_ak.is_empty() {
        store::token_tail(&cred.service_ak)
    } else {
        store::token_tail(&cred.access_token)
    };
    let name = if !cred.username.is_empty() && !cred.project_url_id.is_empty() {
        format!("{} · {}", cred.username, cred.project_url_id)
    } else if !cred.username.is_empty() {
        cred.username.clone()
    } else {
        format!("Meoo 秒悟 {tail}")
    };
    json!({
        "name": name,
        "uid": cred.user_id.clone(),
        "userId": cred.user_id,
        "projectUrlId": cred.project_url_id,
        "tokenTail": tail,
        "expiresAt": cred.expires_at,
        "longLived": cred.access_token.is_empty() && !cred.service_ak.is_empty(),
    })
}

/// 账号去重标识：用户 + 项目 → 项目 → AK 尾号。
///
/// 有 OAuth 身份时用 `meoo:<userId>:<projectUrlId>`（同一用户换项目是不同账号）；
/// 只有项目（手动 AK）时用 `meoo:project:<projectUrlId>`；连项目都没填的手动
/// AK 只能按尾号区分（碰撞概率低，且总比「全部同名」好）。
pub fn identity_of(secret: &Value) -> String {
    let cred = from_secret(secret);
    if !cred.user_id.is_empty() && !cred.project_url_id.is_empty() {
        return format!("meoo:{}:{}", cred.user_id, cred.project_url_id);
    }
    if !cred.project_url_id.is_empty() {
        return format!("meoo:project:{}", cred.project_url_id);
    }
    if !cred.service_ak.is_empty() {
        return format!("meoo:ak:{}", store::token_tail(&cred.service_ak));
    }
    format!("meoo:{}", store::token_tail(&cred.access_token))
}

/// 手动粘贴的项目服务 AK（可选带项目 id 与备注名）。
#[derive(Debug)]
pub struct ManualAk {
    /// 项目服务 AK（已校验前缀）
    pub service_ak: String,
    /// 项目 id（用户可留空，后续从控制面解析）
    pub project_url_id: Option<String>,
    /// 展示名（留空时由账号视图兜底）
    pub name: Option<String>,
}

/// 解析「手动 AK」登录表单：先读 `inputs`，再退回平铺字段。
///
/// 接受 `serviceAk` / `apiKey` / `token` 三个键名（各版本前端用过不同名字），
/// 但只接受 `meoo_project_service_v1.` 前缀 —— `meoo_ak_*` 是用户 Key，
/// 拿去打模型网关只会 401。
pub fn parse_manual(payload: &Value) -> Result<ManualAk, String> {
    let fields = payload.get("inputs").unwrap_or(payload);
    let service_ak = fields
        .get("serviceAk")
        .or_else(|| fields.get("apiKey"))
        .or_else(|| fields.get("token"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if service_ak.is_empty() {
        return Err("请填写项目服务 AK（meoo_project_service_v1....）".to_string());
    }
    if service_ak.starts_with("meoo_ak_") {
        return Err("这是 Meoo 用户 API Key（meoo_ak_*），不是项目服务 AK；\
             请到项目「云服务 → AI」或执行 `meoo cloud pull-env` 获取 meoo_project_service_v1.*"
            .to_string());
    }
    if !service_ak.starts_with("meoo_project_service_v1.") {
        return Err("项目服务 AK 格式不正确，应以 meoo_project_service_v1. 开头".to_string());
    }
    Ok(ManualAk {
        service_ak,
        project_url_id: fields
            .get("projectUrlId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        name: fields
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_user_api_key() {
        let error = parse_manual(&json!({"inputs": {"serviceAk": "meoo_ak_123"}}))
            .expect_err("用户 Key 必须拒绝");
        assert!(error.contains("项目服务 AK"));
    }

    #[test]
    fn accepts_project_service_ak() {
        let parsed = parse_manual(&json!({
            "inputs": {
                "serviceAk": "meoo_project_service_v1.abc",
                "projectUrlId": "proj_1",
                "name": "测试项目"
            }
        }))
        .expect("应接受");
        assert_eq!(parsed.service_ak, "meoo_project_service_v1.abc");
        assert_eq!(parsed.project_url_id.as_deref(), Some("proj_1"));
        assert_eq!(parsed.name.as_deref(), Some("测试项目"));
    }

    #[test]
    fn public_view_never_contains_secrets() {
        let view = account_view(&json!({
            "accessToken": "a",
            "refreshToken": "r",
            "serviceAk": "meoo_project_service_v1.abc",
            "projectUrlId": "proj_1",
            "userId": "u1",
            "username": "测试"
        }));
        let text = view.to_string();
        assert!(!text.contains("\"a\""));
        assert!(!text.contains("\"r\""));
        assert!(!text.contains("meoo_project_service_v1.abc"));
        assert!(text.contains("proj_1"));
    }

    #[test]
    fn parse_manual_falls_back_to_flat_payload() {
        let parsed = parse_manual(&json!({"apiKey": "meoo_project_service_v1.flat"}))
            .expect("平铺字段也应接受");
        assert_eq!(parsed.service_ak, "meoo_project_service_v1.flat");
        assert_eq!(parsed.project_url_id, None);
        assert_eq!(parsed.name, None);
    }

    #[test]
    fn identity_prefers_user_and_project() {
        assert_eq!(
            identity_of(&json!({"userId": "u1", "projectUrlId": "p1"})),
            "meoo:u1:p1"
        );
        assert_eq!(
            identity_of(&json!({"projectUrlId": "p1"})),
            "meoo:project:p1"
        );
        assert_eq!(
            identity_of(&json!({"serviceAk": "meoo_project_service_v1.abc"})),
            "meoo:ak:.abc"
        );
    }
}
