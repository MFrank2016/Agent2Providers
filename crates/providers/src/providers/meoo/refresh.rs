//! 凭证刷新：OAuth access token + 项目服务 AK，单飞 + 比较再写。
//!
//! ── 两套凭证，刷新要一起对齐 ────────────────────────────────
//! ```text
//!   accessToken / refreshToken  控制面（身份 / 项目 / 环境）用，1 小时过期
//!   serviceAk                   模型网关（对话 / 目录）用，按项目解析
//! ```
//! [`ensure_service_ak`] 返回的是**项目服务 AK**（对话 / 目录的 Bearer），
//! 不是 OAuth access token —— 后者只在续期与解析 AK 时用一下，不外传。
//!
//! ── 什么时候真的打网络 ──────────────────────────────────────
//! 判据只有 [`credentials::should_refresh`]：AK 缺失 / 项目不匹配 / access
//! token 进入 5 分钟窗口。三者都不成立时**一次请求都不发** —— 转发路径上每次
//! 取凭证都顺手打一轮上游会把延迟与限额都耗在无意义的地方。
//!
//! ── 单飞：refresh_token 是轮换的 ─────────────────────────────
//! 上游续期会下发新的 refresh_token（旧的可能立即作废）。并发两轮刷新里后到
//! 的那次拿旧 refresh_token 去换 → `invalid_grant` → 用户被踢下线。所以同一
//! 账号的刷新走 [`flight::Table`]：key 里带 refresh_token 的**指纹**（令牌一变
//! 就是新的一轮），只有 leader 真的打上游，等待者直接拿它的结果。
//!
//! leader 拿到锁之后**必须重读账号**：前一个 leader 可能刚落盘，此时再刷一次
//! 等于白白轮换一次 refresh_token。
//!
//! ── 只刷一轮，不重试 ────────────────────────────────────────
//! 401 之后的强制刷新由网关发起一次、插件刷新一次，两边都不循环重试：真失效
//! （`invalid_grant`）时重试只会把 401 拖成超时。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::sync::OnceLock;

use serde_json::Value;

use agent2api_provider_sdk::PluginCtx;

use crate::errors::GatewayError;
use crate::flight::{self, Join};
use crate::store;

use super::{control, credentials, endpoints, oauth};

/// 进程级单飞表：key = `meoo:<account>:<refresh_token 指纹>`。
fn flights() -> &'static flight::Table<String> {
    static TABLE: OnceLock<flight::Table<String>> = OnceLock::new();
    TABLE.get_or_init(flight::Table::new)
}

/// 在 secret 上算出「续期之后」的新 secret。
///
/// ── 只覆盖上游真给了的字段 ──────────────────────────────────
/// 续期响应可能省略 `refresh_token` / `scope` / `openid`。省略 **不等于** 作废：
/// 整包替换会把 refresh_token 抹成空串，账号从此只能重新登录；把 `scope` /
/// `openid` 抹掉则会让下次登录态校验对不上。所以这三个字段**空值不覆盖**。
///
/// `service_ak` 为 `None` = 这一轮没重新解析 AK（原值原样保留）。
pub fn next_secret(current: &Value, token: &oauth::TokenBundle, service_ak: Option<&str>) -> Value {
    let now = crate::http::now_ms();
    let mut next = current.clone();
    if let Some(object) = next.as_object_mut() {
        object.insert(
            "accessToken".into(),
            Value::String(token.access_token.clone()),
        );
        if !token.refresh_token.is_empty() {
            object.insert(
                "refreshToken".into(),
                Value::String(token.refresh_token.clone()),
            );
        }
        object.insert(
            "expiresAt".into(),
            Value::from(now + token.expires_in.max(1) * 1000),
        );
        if !token.scope.is_empty() {
            object.insert("scope".into(), Value::String(token.scope.clone()));
        }
        if !token.openid.is_empty() {
            object.insert("openid".into(), Value::String(token.openid.clone()));
        }
        if let Some(ak) = service_ak {
            object.insert("serviceAk".into(), Value::String(ak.to_string()));
            // 刚解析出来的 AK 属于当前项目：两者必须一起写，否则下一次
            // `should_refresh` 会判成「项目不匹配」再解析一遍。
            let project = object
                .get("projectUrlId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            object.insert("serviceAkProjectId".into(), Value::String(project));
        }
    }
    next
}

/// 取当前可用的**项目服务 AK**（对话 / 目录的 Bearer）。
///
/// `force = true` 时跳过临期判定（401 之后的强制刷新）；否则只在
/// [`credentials::should_refresh`] 成立时才动网络。
pub async fn ensure_service_ak(
    ctx: &PluginCtx,
    account: &str,
    force: bool,
) -> Result<String, GatewayError> {
    let record = store::record(ctx, super::ID, account).await?;
    let current = store::secret_view(&record);
    let cred = credentials::from_secret(&current);
    if !force && !credentials::should_refresh(&cred, crate::http::now_ms()) {
        return Ok(cred.service_ak);
    }
    if cred.refresh_token.is_empty() {
        // 手动 AK 账号没有 OAuth 身份：能做的只有把现有 AK 交出去（它是否
        // 可用由上游判定），没有可续期的东西。
        if !cred.service_ak.is_empty() {
            return Ok(cred.service_ak);
        }
        return Err(GatewayError::with_status(
            401,
            "Meoo 账号没有 refresh_token 或项目服务 AK，请重新登录",
        ));
    }
    let key = format!(
        "meoo:{account}:{}",
        flight::fingerprint(&cred.refresh_token)
    );
    match flights().join(&key) {
        // 等待者拿到的就是 leader 的结果（成功或失败），不再自己打一轮。
        Join::Waiter(waiter) => waiter.wait().await,
        Join::Leader(guard) => {
            let result = refresh_leader(ctx, account, force).await;
            // 失败也要 finish：等待者必须被唤醒，表项也必须释放。
            guard.finish(result.clone());
            result
        }
    }
}

/// leader 的实体：重读 → 续期 → 解析 AK → 比较再写。
async fn refresh_leader(
    ctx: &PluginCtx,
    account: &str,
    force: bool,
) -> Result<String, GatewayError> {
    // 拿到锁后重读：可能已被另一个 leader 刷新过，此时不该再轮换一次令牌。
    let record = store::record(ctx, super::ID, account).await?;
    let current = store::secret_view(&record);
    let cred = credentials::from_secret(&current);
    if !force && !credentials::should_refresh(&cred, crate::http::now_ms()) {
        return Ok(cred.service_ak);
    }
    let needs_ak = cred.service_ak.is_empty() || cred.service_ak_project_id != cred.project_url_id;
    // 缺项目 id 时**先**报错再续期：续期会轮换 refresh_token，为一个注定拼不出
    // `/projects/{id}/cloud/environment` 的请求把令牌换掉，等于白白丢掉一次
    // 有效的登录态。
    if needs_ak && cred.project_url_id.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "Meoo 账号没有项目 URL ID，请重新登录或重新填写项目服务 AK",
        ));
    }
    let api_base = if cred.api_base.is_empty() {
        endpoints::api_base()
    } else {
        cred.api_base.clone()
    };
    let token = oauth::refresh(
        ctx,
        &api_base,
        endpoints::client_id(&api_base),
        &cred.refresh_token,
    )
    .await?;
    let resolved = if needs_ak {
        match control::resolve_service_ak(
            ctx,
            &api_base,
            &token.access_token,
            &cred.project_url_id,
            cred.allow_cloud_enable,
        )
        .await
        {
            Ok(ak) => Some(ak),
            Err(error) => {
                // 令牌已经轮换过：即使 AK 解析失败也要把新令牌落盘，否则账号
                // 带着作废的 refresh_token 停在原地，下一次只会报「登录已失效」。
                // 落盘失败也不改变本次错误 —— 用户该看到的是「AK 解析失败」。
                let saved =
                    store::save(ctx, account, &current, &next_secret(&current, &token, None)).await;
                if matches!(saved, Ok(true)) {
                    let _ = ctx.notify_auth_changed(super::ID, account).await;
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    let service_ak = resolved.as_deref().unwrap_or(&cred.service_ak);
    if service_ak.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "Meoo 项目服务 AK 为空，请重新登录或填写 AK",
        ));
    }
    let next = next_secret(&current, &token, resolved.as_deref());
    if !store::save(ctx, account, &current, &next).await? {
        // 比较再写失败 = 另一个刷新先落盘了。那不是错误：重读赢家，用它的 AK。
        let record = store::record(ctx, super::ID, account).await?;
        let winner = credentials::from_secret(&store::secret_view(&record));
        if !winner.service_ak.is_empty() {
            return Ok(winner.service_ak);
        }
        return Err(GatewayError::with_status(409, "Meoo 凭证刷新冲突，请重试"));
    }
    let _ = ctx.notify_auth_changed(super::ID, account).await;
    Ok(service_ak.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 与 [`credentials::should_refresh`] 同一口径的样本（5 分钟窗口）。
    fn credential(
        expires_at: i64,
        service_ak: &str,
        ak_project: &str,
    ) -> credentials::MeooCredentials {
        credentials::MeooCredentials {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_at,
            api_base: "https://meoo.com".into(),
            gateway_base: "https://api.meoo.host/meoo-ai/compatible-mode/v1".into(),
            project_url_id: "p".into(),
            service_ak: service_ak.into(),
            service_ak_project_id: ak_project.into(),
            user_id: "u".into(),
            username: "n".into(),
            allow_cloud_enable: false,
        }
    }

    #[test]
    fn should_refresh_uses_five_minute_margin() {
        let now = 1_000_000;
        let cred = credential(now + 4 * 60 * 1000, "meoo_project_service_v1.x", "p");
        assert!(credentials::should_refresh(&cred, now));
    }

    #[test]
    fn should_refresh_is_false_when_fresh_and_ak_valid() {
        // 规则：AK 有效 + 项目匹配 + access token 还新鲜 → 一次网络都不打
        let now = 1_000_000;
        let cred = credential(now + 30 * 60 * 1000, "meoo_project_service_v1.x", "p");
        assert!(!credentials::should_refresh(&cred, now));
    }

    #[test]
    fn should_refresh_when_ak_missing_or_project_mismatched() {
        let now = 1_000_000;
        let fresh = now + 30 * 60 * 1000;
        assert!(credentials::should_refresh(
            &credential(fresh, "", "p"),
            now
        ));
        // AK 属于别的项目：换项目之后必须重新解析
        assert!(credentials::should_refresh(
            &credential(fresh, "meoo_project_service_v1.x", "other"),
            now
        ));
    }

    #[test]
    fn should_refresh_ignores_unknown_expiry_with_valid_ak() {
        // expiresAt = 0 表示判不出来：不该因此每轮都去刷
        let now = 1_000_000;
        assert!(!credentials::should_refresh(
            &credential(0, "meoo_project_service_v1.x", "p"),
            now
        ));
    }

    #[test]
    fn next_secret_keeps_project_and_updates_tokens() {
        let current = json!({
            "accessToken": "old",
            "refreshToken": "old-r",
            "expiresAt": 1,
            "projectUrlId": "p1",
            "serviceAk": "meoo_project_service_v1.old",
            "serviceAkProjectId": "p1"
        });
        let token = crate::providers::meoo::oauth::TokenBundle {
            access_token: "new".into(),
            refresh_token: "new-r".into(),
            expires_in: 3600,
            scope: "cli.compat".into(),
            openid: "o".into(),
        };
        let next = next_secret(&current, &token, Some("meoo_project_service_v1.new"));
        assert_eq!(next["accessToken"], "new");
        assert_eq!(next["refreshToken"], "new-r");
        assert_eq!(next["projectUrlId"], "p1");
        assert_eq!(next["serviceAk"], "meoo_project_service_v1.new");
        assert_eq!(next["serviceAkProjectId"], "p1");
        assert_eq!(next["scope"], "cli.compat");
        assert_eq!(next["openid"], "o");
    }

    #[test]
    fn next_secret_keeps_scope_and_openid_when_response_omits_them() {
        // 续期响应没带 scope / openid 时保留旧值（省略 ≠ 作废）
        let current = json!({
            "accessToken": "old",
            "refreshToken": "old-r",
            "expiresAt": 1,
            "scope": "cli.compat",
            "openid": "old-openid"
        });
        let token = crate::providers::meoo::oauth::TokenBundle {
            access_token: "new".into(),
            refresh_token: String::new(),
            expires_in: 3600,
            scope: String::new(),
            openid: String::new(),
        };
        let next = next_secret(&current, &token, None);
        assert_eq!(next["accessToken"], "new");
        assert_eq!(next["refreshToken"], "old-r", "空 refresh 不能覆盖旧值");
        assert_eq!(next["scope"], "cli.compat");
        assert_eq!(next["openid"], "old-openid");
        // 没重新解析 AK 时原值原样保留
        assert_eq!(next["serviceAk"], current["serviceAk"]);
        assert!(next["expiresAt"].as_i64().unwrap_or(0) > 1);
    }

    #[tokio::test]
    async fn flight_table_single_flights_concurrent_callers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let table = Arc::new(flight::Table::<String>::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let leader_table = Arc::clone(&table);
        let leader_calls = Arc::clone(&calls);
        let leader = tokio::spawn(async move {
            match leader_table.join("k") {
                Join::Leader(guard) => {
                    leader_calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    guard.finish(Ok("v".to_string()));
                }
                Join::Waiter(waiter) => {
                    let _ = waiter.wait().await;
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let waiter_table = Arc::clone(&table);
        let waiter_calls = Arc::clone(&calls);
        let waiter = tokio::spawn(async move {
            match waiter_table.join("k") {
                Join::Leader(guard) => {
                    waiter_calls.fetch_add(1, Ordering::SeqCst);
                    guard.finish(Ok("v".to_string()));
                }
                Join::Waiter(waiter) => {
                    assert_eq!(waiter.wait().await.expect("应拿到 leader 结果"), "v");
                }
            }
        });

        leader.await.expect("leader");
        waiter.await.expect("waiter");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "同一 key 只应真实执行一次");
    }
}
