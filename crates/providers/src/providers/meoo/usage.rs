//! Meoo 积分：`/account/points` + `/account/entitlement`。
//!
//! ── 为什么控制面走 OAuth token 而不是项目服务 AK ─────────────
//! 积分 / 权益 / 身份都是「账号级」信息，上游认的是 **OAuth access token**
//! （见 `control.rs` 模块头）。项目服务 AK 只对模型网关有效，拿它查积分必然 401。
//!
//! ── 手动 AK 账号查不了积分 ─────────────────────────────────
//! 手动粘贴 `meoo_project_service_v1.*` 的账号没有 OAuth 身份（`refreshToken`
//! 为空），既没有可用的控制面 Bearer，也没有可续期的令牌。这里给一句**可操作**
//! 的 400，告诉用户去用「浏览器登录」加账号 —— 而不是发一个空 Bearer 让上游
//! 回 401「登录已失效」，那会把人引向「重新登录」却不知道要换登录方式。
//!
//! ── 一条**必须**遵守的契约：读不到余额就不要写 `available` ──────
//! 限额判定走 `core::usage_records::extract_remaining`：`available` 一旦出现
//! 就会被当成真实读数。没有读数时写 `available: 0`，等于告诉限制器「余额为 0」，
//! 账号会被标成「余额不足 / 已跳过」（atomcode 2026-10-17 栽过）。所以
//! [`shape`] 只在**确实解析出** `availableBalance` 时才写 `available` 与
//! `wallets`，其余情况留空让界面显示「未知」。
//!
//! ── 主读数失败就整条失败，附加读数只降级 ──────────────────────
//! `/points` 是用户问的那个数，失败必须如实报错；`/entitlement`（套餐名）与
//! `/identity`（个人版/团队版）只是附加说明，抖动时降级成 `null`，不能把一个
//! 可用的余额读数拖成红色失败。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use serde_json::{json, Value};

use agent2api_provider_sdk::PluginCtx;

use crate::errors::GatewayError;
use crate::store;

use super::{control, credentials, endpoints, refresh};

/// 提前续期的窗口：access token 剩不到 1 分钟就先换一张。
///
/// 余额查询是一次短请求，1 分钟足够覆盖往返；窗口取太大只会让每次查积分都
/// 顺带轮换一次 refresh_token。
const REFRESH_MARGIN_MS: i64 = 60 * 1000;

/// 读一个数字（上游有把数字序列化成字符串的形态，两种都认）。
fn number(value: Option<&Value>) -> Option<f64> {
    let value = value?;
    if let Some(number) = value.as_f64() {
        return Some(number);
    }
    value
        .as_str()
        .and_then(|text| text.trim().parse::<f64>().ok())
}

/// 把读数变成 JSON 数字：整数值保持整数形态（`1234` 而不是 `1234.0`）。
///
/// 积分通常是整数，序列化成浮点会让界面显示 `1234.0`，也会让
/// `value["available"] == 1234` 这类按整数比较的断言落空。
fn amount(value: f64) -> Value {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        Value::from(value as i64)
    } else {
        Value::from(value)
    }
}

/// 按顺序取第一个**非空字符串**字段。
///
/// 不用 `or_else` 直接串：`planName: null` / `planName: ""` 时 `or_else` 已经
/// 选中了这个键，后面的 `planCode` 就永远读不到。
fn text<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    })
}

/// 把 `/points` + `/entitlement` + `/identity` 归成网关认的额度形状（纯函数）。
///
/// 形状（键名照抄别家，界面按这套键读）：
/// ```text
///   { available?, unit, plan, wallets: [{type, displayName, balance}],
///     credits: [{name, remain}], raw: {points, entitlement} }
/// ```
/// 契约见模块头：没有 `availableBalance` 就不写 `available` / `wallets`。
pub fn shape(points: &Value, entitlement: &Value, identity: &Value) -> Value {
    // `control::*` 已经拆过 `data` 信封；再认一层 `account` 是为了兼容
    // 「`data.account` 与 `data` 本身就是余额」两种上游形态。
    let account = points.get("account").unwrap_or(points);
    let available = number(account.get("availableBalance"));
    let total_granted = number(account.get("totalGranted"));
    let total_consumed = number(account.get("totalConsumed"));
    let total_expired = number(account.get("totalExpired"));
    // 套餐名：`planName` → `planCode` → 身份里的 `edition`，都没有就留空串
    // （界面按「没读到」渲染，而不是显示一个编出来的套餐）。
    let plan = text(entitlement, &["planName", "planCode"])
        .or_else(|| text(identity, &["edition"]))
        .unwrap_or("")
        .to_string();

    let mut credits = Vec::new();
    if let Some(value) = available {
        credits.push(json!({"name":"可用积分","remain":amount(value)}));
    }
    if let Some(value) = total_granted {
        credits.push(json!({"name":"累计获得","remain":amount(value)}));
    }
    if let Some(value) = total_consumed {
        credits.push(json!({"name":"累计消耗","remain":amount(value)}));
    }
    // 过期一栏只在真的有过期积分时出现：恒为 0 的一行只会占位。
    if let Some(value) = total_expired.filter(|value| *value > 0.0) {
        credits.push(json!({"name":"已过期","remain":amount(value)}));
    }
    let wallets = available
        .map(|value| {
            vec![json!({
                "type": "meoo_points",
                "displayName": "秒悟积分",
                "balance": amount(value),
            })]
        })
        .unwrap_or_default();
    let mut report = json!({
        "unit": "积分",
        "plan": plan,
        "wallets": wallets,
        "credits": credits,
        "raw": {"points": points, "entitlement": entitlement},
    });
    if let Some(value) = available {
        if let Some(object) = report.as_object_mut() {
            object.insert("available".into(), amount(value));
        }
    }
    report
}

/// 这个 access token 该不该先续期。
///
/// `expiresAt = 0` 表示判不出来 —— 与 [`credentials::should_refresh`] 同一口径，
/// **不算**临期：宁可让上游回 401（有明确文案），也不要每查一次积分就轮换一次
/// refresh_token。
fn token_expiring(cred: &credentials::MeooCredentials, now: i64) -> bool {
    cred.access_token.is_empty()
        || (cred.expires_at > 0 && cred.expires_at - now < REFRESH_MARGIN_MS)
}

/// 查积分：读账号 → （必要时）续期 → 并发读 points/entitlement → 归一。
pub async fn query(ctx: &PluginCtx, account: &str) -> Result<Value, GatewayError> {
    let record = store::record(ctx, super::ID, account).await?;
    let cred = credentials::from_secret(&store::secret_view(&record));
    if cred.refresh_token.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "该 Meoo 账号只有项目服务 AK，无法查询积分；请用「浏览器登录」添加账号",
        ));
    }
    let api_base = if cred.api_base.is_empty() {
        endpoints::api_base()
    } else {
        cred.api_base.clone()
    };
    let access_token = if token_expiring(&cred, crate::http::now_ms()) {
        // 只刷一轮（与网关「401 后重试一次」同一条约定）。这里**不**把续期
        // 错误直接上抛：续期顺带要解析项目服务 AK，而查积分并不需要 AK ——
        // 一个没开通云服务的账号 AK 解析必然失败，但它的积分是查得到的。
        // 令牌真失效时下面的 `/points` 会给出准确的 401，不必提前报错。
        let refreshed = refresh::ensure_service_ak(ctx, account, true).await;
        let record = store::record(ctx, super::ID, account).await?;
        let next = credentials::from_secret(&store::secret_view(&record));
        if next.access_token.is_empty() {
            return Err(refreshed.err().unwrap_or_else(|| {
                GatewayError::with_status(
                    401,
                    "Meoo 账号没有 OAuth 访问令牌，请用「浏览器登录」重新添加账号",
                )
            }));
        }
        next.access_token
    } else {
        cred.access_token.clone()
    };
    let (points, entitlement) = tokio::join!(
        control::points(ctx, &api_base, &access_token),
        control::entitlement(ctx, &api_base, &access_token)
    );
    // 主读数：失败即失败（用户问的就是这个数）。
    let points = points?;
    let entitlement = match entitlement {
        Ok(value) => value,
        Err(error) => {
            agent2api_provider_sdk::log_info!(
                "[Usage] Meoo 权益未取到（积分照常返回）：{}",
                error.message_of()
            );
            Value::Null
        }
    };
    let identity = match control::identity(ctx, &api_base, &access_token).await {
        Ok(value) => value,
        Err(error) => {
            agent2api_provider_sdk::log_info!(
                "[Usage] Meoo 身份未取到（积分照常返回）：{}",
                error.message_of()
            );
            Value::Null
        }
    };
    Ok(shape(&points, &entitlement, &identity))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes_personal_points() {
        let value = shape(
            &json!({"account":{"availableBalance":1234,"totalGranted":2000,"totalConsumed":766}}),
            &json!({"planName":"Pro"}),
            &json!({"edition":"personal"}),
        );
        assert_eq!(value["available"], 1234);
        assert_eq!(value["plan"], "Pro");
        assert_eq!(value["credits"][0]["name"], "可用积分");
    }

    #[test]
    fn numeric_strings_are_accepted() {
        let value = shape(
            &json!({"account":{"availableBalance":"1234.5","totalGranted":"2000","totalConsumed":"765.5"}}),
            &Value::Null,
            &Value::Null,
        );
        assert_eq!(value["available"], 1234.5);
        assert_eq!(value["wallets"][0]["balance"], 1234.5);
        assert_eq!(value["wallets"][0]["type"], "meoo_points");
        assert_eq!(value["wallets"][0]["displayName"], "秒悟积分");
    }

    #[test]
    fn omits_available_when_balance_missing() {
        // 读不到余额时不能写 available: 0（限制器会当成「余额为 0」）
        let value = shape(&json!({"account": {}}), &Value::Null, &Value::Null);
        assert!(value.get("available").is_none());
        assert_eq!(value["wallets"], json!([]));
        assert_eq!(value["unit"], "积分");
    }

    #[test]
    fn accepts_bare_points_object() {
        // `data` 本身就是余额（没有 `account` 一层）时也要读得到
        let value = shape(&json!({"availableBalance": 7}), &Value::Null, &Value::Null);
        assert_eq!(value["available"], 7);
    }

    #[test]
    fn expired_credit_only_when_positive() {
        let zero = shape(
            &json!({"account":{"availableBalance":1,"totalExpired":0}}),
            &Value::Null,
            &Value::Null,
        );
        assert!(!zero["credits"]
            .as_array()
            .map(|items| items.iter().any(|item| item["name"] == "已过期"))
            .unwrap_or(true));

        let positive = shape(
            &json!({"account":{"availableBalance":1,"totalExpired":20}}),
            &Value::Null,
            &Value::Null,
        );
        assert!(positive["credits"]
            .as_array()
            .map(|items| items.iter().any(|item| item["name"] == "已过期"))
            .unwrap_or(false));
    }

    #[test]
    fn plan_falls_back_to_code_then_edition() {
        let by_code = shape(
            &json!({"account":{"availableBalance":1}}),
            &json!({"planCode":"pro_code"}),
            &Value::Null,
        );
        assert_eq!(by_code["plan"], "pro_code");

        let by_edition = shape(
            &json!({"account":{"availableBalance":1}}),
            &Value::Null,
            &json!({"edition":"personal"}),
        );
        assert_eq!(by_edition["plan"], "personal");

        // planName 是空串时不能被它挡住 planCode
        let blank_name = shape(
            &json!({"account":{"availableBalance":1}}),
            &json!({"planName":"  ","planCode":"pro_code"}),
            &Value::Null,
        );
        assert_eq!(blank_name["plan"], "pro_code");
    }

    #[test]
    fn raw_keeps_upstream_payloads() {
        let points = json!({"account":{"availableBalance":1}});
        let entitlement = json!({"planName":"Pro"});
        let value = shape(&points, &entitlement, &Value::Null);
        assert_eq!(value["raw"]["points"], points);
        assert_eq!(value["raw"]["entitlement"], entitlement);
    }

    #[test]
    fn token_expiring_uses_one_minute_margin() {
        let mut cred = credentials::from_secret(&json!({
            "accessToken": "a",
            "refreshToken": "r",
            "expiresAt": 1_000_000
        }));
        assert!(!token_expiring(&cred, 1_000_000 - 120_000));
        assert!(token_expiring(&cred, 1_000_000 - 30_000));
        // 空 token 一定续期
        cred.access_token.clear();
        assert!(token_expiring(&cred, 1_000_000 - 120_000));
        // expiresAt = 0 = 判不出来：不当作临期
        cred.access_token = "a".into();
        cred.expires_at = 0;
        assert!(!token_expiring(&cred, 1_000_000));
    }
}
