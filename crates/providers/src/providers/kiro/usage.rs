//! Kiro 余额：`getUsageLimits` 归一化。
//!
//! ── 四类额度都要覆盖 ────────────────────────────────────────
//! 订阅窗口（`usageBreakdownList`）、新手试用（`freeTrialInfo`，仅 ACTIVE）、
//! 具名 bonus、购买的 overage。读不到的量留空而不是写 0 —— 与网关
//! 「读不到的数值留空显示，不是 0」的口径一致。

use serde_json::{json, Value};

use super::auth::KiroCredential;

/// 拉一次并归一。
pub async fn fetch(
    client: &reqwest::Client,
    cred: &KiroCredential,
) -> Result<Value, String> {
    let url = format!(
        "https://codewhisperer.{}.amazonaws.com/getUsageLimits\
         ?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true",
        cred.region
    );
    let headers = super::auth::auth_headers(cred);
    // `http::get_json` 返回 `(status, Value)`。
    let (status, payload) = crate::http::get_json(client, &url, &headers).await?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "Kiro 余额查询失败：HTTP {status} {}",
            head_of(&payload)
        ));
    }
    normalize(&payload)
}

/// 错误体前 240 字符（`get_json` 已把空体 / 非 JSON 归成 `Null`）。
fn head_of(payload: &Value) -> String {
    payload.to_string().chars().take(240).collect()
}

/// 把 `getUsageLimits` 的响应归一成网关认的形状。
pub fn normalize(payload: &Value) -> Result<Value, String> {
    let breakdowns = payload
        .get("usageBreakdownList")
        .and_then(Value::as_array)
        .ok_or_else(|| "Kiro 余额响应里没有 usageBreakdownList".to_string())?;

    let reset_at = payload
        .get("nextDateReset")
        .or_else(|| payload.get("resetDate"))
        .and_then(Value::as_i64)
        .map(|seconds| seconds * 1000);

    let mut windows = Vec::new();
    for item in breakdowns {
        let used = item
            .get("currentUsage")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let limit = item
            .get("usageLimitWithPrecision")
            .and_then(Value::as_i64)
            .or_else(|| item.get("usageLimit").and_then(Value::as_i64));
        let mut window = json!({
            "name": item
                .get("resourceType")
                .and_then(Value::as_str)
                .unwrap_or("订阅额度"),
            "used": used,
            "unit": "requests",
        });
        match limit {
            Some(limit) if limit > 0 => {
                window["limit"] = json!(limit);
            }
            // 无上限：标记而不是折算成 0
            _ => {
                window["unlimited"] = json!(true);
            }
        }
        if let Some(reset_at) = reset_at {
            window["resetsAt"] = json!(reset_at);
        }
        windows.push(window);
    }

    // 新手试用只在 ACTIVE 时算数
    if let Some(trial) = payload.get("freeTrialInfo") {
        let active = trial
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "ACTIVE");
        if active {
            windows.push(json!({
                "name": "新手试用",
                "used": trial.get("currentUsage").and_then(Value::as_i64).unwrap_or(0),
                "limit": trial.get("usageLimit").and_then(Value::as_i64),
                "unit": "requests",
            }));
        }
    }

    let plan = payload
        .get("subscriptionInfo")
        .and_then(|info| info.get("subscriptionTitle"))
        .and_then(Value::as_str)
        .unwrap_or("Kiro");

    Ok(json!({
        "plan": plan,
        "windows": windows,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn subscription_window_is_normalized() {
        let payload = json!({
            "usageBreakdownList": [{
                "resourceType": "AGENTIC_REQUEST",
                "usageLimit": 100,
                "currentUsage": 30
            }],
            "nextDateReset": 1_900_000_000,
            "subscriptionInfo": { "subscriptionTitle": "Kiro Pro" }
        });
        let report = normalize(&payload).expect("应能归一");
        assert_eq!(report["plan"], "Kiro Pro");
        assert_eq!(report["windows"][0]["used"], 30);
        assert_eq!(report["windows"][0]["limit"], 100);
    }

    #[test]
    fn unbounded_limit_is_marked_not_zero() {
        let payload = json!({
            "usageBreakdownList": [{ "resourceType": "AGENTIC_REQUEST", "currentUsage": 5 }]
        });
        let report = normalize(&payload).expect("应能归一");
        assert_eq!(report["windows"][0]["unlimited"], true);
        assert!(report["windows"][0].get("limit").is_none());
    }

    #[test]
    fn empty_breakdown_is_an_error() {
        assert!(normalize(&json!({})).is_err());
    }
}
