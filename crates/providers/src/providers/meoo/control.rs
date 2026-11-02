//! Meoo 控制面：identity / projects / cloud environment / points / entitlement。
//!
//! ── 控制面走 OAuth token，不走项目服务 AK ────────────────────
//! 这五条链路都是「账号级」信息，上游认的是 **OAuth access token**；
//! 项目服务 AK（`meoo_project_service_v1.*`）只对模型网关有效。两套 Bearer
//! 由 `headers.rs` 分别构造，本文件一律用 [`headers::control_headers`]。
//!
//! ── 响应信封：`data` 可能不在 ────────────────────────────────
//! 上游多数接口是 `{"data": {...}}`，但也有直接返回对象的。取值一律走
//! [`data_of`]（没有 `data` 就整份当数据），这样「某接口换了信封」不会把
//! 成功读成空。
//!
//! ── 项目服务 AK 从云环境里解析 ──────────────────────────────
//! [`resolve_service_ak`] 先读 `/projects/{id}/cloud/environment` 的
//! `meooProjectApiKey`（或在 `instance` 里）；**只有**调用方显式允许
//! （`allow_cloud_enable`）且确实没有时，才 POST `/cloud` 开通云服务再读一次。
//! 默认不开通：开通是有副作用的写操作，不能因为「登录顺手」就替用户做掉。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

// ── 为什么整份 `allow(dead_code)` ───────────────────────────
// 本模块先于 `login.rs` / `refresh.rs` / `mod.rs` 的接线落地（Task 5 才接入
// `normalize_account`），此刻还没有调用方。删掉等于让接线那一步重写一遍
// 控制面查询 —— 而这五条链路的信封口径正是最容易写歪的部分。
#![allow(dead_code)]

use serde_json::Value;

use agent2api_provider_sdk::PluginCtx;

use crate::errors::GatewayError;
use crate::http;

use super::{endpoints, headers};

/// 响应信封里的业务数据：有 `data` 取 `data`，没有就整份当数据。
fn data_of(payload: &Value) -> Value {
    payload
        .get("data")
        .cloned()
        .unwrap_or_else(|| payload.clone())
}

/// 响应信封里的上游文案（`detail` / `message` / `error.message` 三种都认）。
fn message_of(payload: &Value) -> String {
    payload
        .get("detail")
        .or_else(|| payload.get("message"))
        .or_else(|| payload.get("error").and_then(|error| error.get("message")))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// 发一次控制面 GET 并返回信封里的 `data`。
///
/// 401 原样上抛（上层据此判「登录态失效」），其余非 2xx 一律归 502 ——
/// 控制面故障不该被当成「该重新登录」，否则用户会被反复踢去授权。
async fn get_json(
    ctx: &PluginCtx,
    url: &str,
    access_token: &str,
    what: &str,
) -> Result<Value, GatewayError> {
    let client = http::client(None, &ctx.env.proxy);
    let (status, payload) = http::get_json(&client, url, &headers::control_headers(access_token))
        .await
        .map_err(|error| GatewayError::with_status(502, format!("{what}失败：{error}")))?;
    if !(200..300).contains(&status) {
        return Err(GatewayError::with_status(
            if status == 401 { 401 } else { 502 },
            format!("{what}失败（HTTP {status}）：{}", message_of(&payload)),
        ));
    }
    Ok(data_of(&payload))
}

/// 控制面身份（`data` 对象；`data` 缺失时整份返回）。
pub async fn identity(
    ctx: &PluginCtx,
    api_base: &str,
    access_token: &str,
) -> Result<Value, GatewayError> {
    get_json(
        ctx,
        &endpoints::identity_url(api_base),
        access_token,
        "Meoo 身份查询",
    )
    .await
}

/// 项目列表：认 `list` / `items` / `projects` 三种字段名，也认裸数组。
pub async fn list_projects(
    ctx: &PluginCtx,
    api_base: &str,
    access_token: &str,
) -> Result<Vec<Value>, GatewayError> {
    let data = get_json(
        ctx,
        &endpoints::projects_url(api_base),
        access_token,
        "Meoo 项目列表",
    )
    .await?;
    let list = data
        .get("list")
        .or_else(|| data.get("items"))
        .or_else(|| data.get("projects"))
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| data.as_array().cloned())
        .unwrap_or_default();
    Ok(list)
}

/// 按顺序取第一个**非空字符串**字段（`url_id` / `urlId` / `id` 这类改名容错）。
fn text_of<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    })
}

/// 项目列表 → 只读摘要（`{"projects": [{"urlId", "name"}]}`）。
///
/// 上游条目里还有环境、密钥、额度等字段，原样透出等于把控制面响应搬进网关
/// 接口 —— 这里**只**保留 `urlId` / `name` 两个字段，其余一律丢弃。没有名字
/// 时用 `urlId` 兜底（界面至少能显示一行可点的项目，而不是空白）。
///
/// 纯函数：不读账号、不发请求，便于把「哪些字段能出网关」这条边界测死。
pub fn project_summaries(projects: &[Value]) -> Value {
    let items = projects
        .iter()
        .filter_map(|item| {
            let url_id = text_of(item, &["url_id", "urlId", "id"])?;
            let name = text_of(item, &["name", "title"]).unwrap_or(url_id);
            Some(serde_json::json!({ "urlId": url_id, "name": name }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({ "projects": items })
}

/// 解析某个项目的服务 AK（`meoo_project_service_v1.*`）。
///
/// `allow_cloud_enable` 为真且环境里还没有 AK 时才 POST `/cloud` 开通；
/// 开通后仍拿不到就返回 400 的可操作文案（告诉用户去哪儿开通）。
pub async fn resolve_service_ak(
    ctx: &PluginCtx,
    api_base: &str,
    access_token: &str,
    project: &str,
    allow_cloud_enable: bool,
) -> Result<String, GatewayError> {
    let read = |payload: &Value| -> String {
        payload
            .get("meooProjectApiKey")
            .or_else(|| {
                payload
                    .get("instance")
                    .and_then(|value| value.get("meooProjectApiKey"))
            })
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let environment = get_json(
        ctx,
        &endpoints::environment_url(api_base, project),
        access_token,
        "Meoo 项目环境查询",
    )
    .await?;
    let mut ak = read(&environment);
    if ak.is_empty() && allow_cloud_enable {
        let client = http::client(None, &ctx.env.proxy);
        let (status, payload) = http::post_json(
            &client,
            &endpoints::cloud_url(api_base, project),
            &headers::control_headers(access_token),
            &serde_json::json!({ "description": "agent2api: meoo provider" }),
        )
        .await
        .map_err(|error| GatewayError::with_status(502, format!("Meoo 云服务开通失败：{error}")))?;
        if !(200..300).contains(&status) {
            return Err(GatewayError::with_status(
                502,
                format!(
                    "Meoo 云服务开通失败（HTTP {status}）：{}",
                    message_of(&payload)
                ),
            ));
        }
        let environment = get_json(
            ctx,
            &endpoints::environment_url(api_base, project),
            access_token,
            "Meoo 项目环境查询",
        )
        .await?;
        ak = read(&environment);
    }
    if ak.is_empty() {
        return Err(GatewayError::with_status(
            400,
            format!(
                "项目 {project} 还没有开通 Meoo AI 服务：请在 Meoo 打开该项目 → 云服务 开通，\
                 或重新登录并勾选「自动开通」"
            ),
        ));
    }
    if !ak.starts_with("meoo_project_service_v1.") {
        return Err(GatewayError::with_status(
            401,
            "Meoo 返回的项目服务 AK 格式不正确，请重新登录或联系 Meoo",
        ));
    }
    Ok(ak)
}

/// 积分余额（`data` 对象）。
pub async fn points(
    ctx: &PluginCtx,
    api_base: &str,
    access_token: &str,
) -> Result<Value, GatewayError> {
    get_json(
        ctx,
        &endpoints::points_url(api_base),
        access_token,
        "Meoo 积分查询",
    )
    .await
}

/// 账号权益（`data` 对象）。
pub async fn entitlement(
    ctx: &PluginCtx,
    api_base: &str,
    access_token: &str,
) -> Result<Value, GatewayError> {
    get_json(
        ctx,
        &endpoints::entitlement_url(api_base),
        access_token,
        "Meoo 权益查询",
    )
    .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn project_summaries_accept_three_id_spellings() {
        let value = project_summaries(&[
            json!({"url_id": "p1", "name": "项目一"}),
            json!({"urlId": "p2", "name": "项目二"}),
            json!({"id": "p3", "name": "项目三"}),
        ]);
        assert_eq!(
            value["projects"],
            json!([
                {"urlId": "p1", "name": "项目一"},
                {"urlId": "p2", "name": "项目二"},
                {"urlId": "p3", "name": "项目三"},
            ])
        );
    }

    #[test]
    fn project_summaries_fall_back_to_url_id_and_drop_idless_rows() {
        let value = project_summaries(&[
            json!({"url_id": "p1"}),
            json!({"url_id": "p2", "name": "   "}),
            json!({"name": "没有 id 的项目"}),
            json!({"url_id": "p3", "name": "项目三", "serviceAk": "meoo_project_service_v1.secret"}),
        ]);
        assert_eq!(
            value["projects"],
            json!([
                {"urlId": "p1", "name": "p1"},
                {"urlId": "p2", "name": "p2"},
                {"urlId": "p3", "name": "项目三"},
            ])
        );
        // 上游其余字段（密钥 / 环境 / 额度）一个都不能漏出去
        assert!(!value.to_string().contains("meoo_project_service_v1"));
    }

    #[test]
    fn project_summaries_of_empty_list_is_empty_envelope() {
        assert_eq!(project_summaries(&[]), json!({"projects": []}));
    }
}
