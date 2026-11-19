//! AutoClaw 网页登录的**流程编排**：借登记端口、等浏览器回调、换码，把结果放进
//! 流程表，网关按 `pollIntervalMs` 来问。
//!
//! ── 为什么是轮询型而不是回调型 ──────────────────────────────
//! 协议里 `poll_interval_ms > 0` 的含义是「**网关主动问插件要结果**」，与授权在
//! 哪里终结无关。本家的回调打在**插件自己**的 loopback 端口上，永远不经过网关
//! 的 `/api/session/login/callback` —— 报 `0` 的话网关会一直挂着等一个不会到来
//! 的回调，没有任何报错。这与 Accio / Trae / CatPaw 是同一处置。
//!
//! ── 两条入口，一张表 ────────────────────────────────────────
//! ```text
//!   浏览器直达   授权页 302 → 插件占的登记端口 → 本文件的监听器
//!   远程面板     用户把地址栏整条 URL 粘回 → login.oauth-callback 管理动作
//! ```
//! 两条都只投递「变体 + 查询串」，换码逻辑只有一份（[`finish`]）。
//!
//! ── 为什么发起走管理动作而不是 `login.start` ──────────────────
//! 取授权地址（第 ② 步）**需要前端跑完阿里云 SDK 得到的 `ali_captcha_verify_param`**，
//! 而 `login.start` 在网关侧是固定空 payload（见 `RpcAdapter::login_start_async`）。
//! 所以第 ② 步走 `login.oauth-start`，由网关把前端的验证码参数原样转发进来。
//!
//! ── 端口一个都抢不到时 ──────────────────────────────────────
//! 如实报错并让用户先退出 AutoClaw 桌面客户端：Zai 的 redirect_uri 白名单只认
//! 那四个端口，抢不到就没有任何可用的回调落点（网关侧那条「内嵌窗口改道」的
//! 兜底已随实现一起移除 —— 网关不再持有任何 AutoClaw 的回调路由）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 本 crate 编译期禁止 unwrap/expect/panic。

use std::sync::{Arc, Mutex, OnceLock};

use agent2api_provider_protocol as proto;
use serde_json::{json, Value};

use crate::errors::GatewayError;
use crate::logging;

use super::callback_server::CallbackListener;
use super::credentials;
use super::oauth::{self, Vendor};
use super::region::Region;

/// 流程 id 前缀（便于日志与排障时指认）
const FLOW_PREFIX: &str = "autoclaw-web-";

/// 轮询间隔：回调是本机的（延迟极低），1 秒足够且不会让界面觉得卡。
const POLL_INTERVAL_MS: u64 = 1_000;

/// 一轮登录在进程内的状态。
enum FlowState {
    /// 授权地址已给出，等浏览器回调。
    Waiting,
    /// 拿到 code，正在换码。
    Working,
    /// 换好了（存的是扁平凭证，落库时再 `account_from_credentials`）。
    Done(Value),
    /// 这一轮没成。
    Failed(String),
}

struct Entry {
    region: Region,
    vendor: Vendor,
    navigate_uri: String,
    device_id: String,
    listener: Arc<CallbackListener>,
    state: FlowState,
}

fn flows() -> &'static Mutex<std::collections::HashMap<String, Entry>> {
    static FLOWS: OnceLock<Mutex<std::collections::HashMap<String, Entry>>> = OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn with_flows<T>(action: impl FnOnce(&mut std::collections::HashMap<String, Entry>) -> T) -> T {
    match flows().lock() {
        Ok(mut table) => action(&mut table),
        Err(poisoned) => action(&mut poisoned.into_inner()),
    }
}

/// 收掉所有未完成的流程（新一轮发起前调用）：端口不释放的话，这一轮的回调可能
/// 落到上一轮的监听器上（授权码一次性，两轮并存等于让其中一轮必输）。
fn close_all() {
    let entries: Vec<Arc<CallbackListener>> =
        with_flows(|table| table.drain().map(|(_, entry)| entry.listener).collect());
    for listener in entries {
        listener.close();
    }
}

/// 这一轮 `navigate_uri` 的基址。本地形态用占到的登记端口；远程形态用网关
/// 自己的 loopback 地址（Google 宽松匹配可过，Zai 在 `remote_zai_error` 里
/// 提前拒绝）。`bound_port = None` 表示没占到端口，本地形态也回落网关地址。
fn oauth_callback_base(local_browser: bool, navigate_base: &str, bound_port: Option<u16>) -> String {
    if !local_browser {
        return navigate_base.trim_end_matches('/').to_string();
    }
    match bound_port {
        Some(port) => format!("http://localhost:{port}"),
        None => navigate_base.trim_end_matches('/').to_string(),
    }
}

/// 远程形态下 Zai 无法完成（回调白名单只认本机四个登记端口），提前拒绝。
fn remote_zai_error(vendor: Vendor, local_browser: bool) -> Option<&'static str> {
    if !local_browser && vendor == Vendor::Zai {
        return Some("当前部署形态下网关不在浏览器所在的机器上，Zai 登录无法完成 —— 请改用 Google 登录，或用「填写凭证」/「导入桌面端登录态」");
    }
    None
}

/// 发起一次网页登录：借登记端口 → 取授权地址 → 登记流程 → 起后台收尾。
///
/// 返回 `(flow, auth_url)`。
pub(super) async fn start_oauth(
    region: Region,
    vendor: Vendor,
    captcha_verify_param: &str,
    local_browser: bool,
    navigate_base: &str,
) -> Result<(String, String), GatewayError> {
    if let Some(reason) = remote_zai_error(vendor, local_browser) {
        return Err(GatewayError::with_status(400, reason));
    }
    close_all();
    let device_id = oauth::new_oauth_device_id();
    let (sender, inbox) = tokio::sync::mpsc::unbounded_channel();
    let (listener, bound_port) = if local_browser {
        match CallbackListener::bind(sender.clone()).await {
            Ok(listener) => {
                let p = listener.port();
                (Arc::new(listener), Some(p))
            }
            Err(reason) => {
                logging::log("[Login]", &format!("⚠️ {reason}"));
                // 与旧版一致：占不到端口时 Google 回落网关地址，不把能走的路弄坏。
                if vendor == Vendor::Zai {
                    return Err(GatewayError::with_status(
                        400,
                        format!("{reason}；请退出 AutoClaw 桌面客户端后重试"),
                    ));
                }
                (Arc::new(CallbackListener::channel_only(sender.clone())), None)
            }
        }
    } else {
        (Arc::new(CallbackListener::channel_only(sender.clone())), None)
    };
    let base = oauth_callback_base(local_browser, navigate_base, bound_port);
    let navigate = oauth::navigate_uri(&base, vendor);
    let auth_url =
        oauth::request_oauth_url(region, vendor, &navigate, captcha_verify_param, &device_id).await?;
    let state = random_hex()?;
    let flow = format!("{FLOW_PREFIX}{state}");
    with_flows(|table| {
        table.insert(
            flow.clone(),
            Entry {
                region,
                vendor,
                navigate_uri: navigate.clone(),
                device_id,
                listener: Arc::clone(&listener),
                state: FlowState::Waiting,
            },
        );
    });
    spawn_completion(flow.clone(), listener, inbox);
    logging::log(
        "[Login]",
        &format!(
            "发起 AutoClaw {} {}网页登录（等浏览器回调 {navigate}）",
            region.label(),
            vendor.label()
        ),
    );
    Ok((flow, auth_url))
}

/// 后台那半个登录：等回调 → 换码 → 落状态。
fn spawn_completion(
    flow: String,
    listener: Arc<CallbackListener>,
    mut inbox: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    tokio::spawn(async move {
        let Some(payload) = inbox.recv().await else {
            return;
        };
        let (region, vendor, navigate_uri, device_id) = {
            let found = with_flows(|table| {
                table.get(&flow).map(|entry| {
                    (
                        entry.region,
                        entry.vendor,
                        entry.navigate_uri.clone(),
                        entry.device_id.clone(),
                    )
                })
            });
            let Some(found) = found else {
                // 表里已经没有这条（用户取消 / 网关超时后清理过）
                return;
            };
            found
        };
        let (callback_vendor, query) = split_delivery(&payload);
        // 粘贴进来的回调带变体，必须与这一轮一致；不一致说明用户贴错了
        if let Some(callback_vendor) = callback_vendor {
            if callback_vendor != vendor.id() {
                finish_flow(
                    &flow,
                    Err(format!(
                        "回调属于 {}，与本次 {} 登录不一致，请重新发起",
                        callback_vendor,
                        vendor.label()
                    )),
                );
                listener.close();
                return;
            }
        }
        with_flows(|table| {
            if let Some(entry) = table.get_mut(&flow) {
                entry.state = FlowState::Working;
            }
        });
        let outcome =
            finish(region, vendor, &navigate_uri, &device_id, &query).await;
        finish_flow(&flow, outcome.map_err(|error| error.message));
        listener.close();
    });
}

/// 投递形态：`{vendor}|{query}`。裸查询串（用户粘贴）没有前缀。
fn split_delivery(payload: &str) -> (Option<String>, String) {
    match payload.split_once('|') {
        Some((vendor, query)) => (Some(vendor.to_string()), query.to_string()),
        None => (None, payload.to_string()),
    }
}

/// 用回调 query 换码，产出可落库的扁平凭证。
async fn finish(
    region: Region,
    vendor: Vendor,
    navigate_uri: &str,
    device_id: &str,
    query: &str,
) -> Result<Value, GatewayError> {
    let params: std::collections::HashMap<String, String> = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (percent_decode(key), percent_decode(value)))
        .collect();
    if let Some(error) = params.get("error").filter(|value| !value.trim().is_empty()) {
        return Err(GatewayError::with_status(
            400,
            format!("授权被拒绝（{error}）"),
        ));
    }
    let code = params.get("code").map(String::as_str).unwrap_or("").trim();
    if code.is_empty() {
        return Err(GatewayError::with_status(400, "回调没有携带授权码"));
    }
    // 查询串里的 state 是**上游生成的**那个（换码要回传它），不是我们的 flow。
    // 粘贴路径可能只剩 code（网关的 `login.callback` 只抽出 code 参数），
    // 此时传空串 —— 官方客户端同样是 `searchParams.get("state") || ""`。
    let upstream_state = params.get("state").map(String::as_str).unwrap_or("");
    let mut credentials = oauth::exchange_code(
        region,
        vendor,
        code,
        upstream_state.trim(),
        navigate_uri,
        device_id,
    )
    .await?;
    // 邮箱：换回来的 token 里没有它（JWT 只有 user_id / device_id / guid），
    // 而账号在列表上得认得出是谁。best-effort：查不到照常建账号。
    if let Ok(parsed) = credentials::credentials_from_record(&credentials, region) {
        let email = super::profile::email_or_empty(&parsed, "网页登录").await;
        if !email.is_empty() {
            if let Some(object) = credentials.as_object_mut() {
                object.insert("email".to_string(), Value::String(email));
            }
        }
    }
    Ok(credentials)
}

fn finish_flow(flow: &str, outcome: Result<Value, String>) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow) {
            entry.state = match outcome {
                Ok(credentials) => FlowState::Done(credentials),
                Err(message) => FlowState::Failed(message),
            };
        }
    });
}

/// 轮询一次登录进度。
pub(super) async fn login_poll(flow: &str) -> Result<proto::LoginPoll, String> {
    let result = with_flows(|table| match table.get(flow) {
        Some(entry) => Some(match &entry.state {
            FlowState::Waiting => proto::LoginPoll::Pending {
                hint: Some("等待你在浏览器里完成授权…".to_string()),
            },
            FlowState::Working => proto::LoginPoll::Pending {
                hint: Some("已收到授权码，正在换取登录态…".to_string()),
            },
            FlowState::Done(credentials) => {
                match super::login::account_from_credentials(entry.region, credentials.clone()) {
                    Ok(account) => proto::LoginPoll::Done { account },
                    Err(error) => proto::LoginPoll::Failed {
                        message: error.message,
                    },
                }
            }
            FlowState::Failed(message) => proto::LoginPoll::Failed {
                message: message.clone(),
            },
        }),
        None => None,
    });
    match result {
        Some(result) => {
            let terminal = matches!(
                result,
                proto::LoginPoll::Done { .. } | proto::LoginPoll::Failed { .. }
            );
            if terminal {
                let listener = with_flows(|table| table.remove(flow).map(|entry| entry.listener));
                if let Some(listener) = listener {
                    listener.close();
                }
            }
            Ok(result)
        }
        None => Ok(proto::LoginPoll::Failed {
            message: "这次登录流程已失效（插件进程重启过？），请重新发起".to_string(),
        }),
    }
}

/// 取消一轮登录：收监听器（释放端口）并清掉那一条。
pub(super) async fn login_cancel(flow: &str) -> Result<(), String> {
    let listener = with_flows(|table| table.remove(flow).map(|entry| entry.listener));
    if let Some(listener) = listener {
        listener.close();
    }
    Ok(())
}

/// 把用户粘贴的回调输入归一成 `(变体, 原始查询串)`。
///
/// `query` 必须是**未解码**的原始查询串：`finish()` 那边负责百分号解码，
/// 与真实 HTTP 回调（`callback_server`）投进流程表的形态逐字一致。
///
/// ── 四种输入形态（都与真实链路对得上）──────────────────────
///   ① 完整回调 URL：`http://localhost:18432/auth/callback-google?code=…&state=…`
///      —— 网页面板 `waitForManualCallback` 让用户复制地址栏整条 URL 粘回来，
///      这是最常见的一型。旧实现只 `strip_prefix("/auth/callback-")`，认不出它，
///      于是把整条 URL 当裸查询串，`code` 键变成 `http://…?code`，报「没有授权码」。
///   ② 以回调路径开头的半截：`/auth/callback-zai?code=…`
///   ③ 裸查询串：`?code=…&state=…` 或 `code=…&state=…`
///   ④ 裸授权码：原样透传，由 `submit_callback` 拼成 `code=<text>`
///
/// 认不出 ①/②/③ 时按 ④ 处理（透传原文），不在这里抢着判错 —— 是 URL 还是
/// 裸码由 `submit_callback` 按有没有 `code=` 决定，职责不重叠。
///
/// 变体只在 ①/② 里从路径末段取（`zai` / `google`）；③/④ 没有变体，由调用方
/// 拿流程表里的变体兜底 —— 与真实回调那条路（`{vendor}|{query}`）同一口径。
fn parse_callback_input(text: &str) -> (Option<String>, String) {
    let trimmed = text.trim();
    // ①/②：带 scheme 的完整 URL 或以 `/auth/callback-` 开头的半截地址。
    // 用 `Url::parse` 只解 scheme/host/path，查询串**另取原始切片**（`query()`
    // 返回的就是未解码的那一段），绝不 `query_pairs()` 重新拼 —— 否则百分号
    // 会被提前吃掉，与 `finish()` 的解码叠成两次。
    let as_url = if trimmed.contains("://") {
        url::Url::parse(trimmed).ok()
    } else if trimmed.starts_with(oauth::CALLBACK_PATH_PREFIX) {
        // ② 没有 scheme：挂一个占位 origin 让 `Url` 解析路径与原始 query。
        url::Url::parse(&format!("http://localhost{trimmed}")).ok()
    } else {
        None
    };
    if let Some(url) = as_url {
        let path = url.path();
        if let Some(vendor) = path.strip_prefix(oauth::CALLBACK_PATH_PREFIX) {
            if !vendor.is_empty() {
                let query = url.query().unwrap_or("").to_string();
                return (Some(vendor.to_string()), query);
            }
        }
        // 是 URL 但路径不是回调路径：不当作回调（按裸串透传，由调用方决定）。
    }
    // ③ 裸查询串：去掉开头的 `?`，其余原样（前导 `?` 不是查询串的一部分）。
    if let Some(stripped) = trimmed.strip_prefix('?') {
        return (None, stripped.to_string());
    }
    // ④ 裸授权码（或已无前导 `?` 的裸查询串）：原样透传。
    (None, trimmed.to_string())
}

/// 用户手工粘贴回调地址（远程面板形态：浏览器到不了插件所在机器的 loopback）。
///
/// 接受四种输入：完整回调 URL、以回调路径开头的地址、裸查询串、裸授权码 ——
/// 网关的 `login.callback` 只抽出 `code` 参数给我们，因此第四种必须支持（变体与
/// `navigate_uri` 都从流程表里取，不需要 URL 提供）。
pub(super) async fn submit_callback(flow: &str, payload: &str) -> Result<(), String> {
    let entry = with_flows(|table| {
        table
            .get(flow)
            .filter(|entry| matches!(entry.state, FlowState::Waiting))
            .map(|entry| (entry.vendor, entry.listener.clone()))
    });
    let Some((vendor, listener)) = entry else {
        return Err("这次登录已取消或已过期，请重新发起".to_string());
    };
    let text = payload.trim();
    if text.is_empty() {
        return Err("回调地址为空".to_string());
    }
    let (delivery_vendor, query) = try_callback_delivery(vendor.id(), text)?;
    listener
        .deliver(&format!("{delivery_vendor}|{query}"))
        .map_err(|_| "AutoClaw 登录任务已结束，请重新发起".to_string())
}

/// 把一次粘贴输入折成要投递的 `(变体, 原始查询串)`，并在投递前拦下坏输入。
///
/// `vendor_id` 是**这一轮流程**的变体（取自流程表）；输入自带变体时（完整 URL /
/// 路径形式）必须与它一致，否则说明用户贴错了上一轮的回调。
fn try_callback_delivery(vendor_id: &str, input: &str) -> Result<(String, String), String> {
    let (vendor_from_input, mut query) = parse_callback_input(input);
    if let Some(from_input) = vendor_from_input {
        if !from_input.is_empty() && from_input != vendor_id {
            return Err(format!("回调属于 {from_input}，与本次 {vendor_id} 登录不一致"));
        }
    }
    // 纯函数认不出 URL/查询串时，剩下的就是裸授权码 —— 拼成 `code=<text>`。
    // 判据与 `finish()` 的解析口径一致（有没有 `code=`/`error=`）。
    if !query.contains("code=") && !query.contains("error=") {
        query = format!("code={query}");
    }
    let params: std::collections::HashMap<String, String> = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    let has_code = params
        .get("code")
        .is_some_and(|value| !value.trim().is_empty());
    let has_error = params
        .get("error")
        .is_some_and(|value| !value.trim().is_empty());
    if !has_code && !has_error {
        return Err("回调地址没有携带 AutoClaw 授权码".to_string());
    }
    Ok((vendor_id.to_string(), query))
}

/// 32 位小写 hex 随机串（一次性流程 id 用；安全用途，必须用密码学随机源）。
fn random_hex() -> Result<String, GatewayError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| GatewayError::with_status(502, "无法生成安全的登录随机串"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod callback_input_vectors {
    //! 远程面板粘贴回调地址的四种真实输入形态。
    //!
    //! 证据出处：`web_shim.rs::waitForManualCallback` 让用户「复制浏览器地址栏
    //! 中的完整回调地址粘贴提交」，POST 到 `login.oauth-callback` 的 `url` 字段
    //! 就是那条完整 URL。旧实现只 `strip_prefix("/auth/callback-")`，对
    //! `http://localhost:18432/auth/callback-google?code=…` 不匹配，于是把整条
    //! URL 当裸查询串，按 `&`/`=` 拆出的键变成
    //! `http://localhost:18432/auth/callback-google?code`，`params.get("code")`
    //! 为 `None` —— 用户明明完成了授权，界面却报「回调地址没有携带授权码」。
    //!
    //! 这里钉住：`finish()` 拿到的必须是**原始查询串**（未解码），与真实 HTTP
    //! 回调投进流程表的形态逐字一致。

    use super::parse_callback_input;
    use super::try_callback_delivery;

    /// 完整 URL：`http://localhost:<登记端口>/auth/callback-google?code=…&state=…`
    #[test]
    fn a_full_loopback_url_yields_its_vendor_and_raw_query() {
        let (vendor, query) = parse_callback_input(
            "http://localhost:18432/auth/callback-google?code=4%2F0AcA&state=upstream-xyz",
        );
        assert_eq!(Some("google".to_string()), vendor);
        assert_eq!("code=4%2F0AcA&state=upstream-xyz", query);
    }

    /// 127.0.0.1 形态（浏览器把 localhost 解析成 IPv4 时地址栏会是这样）。
    #[test]
    fn a_full_ipv4_loopback_url_is_also_a_callback() {
        let (vendor, query) = parse_callback_input(
            "http://127.0.0.1:18432/auth/callback-google?code=abc%2Bdef&state=s1",
        );
        assert_eq!(Some("google".to_string()), vendor);
        assert_eq!("code=abc%2Bdef&state=s1", query);
    }

    /// 以回调路径开头、没有 scheme 的那半截 URL（旧实现唯一认得的形态）。
    #[test]
    fn a_path_only_callback_still_yields_its_vendor_and_query() {
        let (vendor, query) =
            parse_callback_input("/auth/callback-zai?code=z1&state=s1");
        assert_eq!(Some("zai".to_string()), vendor);
        assert_eq!("code=z1&state=s1", query);
    }

    /// 裸查询串（网关把完整 URL 抽成 `?code=…` 后传进来）。
    #[test]
    fn a_bare_query_string_has_no_vendor_but_keeps_every_param() {
        let (vendor, query) = parse_callback_input("?code=c1&state=s1");
        assert_eq!(None, vendor);
        assert_eq!("code=c1&state=s1", query);
    }

    /// 边界契约：完整 URL 必须被投递成 `{vendor}|{原始查询串}`，而不是把整条
    /// URL 当裸串。旧实现在这里产出 `google|<整条 URL>`，`finish()` 随后报
    /// 「回调没有携带授权码」。
    #[test]
    fn a_full_url_is_delivered_as_vendor_plus_raw_query_not_as_the_whole_url() {
        assert_eq!(
            Ok((
                "google".to_string(),
                "code=4%2F0AcA&state=upstream-xyz".to_string()
            )),
            try_callback_delivery(
                "google",
                "http://localhost:18432/auth/callback-google?code=4%2F0AcA&state=upstream-xyz",
            )
        );
    }

    /// 裸授权码：拼成 `code=<text>`，变体从流程表兜底。
    #[test]
    fn a_bare_code_is_delivered_under_the_flows_vendor() {
        assert_eq!(
            Ok(("google".to_string(), "code=4/0AcA_plain".to_string())),
            try_callback_delivery("google", "4/0AcA_plain")
        );
    }

    /// 裸查询串：去掉前导 `?`，其余（含百分号）原样投递。
    #[test]
    fn a_bare_query_string_is_delivered_without_its_leading_question_mark() {
        assert_eq!(
            Ok(("zai".to_string(), "code=c%2B1&state=s1".to_string())),
            try_callback_delivery("zai", "?code=c%2B1&state=s1")
        );
    }

    /// 变体不一致必须拦下：用户把上一轮 Zai 的回调贴进了这一轮 Google 登录。
    #[test]
    fn a_mismatched_vendor_is_rejected_before_delivery() {
        let result = try_callback_delivery(
            "google",
            "http://localhost:18432/auth/callback-zai?code=c1&state=s1",
        );
        assert!(result.is_err(), "贴错变体不能静默按本轮变体换码");
    }

    /// 没有 code 也没有 error 的输入必须在投递前被拒绝。
    #[test]
    fn an_input_without_code_or_error_is_rejected() {
        let result = try_callback_delivery("google", "http://localhost:18432/auth/callback-google");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod remote_oauth_vectors {
    use super::super::callback_server::REGISTERED_CALLBACK_PORTS;
    use super::super::oauth::Vendor;
    use super::{oauth_callback_base, remote_zai_error};

    #[test]
    fn remote_google_uses_the_gateway_base_without_binding_a_registered_port() {
        let base = oauth_callback_base(false, "http://localhost:3065", None);
        assert_eq!("http://localhost:3065", base);
        assert!(
            !REGISTERED_CALLBACK_PORTS
                .iter()
                .any(|p| base.contains(&p.to_string())),
            "远程形态不得把回调指向登记端口"
        );
    }
    #[test]
    fn local_browser_still_binds_the_registered_port() {
        let base = oauth_callback_base(true, "http://localhost:3065", Some(18432));
        assert_eq!("http://localhost:18432", base);
    }
    #[test]
    fn remote_zai_is_rejected_before_any_port_is_bound() {
        assert!(remote_zai_error(Vendor::Zai, false).is_some());
    }
    #[test]
    fn remote_google_is_allowed() {
        assert!(remote_zai_error(Vendor::Google, false).is_none());
    }
    #[test]
    fn local_zai_is_allowed() {
        assert!(remote_zai_error(Vendor::Zai, true).is_none());
    }
    #[test]
    fn missing_local_browser_defaults_to_local() {
        // 缺省按 true：由 mod.rs 的 `unwrap_or(true)` 实现，这里钉住纯函数的
        // 本地分支在无 bound_port 时也不去猜登记端口，行为与老调用一致。
        assert_eq!(
            "http://localhost:3065",
            oauth_callback_base(true, "http://localhost:3065", None)
        );
    }

    /// 远程形态没有端口监听器，但用户粘贴的完整回调必须仍能投进流程表，
    /// 且投递值 = `{vendor}|{原始查询串}`（缺陷 #1 修的正是这条解析）。
    #[test]
    fn remote_flow_accepts_a_pasted_full_url() {
        use super::super::callback_server::CallbackListener;
        use super::super::oauth::{self, Vendor};
        use super::super::region::Region;
        use super::{with_flows, submit_callback, Entry, FlowState};
        use std::sync::Arc;

        let (sender, mut inbox) = tokio::sync::mpsc::unbounded_channel();
        let listener = Arc::new(CallbackListener::channel_only(sender));
        let flow = "autoclaw-web-test-remote".to_string();
        let navigate = oauth::navigate_uri("http://localhost:3065", Vendor::Google);
        with_flows(|table| {
            table.insert(
                flow.clone(),
                Entry {
                    region: Region::Intl,
                    vendor: Vendor::Google,
                    navigate_uri: navigate,
                    device_id: "deadbeef".to_string(),
                    listener: Arc::clone(&listener),
                    state: FlowState::Waiting,
                },
            );
        });
        // submit_callback 声明为 async，但函数体内没有任何 .await 点；
        // `futures::executor::block_on` 直接驱动它到完成，不必起 tokio runtime。
        let submitted = futures::executor::block_on(submit_callback(
            &flow,
            "http://localhost:3065/auth/callback-google?code=4%2F0AcA&state=upstream-xyz",
        ));
        assert!(submitted.is_ok(), "提交应成功：{submitted:?}");
        let delivered = inbox.try_recv();
        assert_eq!(
            Ok("google|code=4%2F0AcA&state=upstream-xyz".to_string()),
            delivered
        );
        with_flows(|table| {
            table.remove(&flow);
        });
        listener.close();
    }
}

/// 百分号解码（`+` 在查询串里按空格处理）。
fn percent_decode(input: &str) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    let raw = input.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'%' if index + 2 < raw.len() => {
                let hex = &input[index + 1..index + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        bytes.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        bytes.push(raw[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                bytes.push(b' ');
                index += 1;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 供管理动作复用：把 `{state, authUrl, pollIntervalMs}` 组装成网关要的形状。
///
/// `pollIntervalMs` 必须给：这条链的回调落在**插件自己**的登记端口上，网关不会
/// 收到任何 `/api/session/login/callback` —— 只报地址不报间隔，界面就会一直挂着
/// 等一个永远不会到来的跳转（没有任何报错，是最难查的一类失败）。
pub(super) fn start_payload(flow: &str, auth_url: &str) -> Value {
    json!({
        "state": flow,
        "authUrl": auth_url,
        "pollIntervalMs": POLL_INTERVAL_MS,
    })
}
