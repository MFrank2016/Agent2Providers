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
use agent2api_provider_sdk::{Provider, ProviderMeta};

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
}
