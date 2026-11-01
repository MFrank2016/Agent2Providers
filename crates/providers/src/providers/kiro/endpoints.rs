//! Kiro 端点与 region 计算。三条 URL 规则见 spec 第 1 节。

/// Kiro CLI（API Key）的数据面。
pub fn api_key_base(region: &str) -> String {
    format!("https://runtime.{region}.kiro.dev/")
}

/// 默认 region（API Key 不带 `|region` 时用它）。
pub const DEFAULT_REGION: &str = "us-east-1";
