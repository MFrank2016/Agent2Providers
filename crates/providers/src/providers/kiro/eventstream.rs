//! AWS Event Stream（`vnd.amazon.eventstream`）增量解码。
//!
//! 帧结构：12 字节 prelude（总长 / 头长 / prelude CRC）+ headers +
//! payload + 4 字节 message CRC。Kiro 的 header 值只有 UTF-8 string
//! （类型标记 7）。CRC 不校验：TLS 已保护传输，坏帧会在 JSON 解析处失败。

/// prelude 字节数。
const PRELUDE_BYTES: usize = 12;
/// 尾部 message CRC 字节数。
const MESSAGE_CRC_BYTES: usize = 4;
/// header 值类型：UTF-8 string。
const HEADER_TYPE_STRING: u8 = 7;
/// 单帧上限（AWS 规定 16 MiB）；超过视为流错位。
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// 解出的一帧。
#[derive(Clone, Debug, PartialEq)]
pub struct KiroFrame {
    /// `:event-type` 的值（如 `assistantResponseEvent`）。
    pub event: String,
    /// `:message-type` 的值（`event` / `exception`）。
    pub message_type: String,
    /// 未解析的 payload（JSON 文本）。
    pub payload: String,
}

/// 增量解码器：喂字节，出完整帧；最后半帧留在内部。
#[derive(Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂一段字节，返回其中**完整**的帧。
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<KiroFrame>, String> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    /// 收尾：残留字节说明流被截断，必须报错而不是吐出半帧。
    pub fn finish(&self) -> Result<(), String> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Kiro 事件流在帧中途结束（残留 {} 字节）",
                self.buffer.len()
            ))
        }
    }

    fn next_frame(&mut self) -> Result<Option<KiroFrame>, String> {
        if self.buffer.len() < PRELUDE_BYTES {
            return Ok(None);
        }
        let total = read_u32(&self.buffer, 0) as usize;
        let headers_len = read_u32(&self.buffer, 4) as usize;
        if total > MAX_FRAME_BYTES {
            return Err(format!(
                "Kiro 事件流单帧超过 {MAX_FRAME_BYTES} 字节，流已错位"
            ));
        }
        let minimum = PRELUDE_BYTES + MESSAGE_CRC_BYTES;
        if total < minimum || headers_len > total - minimum {
            return Err("Kiro 事件流帧长度非法".to_string());
        }
        if self.buffer.len() < total {
            return Ok(None);
        }
        let frame: Vec<u8> = self.buffer.drain(..total).collect();
        let headers_end = PRELUDE_BYTES + headers_len;
        let payload_end = total - MESSAGE_CRC_BYTES;
        let headers = decode_headers(&frame, PRELUDE_BYTES, headers_end)?;
        Ok(Some(KiroFrame {
            event: headers.get(":event-type").cloned().unwrap_or_default(),
            message_type: headers.get(":message-type").cloned().unwrap_or_default(),
            payload: String::from_utf8_lossy(&frame[headers_end..payload_end]).to_string(),
        }))
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(raw)
}

fn decode_headers(
    frame: &[u8],
    mut offset: usize,
    end: usize,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut headers = std::collections::BTreeMap::new();
    while offset < end {
        if offset + 1 > end {
            return Err("Kiro 事件流 header 名长度越界".to_string());
        }
        let name_len = frame[offset] as usize;
        offset += 1;
        if offset + name_len + 3 > end {
            return Err("Kiro 事件流 header 名越界".to_string());
        }
        let name = String::from_utf8_lossy(&frame[offset..offset + name_len]).to_string();
        offset += name_len;
        let value_type = frame[offset];
        offset += 1;
        if value_type != HEADER_TYPE_STRING {
            return Err(format!(
                "Kiro 事件流 header `{name}` 的值类型 {value_type} 不受支持"
            ));
        }
        let value_len = u16::from_be_bytes([frame[offset], frame[offset + 1]]) as usize;
        offset += 2;
        if offset + value_len > end {
            return Err("Kiro 事件流 header 值越界".to_string());
        }
        headers.insert(
            name,
            String::from_utf8_lossy(&frame[offset..offset + value_len]).to_string(),
        );
        offset += value_len;
    }
    Ok(headers)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// 按 spec 第 2 节拼一帧（CRC 填 0，解码器不校验）。
    fn encode_frame(event: &str, message_type: &str, payload: &str) -> Vec<u8> {
        let mut headers = Vec::new();
        for (name, value) in [(":event-type", event), (":message-type", message_type)] {
            headers.push(name.len() as u8);
            headers.extend_from_slice(name.as_bytes());
            headers.push(7);
            headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
            headers.extend_from_slice(value.as_bytes());
        }
        let total = 12 + headers.len() + payload.len() + 4;
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&(total as u32).to_be_bytes());
        frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(&headers);
        frame.extend_from_slice(payload.as_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame
    }

    #[test]
    fn decodes_one_whole_frame() {
        let bytes = encode_frame("assistantResponseEvent", "event", r#"{"content":"hi"}"#);
        let mut decoder = FrameDecoder::new();
        let frames = decoder.push(&bytes).expect("应能解出一帧");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event, "assistantResponseEvent");
        assert_eq!(frames[0].payload, r#"{"content":"hi"}"#);
        assert!(decoder.finish().is_ok());
    }

    #[test]
    fn buffers_a_frame_split_across_chunks() {
        let bytes = encode_frame("assistantResponseEvent", "event", r#"{"content":"hello"}"#);
        let (head, tail) = bytes.split_at(7);
        let mut decoder = FrameDecoder::new();
        assert!(decoder.push(head).expect("半帧不应报错").is_empty());
        let frames = decoder.push(tail).expect("补齐后应解出");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, r#"{"content":"hello"}"#);
    }

    #[test]
    fn decodes_two_frames_in_one_chunk() {
        let mut bytes = encode_frame("a", "event", r#"{"n":1}"#);
        bytes.extend_from_slice(&encode_frame("b", "event", r#"{"n":2}"#));
        let mut decoder = FrameDecoder::new();
        let frames = decoder.push(&bytes).expect("应解出两帧");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].event, "b");
    }

    #[test]
    fn truncated_stream_is_an_error() {
        let bytes = encode_frame("a", "event", r#"{"n":1}"#);
        let mut decoder = FrameDecoder::new();
        assert!(decoder.push(&bytes[..10]).expect("半帧不报错").is_empty());
        assert!(decoder.finish().is_err(), "流在帧中途结束必须报错");
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut bytes = vec![0u8; 12];
        bytes[..4].copy_from_slice(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes());
        let mut decoder = FrameDecoder::new();
        assert!(decoder.push(&bytes).is_err());
    }
}
