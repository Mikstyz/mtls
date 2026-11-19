pub(crate) fn file_type(name: &str) -> Option<&'static str> {
    if name.is_empty()
        || name.len() > 128
        || name.contains("..")
        || name.starts_with('.')
        || !name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
    {
        return None;
    }

    match name.rsplit_once('.')?.1 {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "webp" => Some("image/webp"),
        "avif" => Some("image/avif"),
        "mp4" => Some("video/mp4"),
        "webm" => Some("video/webm"),
        "m3u8" => Some("application/vnd.apple.mpegurl"),
        "m4s" => Some("video/iso.segment"),
        "ts" => Some("video/mp2t"),
        _ => None,
    }
}

pub(crate) fn byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    if value.len() > 128 || size == 0 || value.contains(',') {
        return None;
    }

    let (first, last) = value.strip_prefix("bytes=")?.split_once('-')?;

    if first.is_empty() {
        let suffix = decimal(last)?;
        if suffix == 0 {
            return None;
        }
        return Some((size.saturating_sub(suffix), size - 1));
    }

    let start = decimal(first)?;
    if start >= size {
        return None;
    }
    let end = if last.is_empty() {
        size - 1
    } else {
        decimal(last)?.min(size - 1)
    };
    if end < start {
        return None;
    }
    Some((start, end))
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    value.parse().ok()
}
