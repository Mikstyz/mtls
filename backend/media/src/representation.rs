pub(crate) fn file_type(name: &str) -> Option<&'static str> {
    match name {
        "original.jpg" | "preview.jpg" | "poster.jpg" | "poster-25.jpg" | "poster-60.jpg" => {
            Some("image/jpeg")
        }
        "original.png" | "preview.png" => Some("image/png"),
        "original.mp4" | "720p.mp4" | "1080p.mp4" | "1440p.mp4" | "2160p.mp4" => Some("video/mp4"),
        "adaptive.m3u8" | "720p.m3u8" | "1080p.m3u8" | "1440p.m3u8" | "2160p.m3u8" => {
            Some("application/vnd.apple.mpegurl")
        }
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
