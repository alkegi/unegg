use encoding_rs::{EUC_KR, SHIFT_JIS};

/// Decode filename bytes. Without the area-code flag the name is UTF-8; with it,
/// `locale_code` selects a legacy code page (932=Shift-JIS, 949=EUC-KR).
pub fn decode_filename(use_area_code: bool, locale_code: Option<u16>, data: &[u8]) -> String {
    if !use_area_code {
        return String::from_utf8_lossy(data).into_owned();
    }

    let locale = locale_code.unwrap_or(0);
    let encoding = match locale {
        932 => SHIFT_JIS,
        949 | 0 => EUC_KR,
        _ => EUC_KR,
    };

    let (decoded, _, _) = encoding.decode(data);
    decoded.into_owned()
}

/// Normalize path separators to forward slash, strip leading slashes, and drop
/// control characters (NUL, terminal escapes, newlines) that a crafted archive
/// could smuggle into a filename.
pub fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches('/')
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_separators_and_controls() {
        assert_eq!(normalize_path("a\\b\\c"), "a/b/c");
        assert_eq!(normalize_path("/leading"), "leading");
        // NUL and a terminal escape sequence are dropped.
        assert_eq!(normalize_path("ev\0il\x1b[2J"), "evil[2J");
    }
}
