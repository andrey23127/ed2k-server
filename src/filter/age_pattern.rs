//! Layer 2: age token + sexual context co-occurrence (SPEC.md §7.6.2).
//!
//! Catches the pattern that defeated AND-only filters: filenames with a
//! numeric age (0-17) plus a sexual-context word in any of several languages.

/// Age regex as a hand-rolled scanner (avoids pulling in the `regex` crate
/// for one pattern; this is in the OFFERFILES hot path).
///
/// Matches: optional digit + age suffix in {yo, yr, year, años, let, jahr},
/// where age is 0-17.
fn contains_minor_age_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find a digit
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Need a word boundary before the digit (start, or non-alphanumeric)
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            i += 1;
            continue;
        }
        // Read 1-2 digit number
        let start = i;
        let mut age: u32 = 0;
        let mut digits = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() && digits < 2 {
            age = age * 10 + (bytes[i] - b'0') as u32;
            i += 1;
            digits += 1;
        }
        if age > 17 {
            continue;
        }
        // Optional whitespace/separator (just spaces for now)
        let after_digits = i;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        // Look for age suffix
        let rest = &s[i..];
        let suffixes = [
            "yo", "y.o", "y.o.", "yr", "yrs", "year", "years",
            "años", "ano", "anos",
            "let", "letnia",
            "jahr", "jährig", "jahrige",
            "лет", "года", "год",
            // CJK / Korean age suffixes (e.g. "13歳", "13才", "13세").
            // Non-Latin — no FP risk inside Latin words. A digit 0-17 directly
            // followed by one of these is an explicit minor-age claim.
            "歳", "才", "세", "歲",
            // School-grade suffixes that imply a minor: Japanese "年生"
            // (e.g. "小学6年生"), Korean "학년" (e.g. "6학년").
            "年生", "学年", "학년",
        ];
        let mut matched = false;
        for suffix in &suffixes {
            if rest.to_lowercase().starts_with(*suffix) {
                // Check word boundary AFTER suffix
                let suffix_end = i + suffix.len();
                if suffix_end == bytes.len() || !is_word_char(bytes[suffix_end]) {
                    matched = true;
                    break;
                }
            }
        }
        if matched {
            return true;
        }
        // No match - reset and continue scanning
        i = if after_digits > start { after_digits } else { i + 1 };
    }
    false
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Sexual-context vocabulary (multi-language, see SPEC.md §7.6.2).
/// Lowercased substrings — match anywhere in filename.
///
/// Long, unique terms (≥5 chars or non-Latin): always substring match.
/// These cannot reasonably appear inside innocent English/Russian words.
const SEX_TERMS_SUBSTRING: &[&str] = &[
    // English (5+ chars, specific)
    "porn", "blowjob", "dildo", "orgasm", "masturbat",
    // German
    "sexuell", "ficken",
    // Spanish/Portuguese (5+ chars)
    "porno", "follar", "desnud",
    // Italian
    "sesso",
    // Russian (Cyrillic — no FP risk in Latin filenames)
    "секс", "порн", "голая", "обнаж",
    // French
    "sexe",
    // CJK / Korean exploitation-specific terms (non-Latin → no Latin-word FP).
    // These denote sexual exploitation; chosen to be specific rather than broad
    // (we do NOT add generic adult terms that legal JAV uses).
    "援助交際",   // enjo-kosai full form (compensated dating w/ minors)
    "원조교제",   // Korean equivalent
    "ロリ",       // "loli" (katakana) — paired with minor-age token in L2
    "幼女",       // "young girl" (prepubescent) — strong CSAM marker
    "近親相姦",   // incest (full form, specific)
    "강간",       // rape (Korean)
    "レイプ",     // rape (katakana)
];

/// Short ambiguous terms — require WORD BOUNDARIES on both sides.
/// Without this, "oral" matches "moral"/"temporal", "anal" matches
/// "analysis"/"anaconda", "nud" matches anything ending in "nud-",
/// "sex" matches "Sussex"/"unisex", causing massive false positives when
/// combined with age tokens like "16 yo behavioral analysis study.pdf".
const SEX_TERMS_WORD_BOUNDED: &[&str] = &[
    "sex", "xxx", "fuck", "nude", "naked", "anal", "oral", "cum",
    "nackt",        // German
    "nud", "scopa", // Italian
];

/// Returns true if `lowered` contains a substring sex term OR a word-bounded short term.
fn contains_sex_term(lowered: &str) -> bool {
    if SEX_TERMS_SUBSTRING.iter().any(|t| lowered.contains(t)) {
        return true;
    }
    let bytes = lowered.as_bytes();
    for term in SEX_TERMS_WORD_BOUNDED {
        let tb = term.as_bytes();
        let mut start = 0;
        while let Some(pos) = lowered[start..].find(term) {
            let abs = start + pos;
            let before_ok = abs == 0 || !is_word_char(bytes[abs - 1]);
            let after_idx = abs + tb.len();
            let after_ok = after_idx == bytes.len() || !is_word_char(bytes[after_idx]);
            if before_ok && after_ok {
                return true;
            }
            start = abs + 1;
        }
    }
    false
}

pub(super) fn matches_layer2(original: &str, lowered: &str) -> bool {
    // Both conditions must hold in same filename.
    (contains_minor_age_token(original) || contains_school_grade_marker(original))
        && contains_sex_term(lowered)
}

/// Detect Japanese/Korean lower-school grade markers where the grade number
/// follows the school prefix: "中1" (JHS yr1 ≈ 12-13yo), "小6" (elementary yr6),
/// "중1"/"초6" (Korean). These are minor-age claims that the digit+suffix
/// scanner misses because the digit comes AFTER the marker, not before.
/// Elementary (小/초) any grade, and junior-high (中/중) grades 1-3 (≈12-15yo)
/// are minors. We do NOT match 高 (high school) — can include 18yo.
fn contains_school_grade_marker(s: &str) -> bool {
    let prefixes = ["小", "초", "中", "중"];
    for p in prefixes {
        let mut from = 0;
        while let Some(rel) = s[from..].find(p) {
            let abs = from + rel;
            let after = abs + p.len();
            // Next char must be a grade digit 1-6.
            if let Some(c) = s[after..].chars().next() {
                if let Some(d) = c.to_digit(10) {
                    if (1..=6).contains(&d) {
                        return true;
                    }
                }
            }
            from = abs + p.len();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_yo() {
        assert!(contains_minor_age_token("Some Movie 8yo Foo.mp4"));
        assert!(contains_minor_age_token("8 yo bar"));
        assert!(contains_minor_age_token("12yr something"));
        assert!(contains_minor_age_token("10 year old"));
    }

    #[test]
    fn ignores_non_age_numbers() {
        assert!(!contains_minor_age_token("Linux 2024 release.iso"));
        assert!(!contains_minor_age_token("MP3 192kbps.mp3"));
        assert!(!contains_minor_age_token("v1.2.3.zip"));
    }

    #[test]
    fn ignores_adult_ages() {
        assert!(!contains_minor_age_token("woman 30 years old.mp4"));
        assert!(!contains_minor_age_token("25yo cat photo"));
    }

    #[test]
    fn boundary_check() {
        // "boyo" should NOT match "yo" with age "bo" - we require digit
        assert!(!contains_minor_age_token("playing.mp4"));
        // "report 2024.pdf" - 2024 is too big for minor age
        assert!(!contains_minor_age_token("report 2024.pdf"));
    }

    #[test]
    fn layer2_combined() {
        // Real attack pattern observed in capture (sanitized):
        let lowered = "[xxx] 8yo movie.mp4".to_lowercase();
        assert!(matches_layer2("[xxx] 8yo movie.mp4", &lowered));
    }

    #[test]
    fn layer2_innocent_age_no_sex() {
        // "12 Years a Slave" - 12 is in age range but no sex term
        let s = "12 Years a Slave (2013).mkv";
        let l = s.to_lowercase();
        assert!(!matches_layer2(s, &l));
    }

    #[test]
    fn layer2_sex_no_minor_age() {
        // Adult content - no minor age - should not match
        let s = "30yo-mature-adult.mp4";
        let l = s.to_lowercase();
        assert!(!matches_layer2(s, &l));
    }

    // ── False-positive regression tests (root cause of 60043 CSAM blocks bug) ──
    // Short ambiguous sex terms (anal/oral/nud) were matching as substrings of
    // common innocent words (analysis/moral/Nudity-the-statue) and combined with
    // legitimate age tokens (14 years, 16 yo) caused mass false-positive blocks.

    #[test]
    fn layer2_fp_analysis_with_age() {
        let s = "16 yo behavioral analysis study.pdf";
        let l = s.to_lowercase();
        assert!(!matches_layer2(s, &l),
                "FALSE POSITIVE: 'analysis' contains 'anal' substring");
    }

    #[test]
    fn layer2_fp_years_analysis() {
        let s = "14 years analysis report.pdf";
        let l = s.to_lowercase();
        assert!(!matches_layer2(s, &l));
    }

    #[test]
    fn layer2_fp_moral_with_age() {
        let s = "10 year old corporate moral handbook.pdf";
        let l = s.to_lowercase();
        assert!(!matches_layer2(s, &l),
                "FALSE POSITIVE: 'moral' contains 'oral' substring");
    }

    #[test]
    fn layer2_fp_anaconda_movie() {
        // Common movie filename with "anaconda" which contains "anac" but not "anal" — should pass
        // Test that "12 year old anaconda" doesn't FP
        let s = "12 year old anaconda documentary.mp4";
        let l = s.to_lowercase();
        // "anaconda" contains "ana" but not "anal" so should NOT match the word-bounded "anal" term
        assert!(!matches_layer2(s, &l));
    }

    #[test]
    fn cjk_age_suffixes_detected() {
        // Japanese 歳/才, Korean 세 — digit 0-17 + suffix = minor age token.
        assert!(contains_minor_age_token("動画 13歳 something.mp4"));
        assert!(contains_minor_age_token("13才 video"));
        assert!(contains_minor_age_token("13세 clip.avi"));
        // Adult ages must NOT match.
        assert!(!contains_minor_age_token("25歳 woman.mp4"));
        assert!(!contains_minor_age_token("30세 adult.mp4"));
    }

    #[test]
    fn school_grade_markers_detected() {
        assert!(contains_school_grade_marker("中1 something"));   // JHS yr1
        assert!(contains_school_grade_marker("小6 video"));        // elem yr6
        assert!(contains_school_grade_marker("중1 clip"));         // KR JHS yr1
        assert!(contains_school_grade_marker("초6 file"));         // KR elem yr6
        // High-school marker (高) must NOT match — can include 18yo.
        assert!(!contains_school_grade_marker("高3 video"));
        // Grade > 6 must not match (out of elementary/JHS range).
        assert!(!contains_school_grade_marker("中9 random"));
    }

    #[test]
    fn cjk_exploitation_context_combined() {
        // Real attack pattern from production (sanitized to structure only):
        // minor-age claim + CJK exploitation context.
        let s = "Jap Loli 13歳 援助交際 video.avi";
        assert!(matches_layer2(s, &s.to_lowercase()));
        let s2 = "中1 ロリ clip.mp4"; // grade marker + katakana loli
        assert!(matches_layer2(s2, &s2.to_lowercase()));
    }

    #[test]
    fn cjk_fp_legit_jav_with_adult_age() {
        // Legal adult JAV with adult age + generic content — must NOT match.
        let s = "Kokoro Wato FC2 PPV 18歳 debut.mp4";
        assert!(!matches_layer2(s, &s.to_lowercase()),
                "FP: adult age 18 must not trigger");
        // Chinese film with episode/year numbers, no minor-age, no sex term.
        let s2 = "陈壮壮 第13集 高清.mp4";
        assert!(!matches_layer2(s2, &s2.to_lowercase()));
    }
}
