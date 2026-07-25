//! Layer 2: age token + sexual context co-occurrence (SPEC.md §7.6.2).
//!
//! Catches the pattern that defeated AND-only filters: filenames with a
//! numeric age (0-17) plus a sexual-context word in any of several languages.

/// Age regex as a hand-rolled scanner (avoids pulling in the `regex` crate
/// for one pattern; this is in the OFFERFILES hot path).
///
/// Matches: optional digit + age suffix in {yo, yr, year, años, let, jahr},
/// where age is 0-17.
/// Age 0 is never written as an age in a filename — it is volume/episode
/// numbering ("Ep 0Y"). Age 1 IS used in real material, so the lower bound stops
/// at 1 and the "1 Year 83 Cumshots" class of false positive is handled by the
/// counter guard below instead of by a blunt bound.
const MIN_AGE: u32 = 1;

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
        // Upper bound: 18+ is not a minor. Lower bound excludes 0, which in
        // practice is only ever episode/volume numbering — live false positive:
        // "XConfessions Vol. 26 Ep 0Y".
        if !(MIN_AGE..=17).contains(&age) {
            continue;
        }
        // Bare "y" suffix, ONLY when directly attached to the digits ("12y",
        // "15y"). Evidenced live: "BroSis G12 B15 12y Sis Blows 15y Bro" carried
        // four minor ages and none was recognised, because "y" alone was not a
        // suffix. Requiring NO space is what makes this safe: Spanish "y" means
        // "and", so "Ana 15 y Maria" would otherwise read as an age token.
        if i < bytes.len() && (bytes[i] | 0x20) == b'y' {
            let after_y = i + 1;
            if after_y == bytes.len() || !is_word_char(bytes[after_y]) {
                return true;
            }
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
            // NOTE: bare "let" was REMOVED. Czech/Slovak "15 let" (= years) is a
            // real age form, but "let" is also an extremely common English verb,
            // and the scanner only requires a word boundary after it. Live FP:
            // "Classic XXX - Vegas 3 Let It Ride (1990)" — a 1990 adult film with
            // adult performers — parsed "3 Let" as "3 years" and, combined with
            // the "xxx" sex term, was wrongly blocked. The inflected Slavic forms
            // below are unambiguous and keep most of the coverage.
            "letnia", "letni", "letech", "letý", "leta",
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
        let rest_lower = rest.to_lowercase();
        for suffix in &suffixes {
            if rest_lower.starts_with(*suffix) {
                // Check word boundary AFTER suffix
                let suffix_end = i + suffix.len();
                if suffix_end == bytes.len() || !is_word_char(bytes[suffix_end]) {
                    // "3 years ago" is a time span, not somebody's age. Live false
                    // positive: an FC2-PPV title reading "From About 3 Years Ago,
                    // My ...". Same for the other languages we already accept an
                    // age suffix in.
                    let tail = rest_lower[suffix.len()..].trim_start();
                    if tail.starts_with("ago")
                        || tail.starts_with("назад")
                        || tail.starts_with("temu")
                        || tail.starts_with("前")
                    {
                        continue;
                    }
                    // A SPELLED-OUT unit followed by another number is a count, not
                    // an age: "1 Year 83 Cumshots" is a compilation spanning a year.
                    // Restricted to the word forms on purpose — the abbreviated ones
                    // are routinely followed by a year of capture ("12yo 2013 cam"),
                    // which must still register as an age.
                    let spelled = matches!(
                        *suffix,
                        "year" | "years" | "año" | "años" | "ano" | "anos"
                            | "jahr" | "лет" | "года" | "год"
                    );
                    if spelled && tail.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        continue;
                    }
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


/// Gender-tagged age pairs: "G12 B15", "g13 b15", "B08 G16".
///
/// A single "B12" is far too weak to act on — it is a vitamin, a bomber, a bus
/// route, a chess opening. What is not ambiguous is a PAIR of them in one
/// filename, which is a naming convention used to label the two children in a
/// video. Requiring two independent tokens is what keeps this false-positive
/// free; combined with L2's mandatory sex term it is a very specific signal.
///
/// Evidenced live (all passed every layer before this):
///   "mov family BroSis G12 B15 - 12y Sis Blows 15y Bro"
///   "mov family BroSis B08 G16 - 16y girl fuck with her 8y bro"
fn count_gender_age_tokens(s: &str) -> usize {
    let b = s.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i] | 0x20; // ASCII-lowercase
        if (c == b'g' || c == b'b') && (i == 0 || !is_word_char(b[i - 1])) {
            let mut j = i + 1;
            let mut age: u32 = 0;
            let mut digits = 0;
            while j < b.len() && b[j].is_ascii_digit() && digits < 2 {
                age = age * 10 + (b[j] - b'0') as u32;
                j += 1;
                digits += 1;
            }
            // 1-2 digits, a minor age, and a word boundary after the number.
            if digits > 0 && age <= 17 && (j == b.len() || !is_word_char(b[j])) {
                count += 1;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    count
}

/// CJK words that state a minor age directly, rather than as digits.
///
/// These are ordinary words, not community jargon, so they are safe to match as
/// substrings in a non-Latin script (no risk of hitting an English word).
///
/// ⚠ DO NOT ADD 女子校生 / 女子高生 ("high-school girl"). That is a mainstream
///   GENRE TAG of legal Japanese adult video, performed by adults over 18 — it
///   appears in catalogued studio releases (e.g. Moodyz MIGD-398, S1, Madonna).
///   Adding it would mass-block a legal category. Junior-high (中学生, 12-15) and
///   elementary (小学生, 6-12) carry no such adult-genre usage, which is why only
///   those are listed. The same reasoning already governs 高 in
///   `contains_school_grade_marker`.
const CJK_MINOR_WORDS: &[&str] = &[
    "中学生",   // junior high (12-15)
    "中學生",   // ditto, traditional
    "初中生",   // junior high (mainland usage)
    "小学生",   // elementary (6-12)
    "小學生",   // ditto, traditional
    "未成年",   // "minor" (legal term), zh/ja
    "미성년",   // ditto, Korean
    "중학생",   // junior high, Korean
    "초등학생", // elementary, Korean
];

fn contains_cjk_minor_word(s: &str) -> bool {
    CJK_MINOR_WORDS.iter().any(|w| s.contains(w))
}

pub(super) fn matches_layer2(original: &str, lowered: &str) -> bool {
    // Both conditions must hold in the same filename: an age claim AND a sexual
    // context. Neither alone is actionable — a 12-year-old's birthday video is
    // not CSAM, and adult pornography is not our concern.
    let age_claim = contains_minor_age_token(original)
        || contains_school_grade_marker(original)
        || contains_cjk_minor_word(original)
        || count_gender_age_tokens(original) >= 2;
    age_claim && contains_sex_term(lowered)
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

    // ── Regression tests from live production data (2026-07) ─────────────
    // Every string below is a REAL filename observed on the server. The blocked
    // ones passed all filter layers before this revision; the allowed ones were
    // wrongly blocked by it.

    #[test]
    fn regression_numbering_and_timespans_are_not_ages() {
        // Live false positives from the 2026-07-23 review, all legal content.
        // Episode/volume numbering read as an age of 0:
        assert!(!contains_minor_age_token(
            "[Lust Cinema] Erika Lust XConfessions Vol. 26 Ep 0Y - Asmr - The Sound Of Sex"
        ));
        // A duration read as an age of 1:
        assert!(!contains_minor_age_token(
            "Onlyfans - Cumpilation 2019, 1 Year 83 Cumshots! (Bareback)"
        ));
        // A point in the past read as an age of 3:
        assert!(!contains_minor_age_token(
            "FC2-PPV-3238169 An Innocent Wife ... From About 3 Years Ago, My Wife"
        ));
        // But real ages still count, including the low ones that DO occur in
        // real material — the fix must not buy precision with coverage:
        assert!(contains_minor_age_token("3 years old girl"));
        assert!(contains_minor_age_token("PornoKid LOLITA8 rare lolita 1yo whore"));
        assert!(contains_minor_age_token("01yo incest GraceL baby girl"));
        // An age followed by the year of capture is still an age (this is why the
        // counter guard is limited to spelled-out units).
        assert!(contains_minor_age_token("cacazinha 12yo 2013 cam"));
    }

    #[test]
    fn regression_bare_y_suffix_is_an_age() {
        // Four minor ages in one name, none previously recognised: "y" was not a
        // suffix and the "G12"/"B15" form was skipped entirely.
        assert!(contains_minor_age_token("BroSis G12 B15 12y Sis Blows 15y Bro"));
        assert!(contains_minor_age_token("16y girl fuck with her 8y bro"));
        assert!(contains_minor_age_token("Daughter 12Yr"));
    }

    #[test]
    fn regression_spanish_y_is_not_an_age() {
        // "y" = "and" in Spanish. Only the attached form counts, so a spaced "y"
        // must NOT read as an age suffix.
        assert!(!contains_minor_age_token("Ana 15 y Maria en la playa"));
    }

    #[test]
    fn regression_gender_age_pairs() {
        assert_eq!(count_gender_age_tokens("mov family BroSis G12 B15 - 12y Sis"), 2);
        assert_eq!(count_gender_age_tokens("mov family BroSis B08 G16 - 16y girl"), 2);
        // A lone token is ambiguous (vitamin B12, chess G4) and must not qualify.
        assert!(count_gender_age_tokens("Vitamin B12 supplement guide") < 2);
        assert!(count_gender_age_tokens("Nikon B12 review") < 2);
        // Adult ages are not minor ages.
        assert_eq!(count_gender_age_tokens("G22 B24 couple"), 0);
    }

    #[test]
    fn regression_let_is_not_a_year_suffix() {
        // THE false positive this revision fixes: a 1990 adult film with adult
        // performers. "Vegas 3 Let It Ride" parsed as "3 years" + "xxx" -> block.
        let name = "Classic XXX - Vegas 3 Let It Ride(1990)(Titty Twister Rip) Victoria Paris";
        assert!(!contains_minor_age_token(name));
        assert!(!matches_layer2(name, &name.to_lowercase()));
    }

    #[test]
    fn regression_series_number_is_not_an_age() {
        // Numbers that index a series or volume, not a person's age.
        for name in [
            "Bring Um Young 13 - Amai Liu, Kitty Jung (Adult, About 18)",
            "Zooskool - Animal Sex 16",
            "Anal Expedition 3 - Sarah Blue, Vanessa Blew",
            "Backdoor Babes 1983",
        ] {
            assert!(
                !contains_minor_age_token(name),
                "series number read as age in {name:?}"
            );
        }
    }

    #[test]
    fn regression_cjk_minor_words() {
        assert!(contains_cjk_minor_word("14歳 中学生"));
        assert!(contains_cjk_minor_word("小学生 幼女"));
        assert!(contains_cjk_minor_word("未成年"));
        // The AV genre tag must NOT be treated as a minor claim.
        assert!(!contains_cjk_minor_word("女子校生アナル大乱交 辻本りょう"));
        assert!(!contains_cjk_minor_word("女子高生"));
    }

    #[test]
    fn regression_legal_jav_genre_not_blocked() {
        // Catalogued studio releases with adult performers. Blocking these would
        // wrongly wipe out a large legal category.
        for name in [
            "MIGD-398-[Moodyz)女子校生アナル大乱交 辻本りょう 浅乃ハルミ",
            "ssni-216 快感！初 体 験8 河北彩花",
            "JUC-705 息子の嫁が巨乳過ぎて… 青木りん",
        ] {
            assert!(
                !matches_layer2(name, &name.to_lowercase()),
                "legal JAV wrongly blocked: {name:?}"
            );
        }
    }

    #[test]
    fn regression_full_layer2_still_blocks_real_cases() {
        // Age signal AND sex term both present -> must block.
        for name in [
            "Mov Family Brosis g13 b15 -15 Boy fuck And Cum On His 13 Sister",
            "mov family BroSis B08 G16 - 16y girl fuck with her 8y bro",
            "9 Yo Girl Sex With 10 Yo Brother",
            "中学生 レイプ",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()),
                "should be blocked: {name:?}"
            );
        }
    }

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
