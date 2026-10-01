//! Recompose Latin letters that arrive DECOMPOSED (Unicode NFD).
//!
//! Some filenames reach us with an accented letter written as two code points:
//! the base letter and a combining mark — "e" + U+0301 instead of "é". Both
//! render identically and compare unequal, and every rule in the term layers
//! that looks at a neighbouring character saw the combining mark, which is not
//! a letter, and read it as a word BOUNDARY.
//!
//! ⚠ THIS IS THE THIRD TIME THE SAME WORD HAS COME THROUGH. The French word for
//!   "elephant" carries an L4 term after an accented letter.
//!     * Before 0.9.75 the boundary test was ASCII-only, so a precomposed "é"
//!       counted as a separator: 21 files blocked and hash-banned (Dumbo, a
//!       Conan album, a 1976 comedy). Fixed by binding on every LATIN letter.
//!     * The same day a phrase exemption was added for the
//!       titles that "survive the boundary fix". Those survivors were NFD —
//!       the fix covered "é" and not "e"+U+0301 — and the phrase patched the
//!       symptom for one title.
//!     * 26.09.2026: "Conan - 01 - La Tour de l'éléphant.cbr", NFD, blocked
//!       again.
//!   The cause was never the vocabulary. It is the representation, and it is
//!   fixed here, once, for every layer: the name is recomposed before any
//!   matching, so the matcher, the phrase exemptions and the age scanner all
//!   see the same text a person sees.
//!
//! Scope, deliberately narrow: the Latin letters and marks that Western
//! European, Czech, Polish and similar filenames actually carry. The table was
//! generated from Unicode's own composition data; it is not a full NFC
//! implementation, and a pair it does not know is left as it was (the matcher
//! still treats a leftover combining mark as part of the word before it — see
//! `is_combining_mark`).

use std::borrow::Cow;

/// Combining diacritical marks — they belong to the character before them.
pub fn is_combining_mark(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036F   // Combining Diacritical Marks
        | 0x1AB0..=0x1AFF // ... Extended
        | 0x1DC0..=0x1DFF // ... Supplement
        | 0x20D0..=0x20FF // ... for Symbols
        | 0xFE20..=0xFE2F // Combining Half Marks
    )
}

fn compose(base: char, mark: u32) -> Option<char> {
    Some(match (base, mark) {
        ('a', 0x0300) => 'à',
        ('a', 0x0301) => 'á',
        ('a', 0x0302) => 'â',
        ('a', 0x0303) => 'ã',
        ('a', 0x0304) => 'ā',
        ('a', 0x0306) => 'ă',
        ('a', 0x0307) => 'ȧ',
        ('a', 0x0308) => 'ä',
        ('a', 0x030A) => 'å',
        ('a', 0x030C) => 'ǎ',
        ('a', 0x0328) => 'ą',
        ('e', 0x0300) => 'è',
        ('e', 0x0301) => 'é',
        ('e', 0x0302) => 'ê',
        ('e', 0x0303) => 'ẽ',
        ('e', 0x0304) => 'ē',
        ('e', 0x0306) => 'ĕ',
        ('e', 0x0307) => 'ė',
        ('e', 0x0308) => 'ë',
        ('e', 0x030C) => 'ě',
        ('e', 0x0327) => 'ȩ',
        ('e', 0x0328) => 'ę',
        ('i', 0x0300) => 'ì',
        ('i', 0x0301) => 'í',
        ('i', 0x0302) => 'î',
        ('i', 0x0303) => 'ĩ',
        ('i', 0x0304) => 'ī',
        ('i', 0x0306) => 'ĭ',
        ('i', 0x0308) => 'ï',
        ('i', 0x030C) => 'ǐ',
        ('i', 0x0328) => 'į',
        ('o', 0x0300) => 'ò',
        ('o', 0x0301) => 'ó',
        ('o', 0x0302) => 'ô',
        ('o', 0x0303) => 'õ',
        ('o', 0x0304) => 'ō',
        ('o', 0x0306) => 'ŏ',
        ('o', 0x0307) => 'ȯ',
        ('o', 0x0308) => 'ö',
        ('o', 0x030B) => 'ő',
        ('o', 0x030C) => 'ǒ',
        ('o', 0x0328) => 'ǫ',
        ('u', 0x0300) => 'ù',
        ('u', 0x0301) => 'ú',
        ('u', 0x0302) => 'û',
        ('u', 0x0303) => 'ũ',
        ('u', 0x0304) => 'ū',
        ('u', 0x0306) => 'ŭ',
        ('u', 0x0308) => 'ü',
        ('u', 0x030A) => 'ů',
        ('u', 0x030B) => 'ű',
        ('u', 0x030C) => 'ǔ',
        ('u', 0x0328) => 'ų',
        ('y', 0x0300) => 'ỳ',
        ('y', 0x0301) => 'ý',
        ('y', 0x0302) => 'ŷ',
        ('y', 0x0303) => 'ỹ',
        ('y', 0x0304) => 'ȳ',
        ('y', 0x0307) => 'ẏ',
        ('y', 0x0308) => 'ÿ',
        ('y', 0x030A) => 'ẙ',
        ('n', 0x0300) => 'ǹ',
        ('n', 0x0301) => 'ń',
        ('n', 0x0303) => 'ñ',
        ('n', 0x0307) => 'ṅ',
        ('n', 0x030C) => 'ň',
        ('n', 0x0327) => 'ņ',
        ('c', 0x0301) => 'ć',
        ('c', 0x0302) => 'ĉ',
        ('c', 0x0307) => 'ċ',
        ('c', 0x030C) => 'č',
        ('c', 0x0327) => 'ç',
        ('s', 0x0301) => 'ś',
        ('s', 0x0302) => 'ŝ',
        ('s', 0x0307) => 'ṡ',
        ('s', 0x030C) => 'š',
        ('s', 0x0327) => 'ş',
        ('z', 0x0301) => 'ź',
        ('z', 0x0302) => 'ẑ',
        ('z', 0x0307) => 'ż',
        ('z', 0x030C) => 'ž',
        ('r', 0x0301) => 'ŕ',
        ('r', 0x0307) => 'ṙ',
        ('r', 0x030C) => 'ř',
        ('r', 0x0327) => 'ŗ',
        ('d', 0x0307) => 'ḋ',
        ('d', 0x030C) => 'ď',
        ('d', 0x0327) => 'ḑ',
        ('t', 0x0307) => 'ṫ',
        ('t', 0x0308) => 'ẗ',
        ('t', 0x030C) => 'ť',
        ('t', 0x0327) => 'ţ',
        ('l', 0x0301) => 'ĺ',
        ('l', 0x030C) => 'ľ',
        ('l', 0x0327) => 'ļ',
        ('g', 0x0301) => 'ǵ',
        ('g', 0x0302) => 'ĝ',
        ('g', 0x0304) => 'ḡ',
        ('g', 0x0306) => 'ğ',
        ('g', 0x0307) => 'ġ',
        ('g', 0x030C) => 'ǧ',
        ('g', 0x0327) => 'ģ',
        ('k', 0x0301) => 'ḱ',
        ('k', 0x030C) => 'ǩ',
        ('k', 0x0327) => 'ķ',
        ('h', 0x0302) => 'ĥ',
        ('h', 0x0307) => 'ḣ',
        ('h', 0x0308) => 'ḧ',
        ('h', 0x030C) => 'ȟ',
        ('h', 0x0327) => 'ḩ',
        ('j', 0x0302) => 'ĵ',
        ('j', 0x030C) => 'ǰ',
        ('w', 0x0300) => 'ẁ',
        ('w', 0x0301) => 'ẃ',
        ('w', 0x0302) => 'ŵ',
        ('w', 0x0307) => 'ẇ',
        ('w', 0x0308) => 'ẅ',
        ('w', 0x030A) => 'ẘ',
        ('A', 0x0300) => 'À',
        ('A', 0x0301) => 'Á',
        ('A', 0x0302) => 'Â',
        ('A', 0x0303) => 'Ã',
        ('A', 0x0304) => 'Ā',
        ('A', 0x0306) => 'Ă',
        ('A', 0x0307) => 'Ȧ',
        ('A', 0x0308) => 'Ä',
        ('A', 0x030A) => 'Å',
        ('A', 0x030C) => 'Ǎ',
        ('A', 0x0328) => 'Ą',
        ('E', 0x0300) => 'È',
        ('E', 0x0301) => 'É',
        ('E', 0x0302) => 'Ê',
        ('E', 0x0303) => 'Ẽ',
        ('E', 0x0304) => 'Ē',
        ('E', 0x0306) => 'Ĕ',
        ('E', 0x0307) => 'Ė',
        ('E', 0x0308) => 'Ë',
        ('E', 0x030C) => 'Ě',
        ('E', 0x0327) => 'Ȩ',
        ('E', 0x0328) => 'Ę',
        ('I', 0x0300) => 'Ì',
        ('I', 0x0301) => 'Í',
        ('I', 0x0302) => 'Î',
        ('I', 0x0303) => 'Ĩ',
        ('I', 0x0304) => 'Ī',
        ('I', 0x0306) => 'Ĭ',
        ('I', 0x0307) => 'İ',
        ('I', 0x0308) => 'Ï',
        ('I', 0x030C) => 'Ǐ',
        ('I', 0x0328) => 'Į',
        ('O', 0x0300) => 'Ò',
        ('O', 0x0301) => 'Ó',
        ('O', 0x0302) => 'Ô',
        ('O', 0x0303) => 'Õ',
        ('O', 0x0304) => 'Ō',
        ('O', 0x0306) => 'Ŏ',
        ('O', 0x0307) => 'Ȯ',
        ('O', 0x0308) => 'Ö',
        ('O', 0x030B) => 'Ő',
        ('O', 0x030C) => 'Ǒ',
        ('O', 0x0328) => 'Ǫ',
        ('U', 0x0300) => 'Ù',
        ('U', 0x0301) => 'Ú',
        ('U', 0x0302) => 'Û',
        ('U', 0x0303) => 'Ũ',
        ('U', 0x0304) => 'Ū',
        ('U', 0x0306) => 'Ŭ',
        ('U', 0x0308) => 'Ü',
        ('U', 0x030A) => 'Ů',
        ('U', 0x030B) => 'Ű',
        ('U', 0x030C) => 'Ǔ',
        ('U', 0x0328) => 'Ų',
        ('Y', 0x0300) => 'Ỳ',
        ('Y', 0x0301) => 'Ý',
        ('Y', 0x0302) => 'Ŷ',
        ('Y', 0x0303) => 'Ỹ',
        ('Y', 0x0304) => 'Ȳ',
        ('Y', 0x0307) => 'Ẏ',
        ('Y', 0x0308) => 'Ÿ',
        ('N', 0x0300) => 'Ǹ',
        ('N', 0x0301) => 'Ń',
        ('N', 0x0303) => 'Ñ',
        ('N', 0x0307) => 'Ṅ',
        ('N', 0x030C) => 'Ň',
        ('N', 0x0327) => 'Ņ',
        ('C', 0x0301) => 'Ć',
        ('C', 0x0302) => 'Ĉ',
        ('C', 0x0307) => 'Ċ',
        ('C', 0x030C) => 'Č',
        ('C', 0x0327) => 'Ç',
        ('S', 0x0301) => 'Ś',
        ('S', 0x0302) => 'Ŝ',
        ('S', 0x0307) => 'Ṡ',
        ('S', 0x030C) => 'Š',
        ('S', 0x0327) => 'Ş',
        ('Z', 0x0301) => 'Ź',
        ('Z', 0x0302) => 'Ẑ',
        ('Z', 0x0307) => 'Ż',
        ('Z', 0x030C) => 'Ž',
        ('R', 0x0301) => 'Ŕ',
        ('R', 0x0307) => 'Ṙ',
        ('R', 0x030C) => 'Ř',
        ('R', 0x0327) => 'Ŗ',
        ('D', 0x0307) => 'Ḋ',
        ('D', 0x030C) => 'Ď',
        ('D', 0x0327) => 'Ḑ',
        ('T', 0x0307) => 'Ṫ',
        ('T', 0x030C) => 'Ť',
        ('T', 0x0327) => 'Ţ',
        ('L', 0x0301) => 'Ĺ',
        ('L', 0x030C) => 'Ľ',
        ('L', 0x0327) => 'Ļ',
        ('G', 0x0301) => 'Ǵ',
        ('G', 0x0302) => 'Ĝ',
        ('G', 0x0304) => 'Ḡ',
        ('G', 0x0306) => 'Ğ',
        ('G', 0x0307) => 'Ġ',
        ('G', 0x030C) => 'Ǧ',
        ('G', 0x0327) => 'Ģ',
        ('K', 0x0301) => 'Ḱ',
        ('K', 0x030C) => 'Ǩ',
        ('K', 0x0327) => 'Ķ',
        ('H', 0x0302) => 'Ĥ',
        ('H', 0x0307) => 'Ḣ',
        ('H', 0x0308) => 'Ḧ',
        ('H', 0x030C) => 'Ȟ',
        ('H', 0x0327) => 'Ḩ',
        ('J', 0x0302) => 'Ĵ',
        ('W', 0x0300) => 'Ẁ',
        ('W', 0x0301) => 'Ẃ',
        ('W', 0x0302) => 'Ŵ',
        ('W', 0x0307) => 'Ẇ',
        ('W', 0x0308) => 'Ẅ',
        _ => return None,
    })
}

/// Recompose base letter + combining mark pairs into the precomposed letter.
/// Returns the input untouched (no allocation) when it has no combining mark,
/// which is nearly every name.
pub fn compose_latin(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_combining_mark) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_combining_mark(c) {
            if let Some(prev) = out.chars().next_back() {
                if let Some(composed) = compose(prev, c as u32) {
                    out.pop();
                    out.push(composed);
                    continue;
                }
            }
        }
        out.push(c);
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decomposed_elephant_is_recomposed() {
        // The exact bytes of the 26.09.2026 name: "e" + U+0301, twice.
        let nfd = "La Tour de l'e\u{301}le\u{301}phant (Panini).cbr";
        assert_eq!(compose_latin(nfd), "La Tour de l'éléphant (Panini).cbr");
    }

    #[test]
    fn spanish_and_portuguese_marks_recompose() {
        assert_eq!(compose_latin("an\u{303}os"), "años");
        assert_eq!(compose_latin("detra\u{300}s"), "detràs");
        assert_eq!(compose_latin("c\u{327}a\u{303}o"), "ção");
        assert_eq!(compose_latin("u\u{308}ber"), "über");
        assert_eq!(compose_latin("z\u{30C}lutoucky\u{301}"), "žlutoucký");
    }

    #[test]
    fn precomposed_and_plain_text_is_borrowed_unchanged() {
        assert!(matches!(compose_latin("Déjà vu.mp3"), Cow::Borrowed(_)));
        assert!(matches!(compose_latin("plain.avi"), Cow::Borrowed(_)));
    }

    #[test]
    fn an_unknown_pair_is_left_alone() {
        // A combining mark on a CJK character: nothing to compose, nothing lost.
        assert_eq!(compose_latin("字\u{301}"), "字\u{301}");
    }
}
