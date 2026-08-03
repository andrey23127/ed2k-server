//! Layer 1 / Layer 4 term matching (logic only — the term lists are NOT in this
//! repo).
//!
//! Per SPEC.md §7.6.1 the jargon list is not published in human-readable form.
//! The terms are therefore loaded at runtime from an operator-supplied file
//! (`content_filter.jargon_terms_file`), exactly like the Layer-4 extra terms,
//! and held in `ContentFilter::jargon_terms`. This module contains only the
//! matching algorithm; shipping the binary/source exposes no vocabulary.
//!
//! Terms are sourced by operators from authoritative bodies (INHOPE, IWF,
//! NCMEC) — markers that do not appear inside legitimate filenames. If no file
//! is supplied, Layer 1 is simply inactive and Layers 2-4 still run.
//!
//! Matching rules
//! --------------
//! ONE left rule, for every term: the match must not begin immediately after an
//! ASCII letter. The right side depends on the term:
//!   * length >= 6 chars: anything may follow;
//!   * length <= 5 chars: no ASCII letter may follow;
//!   * a trailing `$` on any term: no ASCII word character may follow.
//! All three apply only at an edge where the TERM itself is ASCII (see
//! `edge_is_ascii_word`).
//!
//! LEFT ANCHOR — why long terms are not plain substrings
//! -----------------------------------------------------
//! The original rule assumed a term of six or more characters "never occurs
//! inside an innocent word". A live review found the counterexample: the
//! six-character term for the sibling-abuse genre is a suffix of the ordinary
//! English word "fibrosis", so a medical paper
//! ("Cystic fibrosis transmembrane conductance regulator ...pdf") was blocked.
//! The whole class — cystic / pulmonary / hepatic fibrosis — was unreachable.
//!
//! The right-hand side deliberately stays free for long terms, because real
//! catches routinely append characters ("...comic", "...sextaboo", "preteenssss")
//! and trailing digits/underscores are the norm in these filenames
//! ("brosis_001", "italian_brosis_2"). Requiring a boundary on both sides was
//! measured on a 3543-file window and would have dropped four true catches.
//!
//! Concatenations that genuinely start mid-word — a site name gluing a prefix
//! onto a term ("july" + the jailbait marker, "xxx" + a zoo-site name) — are
//! covered by adding the concatenated form as its own term. On the same window
//! that restored every affected file, for a net loss of zero true positives.
//!
//! WHY THE BOUNDARY IS "LETTER" AND NOT "WORD CHARACTER"
//! -----------------------------------------------------
//! Digits and `_` separate; letters bind. In this corpus `_` is the single most
//! common separator, and markers are routinely glued to a number. Treating them
//! as word characters silently lost real catches: a five-character marker missed
//! "2<marker>", and a four-character one missed "<marker>_virgin" and
//! "<marker>_x264" — 13 files on the review window, against zero new matches
//! that resemble an ordinary word. The protection that matters is unchanged: a
//! short token still cannot fire inside a run of letters.
//!
//! RIGHT ANCHOR (`$`) — opt-in, for terms that prefix a real word
//! --------------------------------------------------------------
//! Some terms are a legitimate prefix of a longer innocent word, where the left
//! rule cannot help because the term starts at a word boundary in both cases.
//! The live example is a zoo-site brand written with spaces, which is also the
//! opening of "Art of Zoology". Ending that term with `$` requires the match to
//! stop at a boundary: the brand still fires wherever it is followed by a dash,
//! a bracket or an extension, and the zoology title does not.
//!
//! Use it sparingly and never by reflex — a marker that legitimately runs into
//! the next token, e.g. "horse cum" in "Horse Cumswallow", is lost the moment
//! `$` is added to it.
//!
//! NOT SOLVABLE HERE: a term that is a suffix of a longer innocent PHRASE.
//! "star sessions" sits inside the jazz title "All Star Sessions", and both
//! start the phrase at a word boundary; no boundary rule can separate them.
//! Such a term needs a narrower form, or does not belong in the list.
//!
/// Threshold (in chars) at/above which a term is substring-matched; below it,
/// a right-hand boundary is required as well.
const SUBSTRING_MIN_CHARS: usize = 6;

/// A trailing `$` in a term means "and the match must end at a boundary".
/// Opt-in per term — see the RIGHT ANCHOR note at the top of the file.
const RIGHT_ANCHOR: char = '$';

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_letter(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

/// What the character after a match must not be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RightRule {
    /// Anything may follow. Long terms default to this: real filenames append
    /// freely — `term_001`, `term-2`, `termsss`.
    Free,
    /// No ASCII letter may follow. Short terms default to this, so a short token
    /// cannot fire inside a longer ordinary word.
    NotLetter,
    /// No ASCII word character may follow — letters, digits and `_`. Requested
    /// explicitly with a trailing `$`.
    NotWordChar,
}

/// Whether the boundary rules apply at a given END of a term.
///
/// They only make sense when the term's own edge is an ASCII word character.
/// The rules exist for one purpose: stop an ASCII term from firing inside a
/// longer ASCII word. A term that begins or ends with a CJK character has no
/// such failure mode — CJK is written without word separators, so demanding a
/// non-word neighbour would reject perfectly good matches.
///
/// This is not hypothetical. A two-character Chinese term sat directly after a
/// digit in a real filename ("...10-19<term>..."); byte-wise its left neighbour
/// is '9', so an unconditional boundary check dropped a correct block.
fn edge_is_ascii_word(b: Option<&u8>) -> bool {
    b.is_some_and(|b| is_word_char(*b))
}

/// Split a term into its text and whether it asked for a right anchor.
/// A bare `$` is not an anchor request — it is the whole term.
fn split_anchor(term: &str) -> (&str, bool) {
    match term.strip_suffix(RIGHT_ANCHOR) {
        Some(stripped) if !stripped.is_empty() => (stripped, true),
        _ => (term, false),
    }
}

/// True if `term` (already lowercased, anchor stripped) occurs in `lowered`
/// with the required boundaries.
///
/// The left rule is always the same — the match must not begin immediately
/// after an ASCII letter — and applies only when the term itself starts with an
/// ASCII word character. The right rule is the caller's choice.
fn contains_bounded(lowered: &str, term: &str, right: RightRule) -> bool {
    let bytes = lowered.as_bytes();
    let tb = term.as_bytes();
    let check_left = edge_is_ascii_word(tb.first());
    let check_right = right != RightRule::Free && edge_is_ascii_word(tb.last());
    let mut start = 0;
    while let Some(pos) = lowered[start..].find(term) {
        let abs = start + pos;
        let before_ok = !check_left || abs == 0 || !is_letter(bytes[abs - 1]);
        let end = abs + tb.len();
        let after_ok = !check_right
            || end == bytes.len()
            || match right {
                RightRule::Free => true,
                RightRule::NotLetter => !is_letter(bytes[end]),
                RightRule::NotWordChar => !is_word_char(bytes[end]),
            };
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// Returns the term from `terms` that matches `lowered` (already lowercased;
/// terms are expected pre-lowercased by the loader), or None.
///
/// Used for BOTH Layer 1 (jargon) and Layer 4 (operator extras). Layer 4 used
/// to call `str::contains` directly, which meant none of the rules below applied
/// to it; the term that produced the live fibrosis false positive was in fact a
/// Layer-4 term. One matcher for both lists is the only way to keep them from
/// drifting apart again.
///
/// The returned term is the list entry VERBATIM, `$` included, so an operator
/// reading a review can find the exact line that fired.
pub(super) fn matches_terms<'a>(lowered: &str, terms: &'a [String]) -> Option<&'a str> {
    for term in terms {
        if term.is_empty() {
            continue;
        }
        let (text, anchored) = split_anchor(term);
        let right = if anchored {
            RightRule::NotWordChar
        } else if text.chars().count() >= SUBSTRING_MIN_CHARS {
            RightRule::Free
        } else {
            RightRule::NotLetter
        };
        if contains_bounded(lowered, text, right) {
            return Some(term.as_str());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic, non-real terms exercise the LOGIC without embedding any real
    // vocabulary: "longmarker" (≥6 → substring), "shrt" (≤5 → word-bounded).
    fn sample() -> Vec<String> {
        vec!["longmarker".to_string(), "shrt".to_string()]
    }

    #[test]
    fn long_term_substring_matches_anywhere() {
        let t = sample();
        assert!(matches_terms("video longmarker something.mp4", &t).is_some());
        // Unanchored on the RIGHT is still fine for long terms.
        assert!(matches_terms("longmarkerx.zip", &t).is_some());
        assert!(matches_terms("[longmarker]_001.mp4", &t).is_some());
        assert!(matches_terms("italian_longmarker_2.avi", &t).is_some());
        assert!(matches_terms("9longmarker.mkv", &t).is_some()); // digit is not a letter
    }

    #[test]
    fn long_term_does_not_start_inside_an_english_word() {
        // THE REGRESSION: a term that is a suffix of an ordinary word must not
        // fire. Mirrors the live "fibrosis" false positive with a synthetic term.
        let t = vec!["marker".to_string()];
        assert!(matches_terms("biomarker discovery in plasma.pdf", &t).is_none());
        assert!(matches_terms("xmarker.zip", &t).is_none());
        // ...but the same term still fires when it starts a word.
        assert!(matches_terms("bio marker discovery.pdf", &t).is_some());
        assert!(matches_terms("bio-marker.pdf", &t).is_some());
    }

    #[test]
    fn concatenated_form_is_covered_by_its_own_term() {
        // A site name gluing a prefix onto a term is reachable by listing the
        // concatenation — this is how the left anchor stays lossless.
        let t = vec!["marker".to_string(), "biomarker".to_string()];
        assert!(matches_terms("biomarker discovery.pdf", &t).is_some());
    }

    #[test]
    fn short_term_requires_word_boundaries() {
        let t = sample();
        assert!(matches_terms("a shrt clip.mp4", &t).is_some());
        assert!(matches_terms("[shrt] file.mkv", &t).is_some());
        assert!(matches_terms("file.shrt.video.mkv", &t).is_some()); // dots are boundaries
        assert!(matches_terms("xx-shrt-xx.mp4", &t).is_some());       // hyphens are boundaries
        // Letters bind → must NOT match (substring of a longer ordinary word).
        assert!(matches_terms("ashrtb album.mp3", &t).is_none());
        assert!(matches_terms("shrtly.mp4", &t).is_none());
        assert!(matches_terms("ashrt.mp4", &t).is_none());
        // Digits and _ separate. These were losses under the old word-char rule:
        // a marker glued to a number or joined with an underscore is still the
        // marker, and this corpus writes them that way constantly.
        assert!(matches_terms("file_shrt_xx.mp4", &t).is_some());
        assert!(matches_terms("2shrt clip.mp4", &t).is_some());
        assert!(matches_terms("shrt_virgin.avi", &t).is_some());
        assert!(matches_terms("shrt2011.mpg", &t).is_some());
    }

    #[test]
    fn right_anchor_is_opt_in() {
        // Without `$` a long term ignores what follows.
        let free = vec!["art of zoo".to_string()];
        assert!(matches_terms("the art of zoology (bbc).mkv", &free).is_some());

        // With `$` it must stop at a boundary — which is what separates the
        // brand from the innocent word that starts the same way.
        let anchored = vec!["art of zoo$".to_string()];
        assert!(matches_terms("the art of zoology (bbc).mkv", &anchored).is_none());
        assert!(matches_terms("art of zoological illustration.pdf", &anchored).is_none());
        assert!(matches_terms("art of zoo - vixen.mp4", &anchored).is_some());
        assert!(matches_terms("(art of zoo) - blondie.mp4", &anchored).is_some());
        assert!(matches_terms("clip art of zoo.mp4", &anchored).is_some());

        // The reported term is the list entry verbatim, `$` and all, so the
        // operator can grep for the line that fired.
        assert_eq!(matches_terms("art of zoo - vixen.mp4", &anchored), Some("art of zoo$"));

        // `$` also tightens the right side of a SHORT term from letters to all
        // word characters.
        let short = vec!["abc$".to_string()];
        assert!(matches_terms("abc_1.mp4", &short).is_none());
        assert!(matches_terms("abc-1.mp4", &short).is_some());

        // A bare "$" is a term, not an anchor request.
        let dollar = vec!["$".to_string()];
        assert!(matches_terms("price $5.mp4", &dollar).is_some());
    }

    #[test]
    fn cjk_terms_match_regardless_of_neighbours() {
        // A CJK term has no ASCII word edges, so neither boundary rule applies:
        // it behaves as a plain substring, which is the only correct reading for
        // a script written without word separators.
        let t = vec!["幼女".to_string()];
        assert!(matches_terms("中国 幼女 幼童.avi", &t).is_some());
        assert!(matches_terms("欧美无码幼女学生.avi", &t).is_some());
        // THE REGRESSION: an ASCII digit directly before the term. Byte-wise
        // that is a word character, and an unconditional boundary check dropped
        // this real filename.
        assert!(matches_terms("小陈头星选10-19幼女大奶妹子.mp4", &t).is_some());
        assert!(matches_terms("x幼女y.avi", &t).is_some());
        // Long CJK terms take the substring path and must not be left-anchored.
        let t2 = vec!["ロリータ写真集".to_string()];
        assert!(matches_terms("abcロリータ写真集.zip", &t2).is_some());
    }

    #[test]
    fn empty_list_matches_nothing() {
        assert!(matches_terms("anything at all.mp4", &[]).is_none());
    }

    #[test]
    fn empty_term_is_skipped() {
        let t = vec!["".to_string(), "longmarker".to_string()];
        assert!(matches_terms("nothing here.mp4", &t).is_none());
        assert!(matches_terms("longmarker.mp4", &t).is_some());
    }
}
