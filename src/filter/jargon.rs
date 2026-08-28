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
//! ONE left rule, for every term: the match must not begin immediately after a
//! LATIN letter (accents included — see `is_letter_char`). The right side
//! depends on the term:
//!   * length >= 6 chars: anything may follow;
//!   * length <= 5 chars: no Latin letter may follow;
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

/// Does this character BIND to a neighbouring term, i.e. is it part of the same
/// word?
///
/// Latin script, not ASCII. The rule used to test `is_ascii_alphabetic`, which
/// made an accented letter a separator: a five-character term sat inside the
/// French word for "elephant" with `é` on its left, the left rule saw a
/// non-ASCII byte, called it a boundary and fired. On one review window that
/// blocked 21 files — Dumbo, a 1976 comedy and its soundtrack, a Conan album, a
/// popular-science ebook — and every one of them ended up in the hash ban list,
/// which also counted against the people sharing them. A Spanish word for
/// "quadruped" produced the same failure against a four-character term.
///
/// Cyrillic, Greek and CJK deliberately do NOT bind. Measured on the same
/// window: binding on every Unicode letter additionally dropped three CORRECT
/// blocks, where a Latin marker was glued straight onto Chinese text with no
/// separator ("...最新最牛逼<brand>+兽皇...", "正太shota么么哒<term>+boy-10Yo").
/// Those scripts are written without word separators, so an adjacent character
/// there says nothing about word membership — the same reasoning that already
/// exempts CJK terms from the boundary rules entirely.
///
/// Restricting it to Latin costs zero true positives on that window and removes
/// all 22 false ones.
fn is_letter_char(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphabetic();
    }
    // Latin-1 Supplement letters, Latin Extended-A/-B, IPA extensions, and
    // Latin Extended Additional (Vietnamese, and the precomposed forms these
    // filenames are full of).
    matches!(c as u32, 0x00C0..=0x024F | 0x1E00..=0x1EFF) && c.is_alphabetic()
}

/// Word character for the opt-in `$` anchor: a binding letter, an ASCII digit
/// or `_`.
fn is_word_char_at(c: char) -> bool {
    is_letter_char(c) || c.is_ascii_digit() || c == '_'
}

/// The character immediately before byte offset `at`, if any.
fn char_before(s: &str, at: usize) -> Option<char> {
    s[..at].chars().next_back()
}

/// The character starting at byte offset `at`, if any.
fn char_at(s: &str, at: usize) -> Option<char> {
    s[at..].chars().next()
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
/// Characters that count as a separator between the words of a term.
const SEPARATORS: [char; 4] = [' ', '-', '_', '.'];

/// Byte offset of the character after the one at `at`.
///
/// Slicing a `str` at a byte that is not a character boundary panics, and these
/// filenames are full of multi-byte characters, so the scan advances by
/// characters and never by one byte.
fn next_char_boundary(s: &str, at: usize) -> usize {
    let mut n = at + 1;
    while n < s.len() && !s.is_char_boundary(n) {
        n += 1;
    }
    n
}

/// Find `term` in `hay` at or after `from`, treating a SPACE in the term as
/// "one or more separator characters".
///
/// A multi-word brand is written every possible way in filenames — with spaces,
/// hyphens, underscores or dots — and each spelling used to need its own entry.
/// Missing one is silent: a term list carrying the spaced form of a brand let 25
/// files of the hyphenated form through, and three of them were sitting in live
/// search results.
///
/// ⚠ THE ASYMMETRY IS DELIBERATE. Only a SPACE in the term is flexible. A term
///   written with a hyphen matches ONLY a hyphen. That is what keeps a
///   hyphenated brand from matching the same two words written with a space —
///   which for at least one term in the L1 list is the difference between the
///   brand and an ordinary vehicle name. Write the separator you mean: space
///   for "any", hyphen for "exactly this".
///
/// Concatenation is NOT a separator: "one or more" means at least one character.
/// A concatenated spelling stays a separate entry.
fn find_flexible(hay: &str, term: &str, from: usize) -> Option<(usize, usize)> {
    // The byte walk below assumes ASCII. Terms in other scripts (CJK) never
    // carry a separator anyway, so they take the plain path.
    if !term.contains(' ') || !term.is_ascii() {
        return hay[from..].find(term).map(|p| (from + p, from + p + term.len()));
    }
    let hb = hay.as_bytes();
    let mut start = from;
    'outer: while start < hb.len() {
        // Anchor on the first character to keep this linear enough.
        let first = term.as_bytes()[0];
        match hay[start..].find(first as char) {
            Some(p) => start += p,
            None => return None,
        }
        let mut h = start;
        let mut t = 0;
        let tb = term.as_bytes();
        while t < tb.len() {
            if tb[t] == b' ' {
                // One or more separators.
                let mut n = 0;
                while h < hb.len() && SEPARATORS.contains(&(hb[h] as char)) {
                    h += 1;
                    n += 1;
                }
                if n == 0 {
                    start = next_char_boundary(hay, start);
                    continue 'outer;
                }
                t += 1;
                continue;
            }
            if h >= hb.len() || hb[h] != tb[t] {
                start = next_char_boundary(hay, start);
                continue 'outer;
            }
            h += 1;
            t += 1;
        }
        return Some((start, h));
    }
    None
}

fn contains_bounded(lowered: &str, term: &str, right: RightRule) -> bool {
    let tb = term.as_bytes();
    let check_left = edge_is_ascii_word(tb.first());
    let check_right = right != RightRule::Free && edge_is_ascii_word(tb.last());
    let mut start = 0;
    while let Some((abs, end)) = find_flexible(lowered, term, start) {
        // Neighbour tests are on CHARACTERS, not bytes: an accented letter is
        // several bytes and its trailing byte is not alphabetic, which used to
        // read as a word boundary. See `is_letter_char`.
        let before_ok = !check_left || !char_before(lowered, abs).is_some_and(is_letter_char);
        let after_ok = !check_right
            || match (right, char_at(lowered, end)) {
                (_, None) => true,
                (RightRule::Free, _) => true,
                (RightRule::NotLetter, Some(c)) => !is_letter_char(c),
                (RightRule::NotWordChar, Some(c)) => !is_word_char_at(c),
            };
        if before_ok && after_ok {
            return true;
        }
        start = next_char_boundary(lowered, abs);
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

    // ⚠ `matches_terms` takes an ALREADY-LOWERCASED name — the fold happens in
    // the caller. Every fixture below is written in lower case for that reason.
    // Getting this wrong is quiet: an upper-case fixture makes a NEGATIVE
    // assertion pass for the wrong reason, so the test guards nothing.

    #[test]
    fn a_space_in_a_term_matches_any_separator() {
        // A multi-word brand is written every way there is. Carrying only the
        // spaced form let 25 files of the hyphenated form through on one
        // measurement, three of them live in search results.
        let t = vec!["shrt marker".to_string()];
        for name in [
            "shrt marker - ann 015.mp4",
            "shrt-marker_ann-015_1080p.mp4",
            "shrt_marker ann 015.mp4",
            "shrt.marker.ann.015.mp4",
            "shrt - marker ann.mp4",
        ] {
            assert!(matches_terms(name, &t).is_some(), "missed {name}");
        }
        // Concatenation is NOT a separator — "one or more" means at least one.
        assert!(matches_terms("shrtmarker ann.mp4", &t).is_none());
    }

    #[test]
    fn a_hyphen_in_a_term_matches_only_a_hyphen() {
        // THE ASYMMETRY, and the reason for it. Written with a hyphen, the term
        // must not reach the same two words separated by a space — for one term
        // in the live L1 list that is the difference between a brand and an
        // ordinary vehicle name.
        let t = vec!["shrt-marker".to_string()];
        assert!(matches_terms("shrt-marker issue 15.rar", &t).is_some());
        assert!(matches_terms("shrt marker rover 2004 review.avi", &t).is_none());
        assert!(matches_terms("shrt_marker.avi", &t).is_none());
        assert!(matches_terms("shrt.marker.avi", &t).is_none());
    }

    #[test]
    fn flexible_matching_keeps_the_boundary_rules() {
        // The separator is flexible; the edges are not.
        let t = vec!["shrt marker".to_string()];
        assert!(matches_terms("ashrt-marker.mp4", &t).is_none());
        assert!(matches_terms("shrt-markerish.mp4", &t).is_some()); // long term: tail free
        // And a right anchor still applies to the end of the whole term.
        let anchored = vec!["shrt marker$".to_string()];
        assert!(matches_terms("shrt-markers of the world.pdf", &anchored).is_none());
        assert!(matches_terms("shrt-marker - vixen.mp4", &anchored).is_some());
        assert!(matches_terms("shrt.marker_01.mp4", &anchored).is_none());
    }

    #[test]
    fn accented_letters_bind_like_ascii_ones() {
        // THE REGRESSION this rule was changed for. A five-character term sits
        // inside the French word for "elephant"; before the fix its left
        // neighbour `é` was not an ASCII letter, so the boundary check passed
        // and 21 legitimate files were blocked and then hash-banned.
        let t = vec!["shrt".to_string()];
        assert!(matches_terms("le grand éshrt blanc.mp4", &t).is_none());
        assert!(matches_terms("l'éshrt aveugle.mp3", &t).is_none());
        // A long term is protected on the left by the same rule.
        let long = vec!["marker".to_string()];
        assert!(matches_terms("télémarker sur la piste.avi", &long).is_none());
        // Right side too: no Latin letter may follow a short term.
        assert!(matches_terms("shrté.mp4", &t).is_none());
        // ...and the term still fires at a real boundary in the same language.
        assert!(matches_terms("le shrt à paris.mp4", &t).is_some());
        assert!(matches_terms("écoute - shrt.mp4", &t).is_some());
    }

    #[test]
    fn non_latin_scripts_do_not_bind() {
        // Measured cost of the alternative: binding on EVERY Unicode letter
        // dropped three correct blocks on the review window, where a Latin
        // marker was glued straight onto Chinese text. CJK and Cyrillic are
        // written without word separators, so an adjacent character there says
        // nothing about word membership.
        let t = vec!["shrt".to_string()];
        assert!(matches_terms("最新最牛逼shrt+兽皇合集.torrent", &t).is_some());
        assert!(matches_terms("shrt么么哒.mp4", &t).is_some());
        let long = vec!["marker".to_string()];
        assert!(matches_terms("正太shota么么哒marker+boy.mp4", &long).is_some());
        assert!(matches_terms("порноmarker.avi", &long).is_some());
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
