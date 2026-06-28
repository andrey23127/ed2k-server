//! Layer 1 jargon matching (logic only — the term list is NOT in this repo).
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
//! Classification is by term length (matches the historical split):
//!   * length >= 6 chars: substring match (these never occur inside innocent
//!     words, so an unanchored match is safe);
//!   * length <= 5 chars: word-boundary match on both sides (a short token must
//!     not fire inside a longer run of word chars, and must not match when it
//!     is a substring of an ordinary word).

/// Threshold (in chars) at/above which a term is substring-matched; below it,
/// word boundaries are required.
const SUBSTRING_MIN_CHARS: usize = 6;

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True if `term` (already lowercased) occurs in `lowered` with word boundaries
/// on both sides.
fn contains_word_bounded(lowered: &str, term: &str) -> bool {
    let bytes = lowered.as_bytes();
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
    false
}

/// Returns true if `lowered` (already lowercased) contains any Layer 1 jargon
/// term from `terms` (terms are expected pre-lowercased by the loader).
/// Long terms use substring match; short terms require word boundaries.
/// Internal — not re-exported. Callers go through `ContentFilter::check`.
pub(super) fn matches_layer1(lowered: &str, terms: &[String]) -> bool {
    for term in terms {
        if term.is_empty() {
            continue;
        }
        if term.chars().count() >= SUBSTRING_MIN_CHARS {
            if lowered.contains(term.as_str()) {
                return true;
            }
        } else if contains_word_bounded(lowered, term) {
            return true;
        }
    }
    false
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
        assert!(matches_layer1("video longmarker something.mp4", &t));
        assert!(matches_layer1("xlongmarkerx.zip", &t)); // unanchored OK for long terms
    }

    #[test]
    fn short_term_requires_word_boundaries() {
        let t = sample();
        assert!(matches_layer1("a shrt clip.mp4", &t));
        assert!(matches_layer1("[shrt] file.mkv", &t));
        assert!(matches_layer1("file.shrt.video.mkv", &t)); // dots are boundaries
        assert!(matches_layer1("xx-shrt-xx.mp4", &t));       // hyphens are boundaries
        // No boundary → must NOT match (substring of a longer ordinary word).
        assert!(!matches_layer1("ashrtb album.mp3", &t));
        // _ counts as a word char, so an underscore run is one identifier.
        assert!(!matches_layer1("file_shrt_xx.mp4", &t));
    }

    #[test]
    fn empty_list_matches_nothing() {
        assert!(!matches_layer1("anything at all.mp4", &[]));
    }

    #[test]
    fn empty_term_is_skipped() {
        let t = vec!["".to_string(), "longmarker".to_string()];
        assert!(!matches_layer1("nothing here.mp4", &t));
        assert!(matches_layer1("longmarker.mp4", &t));
    }
}
