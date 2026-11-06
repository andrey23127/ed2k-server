//! Signals for the filter audit (`/api/review?format=audit`).
//!
//! The audit looks for FALSE POSITIVES: a term that fires on song titles, a
//! book, a cartoon episode. Those are found by reading the names the filter
//! blocked — but most blocked names are blocked rightly, and those are not
//! text anyone should have to read to find the few mistakes. So every blocked
//! name is first reduced to a handful of signals, and a name is shown only
//! when nothing in it but the rule that fired points at abuse:
//!
//! * `explicit` — ordinary adult sexual vocabulary;
//! * `age` — a child's age written as a number with a unit ("9 yo");
//! * `minor` — a generic word for a child, other than the rule itself;
//! * `marker2` — the name still trips a term layer with the rule's own term
//!   taken out: a second marker from the operator's lists. This is how the
//!   lists themselves join the test without being repeated here.
//!
//! A rule is judged as a whole too: when a quarter of its hits carry a signal
//! that points at a child (age, child word, second marker) it is a working
//! marker, and none of its names are shown. Explicit words alone do not make
//! a marker — a term that fires on legal adult titles is a false positive
//! too — but a name with them is never shown; its hash is listed for review.
//! What remains visible is the case the audit exists for — a term alone in
//! an otherwise ordinary name.
//!
//! The vocabulary here is deliberately generic and errs towards hiding: a
//! name withheld by mistake costs a false positive staying in the list one
//! more round; a name shown by mistake costs much more.

use crate::filter::{ContentFilter, FilterResult, Layer};

/// What a file is, by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Audio,
    Video,
    Image,
    Doc,
    Archive,
    Software,
    Other,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Audio => "audio",
            Kind::Video => "video",
            Kind::Image => "image",
            Kind::Doc => "doc",
            Kind::Archive => "archive",
            Kind::Software => "software",
            Kind::Other => "other",
        }
    }
}

pub fn kind_of(name: &str) -> Kind {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "mp3" | "mp2" | "flac" | "ogg" | "oga" | "wma" | "m4a" | "m4b" | "m4r" | "ape" | "wav"
        | "wave" | "aac" | "opus" | "mpc" | "wv" | "mka" | "ac3" | "dts" | "mid" | "midi"
        | "cue" | "aif" | "aiff" | "amr" | "au" | "ra" | "tta" | "shn" | "spx" | "caf" | "dsf"
        | "dff" | "xm" | "mod" | "s3m" | "it" => Kind::Audio,
        "avi" | "mkv" | "mp4" | "wmv" | "mpg" | "mpeg" | "mov" | "flv" | "m4v" | "ts" | "m2ts"
        | "vob" | "rmvb" | "rm" | "3gp" | "webm" | "divx" | "ogm" | "asf" | "srt" | "sub" => {
            Kind::Video
        }
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff" => Kind::Image,
        "pdf" | "epub" | "mobi" | "djvu" | "djv" | "doc" | "docx" | "txt" | "rtf" | "chm"
        | "azw" | "azw3" | "fb2" | "lit" | "ppt" | "pptx" | "xls" | "xlsx" | "odt" | "htm"
        | "html" | "ps" => Kind::Doc,
        // Comic archives are pictures, and disc images may hold films: neither
        // is a document or a program, whose clean names the audit shows.
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "tgz" | "cbr" | "cbz" | "cb7" => {
            Kind::Archive
        }
        "exe" | "msi" | "apk" | "dmg" | "cab" | "jar" | "deb" | "rpm" => Kind::Software,
        _ => Kind::Other,
    }
}

/// Whole words.
const EXPLICIT_WORDS: &[&str] = &[
    "sex", "sexo", "sesso", "porn", "porno", "xxx", "nude", "nudes", "naked", "nackt", "nue",
    "nuda", "nudo", "cum", "cumshot", "anal", "oral", "blowjob", "bj", "handjob", "pussy",
    "cock", "dick", "tits", "boobs", "dildo", "creampie", "gangbang", "incest", "hentai", "milf",
    "hardcore", "softcore", "deepthroat", "threesome", "bdsm", "fetish", "upskirt", "voyeur",
    "topless", "stripper", "striptease", "lesbian", "lesbians", "orgy", "slut", "whore",
    "minet", "голая", "голые", "минет", "polla", "coño", "salope", "chatte", "puta",
];
/// Word prefixes.
const EXPLICIT_PREFIXES: &[&str] = &[
    "fuck", "fick", "masturb", "orgasm", "sperm", "rape", "erotic", "erotik", "erotis", "porn",
    "порн", "секс", "трах", "ебл", "ебет", "сиськ", "desnud", "scopat", "baise", "follan",
];
/// Substrings, for scripts written without spaces.
const EXPLICIT_CJK: &[&str] = &["無修正", "エロ", "性交", "中出し", "色情", "做爱", "做愛", "淫"];

/// Generic words for a child. Whole words. Not "baby" or "kind": both are in
/// too many song titles, and the other signals cover their adult use.
const MINOR_WORDS: &[&str] = &[
    "child", "children", "childs", "kid", "kids", "teen", "teens", "teenie", "teenies", "preteen",
    "preteens", "underage", "toddler", "toddlers", "infant", "infants",
    "schoolgirl", "schoolgirls", "schoolboy", "schoolboys", "kinder", "enfant",
    "enfants", "fillette", "niña", "niñas", "niño", "niños", "menina", "meninas", "menino",
    "bambina", "bambine", "bambino", "bambini", "дети", "детей", "ребенок", "ребёнок",
];
const MINOR_PREFIXES: &[&str] = &["девочк", "мальчик", "детск", "школьниц", "малолет", "ragazzin"];
const MINOR_CJK: &[&str] = &["少女", "幼女", "幼児", "児童", "儿童", "小学", "中学生", "女児", "男児"];

/// Units a child's age is written with, after the number.
const AGE_UNITS: &[&str] = &[
    "yo", "y", "yrs", "yr", "years", "year", "anos", "años", "anni", "jahre", "ans", "лет",
    "года", "год", "歳", "歲", "岁", "才",
];

fn words(lower: &str) -> impl Iterator<Item = &str> {
    lower.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty())
}

pub fn has_explicit(lower: &str) -> bool {
    words(lower).any(|w| {
        EXPLICIT_WORDS.contains(&w) || EXPLICIT_PREFIXES.iter().any(|p| w.starts_with(p))
    }) || EXPLICIT_CJK.iter().any(|s| lower.contains(s))
}

pub fn has_minor_word(lower: &str) -> bool {
    words(lower)
        .any(|w| MINOR_WORDS.contains(&w) || MINOR_PREFIXES.iter().any(|p| w.starts_with(p)))
        || MINOR_CJK.iter().any(|s| lower.contains(s))
}

/// A number from 1 to 17 standing alone and followed by an age unit ("9yo",
/// "9 y.o.", "12 anos", "13歳"), or after "age"/"aged".
pub fn has_age(lower: &str) -> bool {
    let chars: Vec<char> = lower.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        // Part of a word or a longer number ("x264", "s01e12", "1080").
        if start > 0 && chars[start - 1].is_alphanumeric() {
            continue;
        }
        let digits: String = chars[start..i].iter().collect();
        let Ok(n) = digits.parse::<u32>() else { continue };
        if !(1..=17).contains(&n) || digits.len() > 2 {
            continue;
        }
        // "age 9" / "aged 9"
        let before: String = chars[..start].iter().collect();
        let before = before.trim_end_matches(|c: char| !c.is_alphanumeric());
        if before.ends_with("age") || before.ends_with("aged") {
            return true;
        }
        // Up to two separators, then the unit.
        let mut j = i;
        let mut seps = 0;
        while j < chars.len() && seps < 2 && matches!(chars[j], ' ' | '_' | '-' | '.') {
            j += 1;
            seps += 1;
        }
        let rest: String = chars[j..].iter().take(8).collect();
        let rest_letters: String = rest.chars().filter(|c| *c != '.').collect();
        for u in AGE_UNITS {
            if let Some(after) = rest_letters.strip_prefix(u) {
                let ends = after.chars().next().map_or(true, |c| !c.is_alphabetic());
                // CJK units need no boundary.
                if ends || !u.is_ascii() {
                    return true;
                }
            }
        }
    }
    false
}

/// The signals of one blocked name.
#[derive(Debug, Clone, Copy, Default)]
pub struct Signals {
    pub explicit: bool,
    pub age: bool,
    pub minor: bool,
    pub marker2: bool,
}

impl Signals {
    /// Any signal: the name is not shown.
    pub fn dirty(&self) -> bool {
        self.explicit || self.age || self.minor || self.marker2
    }

    /// A signal that points at a child, not just at adult content: what
    /// makes a rule a working marker.
    pub fn strong(&self) -> bool {
        self.age || self.minor || self.marker2
    }
}

/// The term a rule's reason names, without the decorations the filter adds.
/// Lower-cased, with every run of non-alphanumeric characters as one space.
pub fn separators_to_spaces(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut gap = true;
    for c in s.to_lowercase().chars() {
        if c.is_alphanumeric() {
            out.push(c);
            gap = false;
        } else if !gap {
            out.push(' ');
            gap = true;
        }
    }
    out
}

fn reason_term(reason: &str) -> &str {
    reason.trim_end_matches(" (mojibake)").trim()
}

pub fn signals(filter: &ContentFilter, name: &str, layer: Layer, reason: &str) -> Signals {
    let lower = name.to_lowercase();
    // The rule's own term does not count against the name: it is what is
    // being judged. Removed from a copy with every separator turned into a
    // space, the way the term layers see it: removed from the raw name, a
    // term the layers matched across "." or "_" ("Star.Sessions") stayed in,
    // tripped the layer again and counted as a second marker. On 31.10.2026
    // that made every L1 and L4 rule a "marker" and withheld every name.
    let stripped = match layer {
        Layer::L1Jargon | Layer::L4Extra => {
            let t = separators_to_spaces(reason_term(reason));
            if t.trim().is_empty() {
                lower.clone()
            } else {
                let spaced = separators_to_spaces(&lower);
                let squashed: String = t.chars().filter(|c| *c != ' ').collect();
                let once = spaced.replace(t.trim(), " ");
                if squashed.len() > 2 {
                    once.replace(&squashed, " ")
                } else {
                    once
                }
            }
        }
        _ => lower.clone(),
    };
    let age = match layer {
        // The age IS the rule; it is not a second signal.
        Layer::L2AgePattern => false,
        _ => has_age(&stripped),
    };
    // A second marker: the name still trips a term layer with the rule's own
    // term removed. An all-zero hash is on no list.
    let marker2 = match filter.check_ignoring_whitelist(&[0u8; 16], &stripped) {
        FilterResult::Block(l, _) => match layer {
            Layer::L2AgePattern => matches!(l, Layer::L1Jargon | Layer::L4Extra),
            _ => true,
        },
        FilterResult::Allow => false,
    };
    Signals {
        explicit: has_explicit(&stripped),
        age,
        minor: has_minor_word(&stripped),
        marker2,
    }
}

/// How a rule behaves over all its hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Few or no hits point at a child: the term fires on ordinary names.
    LikelyFalsePositive,
    /// A quarter or more of its hits point at a child: a working marker.
    /// None of its names are shown.
    Marker,
    Mixed,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::LikelyFalsePositive => "likely false positive",
            Verdict::Marker => "marker (names withheld)",
            Verdict::Mixed => "mixed",
        }
    }
}

/// `strong`: hits whose name points at a child (`Signals::strong`).
pub fn verdict(hits: usize, strong: usize) -> Verdict {
    if hits == 0 {
        return Verdict::Mixed;
    }
    let share = strong as f64 / hits as f64;
    if share >= 0.25 {
        Verdict::Marker
    } else if hits >= 3 && share < 0.10 {
        Verdict::LikelyFalsePositive
    } else {
        Verdict::Mixed
    }
}

/// May the audit show this name? Only a clean name, in a rule that is not a
/// working marker; for the age rule, only a file that cannot be a picture
/// or a film.
pub fn name_visible(sig: &Signals, verdict: Verdict, layer: Layer, kind: Kind) -> bool {
    if sig.dirty() || verdict == Verdict::Marker {
        return false;
    }
    match layer {
        Layer::L3HashBlock => false,
        // The age rule matched an age next to a sexual word, or an age
        // notation that stands alone: that is the child signal itself, and
        // "audio" is only what the extension says (an .ogg can be a film).
        Layer::L2AgePattern => false,
        // A film, a picture or an archive is never shown, under any rule: a
        // clean-looking name there can still be a studio or series marker
        // with nothing else in it. The false positives that do occur are
        // song, book and program titles that carry a term, and those are
        // what is shown.
        _ => matches!(kind, Kind::Audio | Kind::Doc | Kind::Software),
    }
}

/// A name from outside the blocked set (an alias of an indexed file, a
/// decoy's other names): shown only when it carries no signal at all.
pub fn plain_name_visible(filter: &ContentFilter, name: &str) -> bool {
    let lower = name.to_lowercase();
    !has_explicit(&lower)
        && !has_age(&lower)
        && !has_minor_word(&lower)
        && !filter.check_ignoring_whitelist(&[0u8; 16], name).is_blocked()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_are_found_where_they_are_written_as_ages() {
        for s in ["9yo", "9 yo", "a 12 y.o. b", "13_years", "age 11", "aged 8", "12 anos", "13歳", "13歲"] {
            assert!(has_age(s), "{s}");
        }
        for s in ["x264", "s01e12", "1080p", "track 12", "21 years", "2 kids", "12 monkeys", "5.1"] {
            assert!(!has_age(s), "{s}");
        }
    }

    #[test]
    fn kinds_and_words() {
        assert_eq!(kind_of("Band - Song.MP3"), Kind::Audio);
        assert_eq!(kind_of("a.b.mkv"), Kind::Video);
        assert_eq!(kind_of("Book.epub"), Kind::Doc);
        assert_eq!(kind_of("noext"), Kind::Other);
        assert!(has_explicit("some porno title"));
        assert!(!has_explicit("elephant walk live"));
        assert!(has_minor_word("for kids"));
        assert!(!has_minor_word("kidney stones"));
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(20, 0), Verdict::LikelyFalsePositive);
        assert_eq!(verdict(20, 5), Verdict::Marker);
        assert_eq!(verdict(20, 3), Verdict::Mixed);
        assert_eq!(verdict(2, 0), Verdict::Mixed);
        assert_eq!(verdict(2, 1), Verdict::Marker);
    }

    #[test]
    fn a_term_alone_in_an_ordinary_name_is_shown_and_nothing_else_is() {
        let f = ContentFilter::new().with_extra_terms(vec!["elephant".to_string()]);
        let clean = signals(&f, "Band - Elephant (live).mp3", Layer::L4Extra, "elephant");
        assert!(!clean.dirty());
        assert!(name_visible(&clean, Verdict::LikelyFalsePositive, Layer::L4Extra, Kind::Audio));
        assert!(!name_visible(&clean, Verdict::LikelyFalsePositive, Layer::L4Extra, Kind::Video));
        let dirty = signals(&f, "elephant porno.avi", Layer::L4Extra, "elephant");
        assert!(dirty.explicit && dirty.dirty() && !dirty.strong());
        assert!(!name_visible(&dirty, Verdict::Mixed, Layer::L4Extra, Kind::Video));
        // A clean name in a working marker's group stays hidden.
        assert!(!name_visible(&clean, Verdict::Marker, Layer::L4Extra, Kind::Audio));
        // The age rule hides the name whatever the extension says.
        assert!(!name_visible(&clean, Verdict::LikelyFalsePositive, Layer::L2AgePattern, Kind::Audio));
        // A second listed term is a second marker.
        let f2 = f.with_extra_terms(vec!["walrus".to_string()]);
        let two = signals(&f2, "elephant walrus.mp4", Layer::L4Extra, "elephant");
        assert!(two.marker2);
        // The term across separators is the rule's own term, not a second one.
        let f3 = ContentFilter::new().with_extra_terms(vec!["star sessions".to_string()]);
        for n in ["Star.Sessions set 01.zip", "Star_Sessions set 01.zip", "star sessions set.zip"] {
            assert!(!signals(&f3, n, Layer::L4Extra, "star sessions").marker2, "{n}");
        }
    }
}
