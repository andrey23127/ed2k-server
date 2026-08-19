//! Layer 2: age token + sexual context co-occurrence (SPEC.md §7.6.2).
//!
//! Catches the pattern that defeated AND-only filters: filenames with a
//! numeric age (0-17) plus a sexual-context word in any of several languages.

use super::layer2_terms::Layer2Terms;

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

/// Returns a short description of the age token found ("age 12 (yo)"), or None.
///
/// The description is what makes a block reviewable: "3 Year Dry Spell" and
/// "3 years old girl" both contain the digits 3 and a year unit, and only the
/// rendered token shows which reading was taken. Both live false positives in
/// this layer were spotted exactly this way.
fn contains_minor_age_token(s: &str) -> Option<String> {
    scan_minor_age_token(s, |_, _, _| true)
}

/// Scan for a minor-age token, returning the FIRST one that `accept` allows.
///
/// The predicate exists because callers disagree about what counts. The pairing
/// rule takes any age token; the unpaired rule takes only ages at or below its
/// threshold, written in a compact notation.
///
/// Returning only the first match REGARDLESS of the caller was a real bug:
/// `Prostitutas 11y little baby whore PedoDad 10yo.wmv` was served from the
/// index because the scan stopped at `11y`, whose suffix is not compact, and
/// never reached the `10yo` that the unpaired rule would have fired on. A name
/// was therefore only caught when a qualifying age happened to come FIRST.
fn scan_minor_age_token<F>(s: &str, accept: F) -> Option<String>
where
    F: Fn(u32, &str, usize) -> bool,
{
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
                // Consult `accept` like every other suffix does. This branch
                // used to return unconditionally, which meant it ignored the
                // caller's predicate entirely: the unpaired rule was firing on
                // bare-"y" tokens it had explicitly excluded, and — worse — a
                // bare "y" hid any later token, since the scan returned here
                // before reaching it.
                if accept(age, "bare y", start) {
                    return Some(format!("age {age} (bare y)"));
                }
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
            // NOTE: the school-grade suffixes "年生"/"学年"/"학년" are NOT here.
            // They were, and it was wrong: the digit in front of them is a GRADE,
            // not an age. "中学2年生" is a 14-year-old in the second year of
            // junior high, and this scanner rendered it as "age 2"; "小学6年生"
            // became "age 6". Worse than the mislabelling, the reading is unsafe
            // in the other direction — "大学1年生" is a university FRESHMAN, 18
            // or 19, and parsed as "age 1" it was a minor-age claim. Grades are
            // handled by `contains_school_grade_marker`, which knows what school
            // level each grade belongs to.
        ];
        let mut matched: Option<&str> = None;
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
                    let spelled = matches!(
                        *suffix,
                        "year" | "years" | "año" | "años" | "ano" | "anos"
                            | "jahr" | "лет" | "года" | "год"
                    );

                    // A spelled-out year unit in a DURATION is not an age. The
                    // reference word can follow the number ("3 Year Dry Spell",
                    // "5 years later", "2 years ago") or precede it ("Back After 10
                    // Years", "for 10 years"). All are live false positives from
                    // adult titles; the age reading only holds when the number is a
                    // person's age, not an elapsed span.
                    // ONLY unambiguous duration markers. Notably NOT "old":
                    // "9 years old" is the single most common way a real age is
                    // written, so "old" after a year unit is an AGE, not a span.
                    const AFTER: &[&str] = &[
                        "ago", "назад", "temu", "前", "dry spell", "later",
                        "apart", "anniversary",
                    ];
                    // Reference word right before the number. Kept deliberately
                    // small; "after" covers "Back After 10 Years".
                    const BEFORE: &[&str] = &["after", "spanning"];
                    // Anniversary markers, matched as a SUBSTRING of the text just
                    // before the number rather than as an exact preceding word.
                    //
                    // "anniversary" is already in AFTER, which covers the English
                    // order ("16 Years Anniversary"). Romance languages put it
                    // first — "Aniversário 16 anos" — and that got through as
                    // "age 16" on a Brazilian studio's 16th-anniversary release.
                    //
                    // Substring, and not the exact-word test used for BEFORE,
                    // because the word carries accents: the word-extraction below
                    // splits on non-ASCII-alphabetic characters, so "aniversário"
                    // arrives as "rio". Prefixes also survive the mojibake these
                    // filenames are full of ("AniversÃ¡rio" still contains
                    // "anivers").
                    const ANNIVERSARY: &[&str] =
                        &["annivers", "anivers", "jubil", "jahrestag", "годовщин", "юбиле"];
                    // How far back to look. Short on purpose: the marker has to be
                    // next to the number, so "Anniversary Edition ... 12 years old
                    // girl" is still an age.
                    const ANNIVERSARY_LOOKBACK: usize = 32;
                    if spelled {
                        let tail_hit = AFTER.iter().any(|w| tail.starts_with(w));
                        // Word immediately before the digit run.
                        let prefix = s[..start].trim_end();
                        let prev_word = prefix
                            .rsplit(|c: char| !c.is_ascii_alphabetic())
                            .find(|w| !w.is_empty())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        let before_hit = BEFORE.iter().any(|w| *w == prev_word);
                        // Lookback is in CHARS, not bytes — these names are full of
                        // multi-byte text and slicing by byte offset would panic.
                        let lookback: String = prefix
                            .chars()
                            .rev()
                            .take(ANNIVERSARY_LOOKBACK)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<String>()
                            .to_lowercase();
                        let anniversary_hit =
                            ANNIVERSARY.iter().any(|w| lookback.contains(w));
                        if tail_hit || before_hit || anniversary_hit {
                            continue;
                        }
                    }

                    // A spelled-out unit followed by another NUMBER is a counter,
                    // not an age: "1 Year 83 Cumshots". Abbreviated units are often
                    // followed by a capture year ("12yo 2013 cam"), which stays an
                    // age, so this is limited to the spelled forms.
                    if spelled && tail.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                        continue;
                    }
                    matched = Some(*suffix);
                    break;
                }
            }
        }
        if let Some(suf) = matched {
            if accept(age, suf, start) {
                return Some(format!("age {age} ({suf})"));
            }
            // Rejected by the caller — keep scanning. This is the fix: the loop
            // used to return here unconditionally, so a later qualifying token
            // was never reached.
        }
        // No match - reset and continue scanning
        i = if after_digits > start { after_digits } else { i + 1 };
    }
    None
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Sexual-context vocabulary (multi-language, see SPEC.md §7.6.2).
/// Lowercased substrings — match anywhere in filename.
///
/// Long, unique terms (≥5 chars or non-Latin): always substring match.
/// These cannot reasonably appear inside innocent English/Russian words.
// SEX_TERMS_SUBSTRING moved to Layer2Terms (filter/layer2_terms.rs).

/// Short ambiguous terms — require WORD BOUNDARIES on both sides.
/// Without this, "oral" matches "moral"/"temporal", "anal" matches
/// "analysis"/"anaconda", "nud" matches anything ending in "nud-",
/// "sex" matches "Sussex"/"unisex", causing massive false positives when
/// combined with age tokens like "16 yo behavioral analysis study.pdf".
// SEX_TERMS_WORD_BOUNDED moved to Layer2Terms (filter/layer2_terms.rs).

/// Sex terms that may be FOLLOWED by anything, but must still start at a word
/// boundary.
///
/// English inflects, and the two-sided rule silently lost the inflected forms:
/// `fuck` did not match "Fucking" or "fucked", `nude` did not match "nudes".
/// A live capture found `14Yo Girl And Boy Fucking Live.mp4` being served from
/// the index — the age token was seen, the sexual context was written in plain
/// English, and Layer 2 still did not fire.
///
/// This is the same correction `jargon.rs` received earlier; the two matchers
/// had drifted, and this list is the narrow version of that fix. Only terms
/// whose continuations are safe belong here — measured against ordinary titles:
/// `anal` would take Analog/analysis/Anals, `cum` would take Cumberland/cumbia,
/// `sex` would take Sexton/Sexto, so those stay two-sided above.
// SEX_TERMS_PREFIX moved to Layer2Terms (filter/layer2_terms.rs).

// NOTE on the two above: each does have an innocent host word — "Molestation
// awareness seminar", "Rapeseed oil" — that the left rule does NOT exclude,
// because the term starts those words too. ( "grape" IS excluded: there the
// term starts after a letter.) They are still safe here because Layer 2 fires
// only when a MINOR-AGE token co-occurs, and neither an agricultural paper nor
// a safeguarding seminar carries one. That gate is what makes the whole list
// affordable; a term list without it could not contain these words at all.

/// Sex terms specific enough to match anywhere, including inside a word.
///
/// Checked against ordinary titles: none of these has an innocent host word.
/// Deliberately absent: `dick` (Dick Tracy, Moby Dick), `virgin` (Virginia,
/// Virgin Media), `pussy` (Pussy Riot, Pussycat Dolls) — each has real
/// collisions, and `pussy` only just: it needs word bounds, kept below.
// SEX_TERMS_SUBSTRING_EXTRA moved to Layer2Terms (filter/layer2_terms.rs).

/// Sex terms needing bounds on both sides, added alongside the originals.
// SEX_TERMS_BOUNDED_EXTRA moved to Layer2Terms (filter/layer2_terms.rs).

/// Returns true if `lowered` contains a substring sex term OR a word-bounded short term.
fn contains_sex_term(lowered: &str, t: &Layer2Terms) -> bool {
    if t.sex_substring.iter().any(|w| lowered.contains(w.as_str())) {
        return true;
    }
    let bytes = lowered.as_bytes();
    // Prefix terms: must START at a boundary, may continue into an inflection.
    for term in &t.sex_prefix {
        let mut start = 0;
        while let Some(pos) = lowered[start..].find(term) {
            let abs = start + pos;
            if abs == 0 || !is_word_char(bytes[abs - 1]) {
                return true;
            }
            start = abs + 1;
        }
    }
    for term in &t.sex_bounded {
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
// CJK_MINOR_WORDS moved to Layer2Terms (filter/layer2_terms.rs).

fn contains_cjk_minor_word(s: &str, t: &Layer2Terms) -> bool {
    t.minor_cjk.iter().any(|w| s.contains(w.as_str()))
}

/// Latin-script words that name an age range entirely below 18, with no adult
/// reading.
///
/// These belong in Layer 2 rather than in the operator term list, and the reason
/// is worth stating: as a bare L4 substring "toddler" blocks parenting books,
/// cookbooks and a reality TV series — all checked against real titles. Gated
/// behind Layer 2's sex-term requirement it cannot: "Toddler Nutrition Guide"
/// carries no sexual context, while "[Toddler HC][Handjob]" — the live sample
/// that prompted this — carries two.
///
/// Kept deliberately short. "child", "kid", "baby", "little" and "young" are NOT
/// here: each has ordinary adult readings ("baby" as an endearment, "young" as a
/// comparative) and each appears in legal adult titles, so even age-gating them
/// would not make them safe.
// LATIN_MINOR_WORDS moved to Layer2Terms (filter/layer2_terms.rs).

// "toddler" was here and MOVED BACK to the operator term list (Layer 4).
//
// The reasoning for putting it here was sound and the outcome was not. Gated
// behind Layer 2's sexual-term requirement it protects parenting books — but a
// search-result capture found ten files it let through, because their sexual
// context is not in the term list: "Mom Suck 2 Toddler Boy Boner", "Toddler Boy
// Shows His Dick", "toddler fick" (German), "[Toddler HC][Latina] Sobrinita
// Daniela 5 anos" (no verb at all).
//
// As a bare L4 term it catches all of them and also blocks a handful of
// legitimate titles — parenting guides, cookbooks, a reality series. The
// operator accepted that trade: those go in the hash whitelist as they appear,
// which is a few entries, against tens of files getting through.

/// Bounded on the LEFT only, so a plural still matches.
///
/// "infant" was tried here and removed: allowing a trailing letter makes it
/// match "Infantry", and forbidding one loses "infants". Neither is acceptable,
/// and the word is rare enough in this material that a narrower rule is not
/// worth the risk. "toddler" has no such collision — no ordinary English word
/// continues past it except its own plural.
fn contains_latin_minor_word(lowered: &str, t: &Layer2Terms) -> bool {
    let bytes = lowered.as_bytes();
    for w in &t.minor_latin {
        let mut start = 0;
        while let Some(pos) = lowered[start..].find(w) {
            let abs = start + pos;
            let before_ok = abs == 0 || !is_word_char(bytes[abs - 1]);
            // Trailing letters are allowed ("toddlers"), a leading one is not.
            if before_ok {
                return true;
            }
            start = abs + 1;
        }
    }
    false
}

/// Returns a description of WHY layer 2 fired ("age 12 (yo)", "CJK minor word",
/// ...), or None. The description travels with the block so a reviewer can judge
/// the decision without re-deriving it.
pub(super) fn matches_layer2(original: &str, lowered: &str, t: &Layer2Terms) -> Option<String> {
    // A fixed innocent phrase overrides everything below — see
    // SEX_TERM_EXCEPTIONS.
    if has_sex_term_exception(lowered, t) {
        return None;
    }
    // Both conditions must hold in the same filename: an age claim AND a sexual
    // context. Neither alone is actionable — a 12-year-old's birthday video is
    // not CSAM, and adult pornography is not our concern.
    let age_claim = contains_minor_age_token(original)
        .or_else(|| {
            contains_school_grade_marker(original).then(|| "school grade marker".to_string())
        })
        .or_else(|| contains_cjk_minor_word(original, t).then(|| "CJK minor word".to_string()))
        .or_else(|| {
            contains_latin_minor_word(lowered, t).then(|| "minor-age word".to_string())
        })
        .or_else(|| {
            (count_gender_age_tokens(original) >= 2)
                .then(|| "gender-age pair".to_string())
        })
        .or_else(|| contains_ru_minor_word(lowered, t).then(|| "RU minor word".to_string()))?;
    if contains_sex_term(lowered, t) || contains_ru_sex_term(lowered, t) {
        return Some(age_claim);
    }
    // No sexual term — but an age of 12 or under stands on its own. See
    // UNPAIRED_AGE_MAX for why the pairing rule has to be relaxed there.
    contains_unpaired_minor_age(original, lowered, t)
}

/// Animals that appear in bestiality filenames, and nowhere in the vocabulary of
/// ordinary pornography.
///
/// The list is short because most animal words are ALSO porn slang for a
/// position or a person: "doggy"/"doggystyle" is a position, "bitch" and "beast"
/// describe people, "bull" is a role, "pig" appears in "pig tails". Measured on
/// twelve real adult titles, including those words produced ten false positives
/// out of twelve. What remains are large animals no one is described as.
// ZOO_ANIMALS moved to Layer2Terms (filter/layer2_terms.rs).

/// Acts that, next to one of the animals above, describe bestiality.
///
/// Deliberately EXCLUDES "cock", "dick", "anal" and "sex": each is ordinary porn
/// vocabulary about humans, and "Horse Cock Dildo" is a toy, not an animal.
/// Also excludes "semen", "sperm" and "breed", which belong to veterinary and
/// husbandry texts.
// ZOO_ACTS moved to Layer2Terms (filter/layer2_terms.rs).

/// Veterinary and agricultural contexts, which legitimately pair an animal with
/// a reproductive term.
// ZOO_GUARD moved to Layer2Terms (filter/layer2_terms.rs).

/// Detect bestiality described in plain words rather than by a brand or a slang
/// compound.
///
/// ⚠ NOT WIRED UP. Measured at 8% precision on its first live window — 234
/// matches, 207 of them gay-porn studios ("Raging Stallion"), size metaphors
/// ("horse hung", "donkey dick"), animal-shaped toys ("Bad Dragon") and
/// performer names ("Jesse Pony"). See the disabled call site in filter/mod.rs
/// for why narrowing the lists cannot fix it. Retained because the handful it
/// caught correctly is real and a phrase-based successor could work.
///
/// The existing zoo terms are fixed strings — a brand name, or a two-word
/// compound like "horse cum". A live sample defeated all of them with ordinary
/// English: "Animal Horse Dolly's Farm ... Small Black Pony Cums Inside Dolly's
/// Pussy Then She Does Her Dog". Nothing there is a term; the animals and the
/// acts are simply written out and separated by other words.
///
/// So this pairs the two independently, the same shape as the age rule. The
/// safety comes entirely from how narrow both lists are — see the notes on each.
pub(super) fn matches_zoo_cooccurrence(lowered: &str, t: &Layer2Terms) -> Option<String> {
    if t.zoo_guard.iter().any(|g| lowered.contains(g.as_str())) {
        return None;
    }
    let animal = t.zoo_animals.iter().find(|a| word_present(lowered, a))?;
    let act = t.zoo_acts.iter().find(|a| word_present(lowered, a))?;
    Some(format!("{animal} + {act}"))
}

/// Whole-word test: "horse" must not fire inside "horseradish", and "k9" needs
/// its own boundaries.
fn word_present(lowered: &str, needle: &str) -> bool {
    let bytes = lowered.as_bytes();
    let mut start = 0;
    while let Some(pos) = lowered[start..].find(needle) {
        let abs = start + pos;
        let end = abs + needle.len();
        let before_ok = abs == 0 || !is_word_char(bytes[abs - 1]);
        let after_ok = end == bytes.len() || !is_word_char(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// Phrases that make a broad sexual term innocent.
///
/// Checked BEFORE the term scan and against the whole name: a match here means
/// Layer 2 does not fire at all.
///
/// The problem these solve: "секс" and "голая" are exactly the words these files
/// use, and also exactly the words a sex-education title, a documentary or a
/// 2009 romantic comedy uses. Narrowing the terms loses the catches — removing
/// the two cost five of six in a sample. Naming the innocent PHRASES keeps both,
/// because the phrases are fixed and few.
///
/// Кept to fixed expressions. A phrase list is a maintenance burden that grows
/// with every false positive, so it earns its place only where the single word
/// cannot be fixed and is worth keeping.
// SEX_TERM_EXCEPTIONS moved to Layer2Terms (filter/layer2_terms.rs).

fn has_sex_term_exception(lowered: &str, t: &Layer2Terms) -> bool {
    t.exceptions.iter().any(|p| lowered.contains(p.as_str()))
}

/// Russian words naming a minor.
///
/// The Russian-speaking segment is a large share of this network and NOTHING in
/// any list covered it — not the jargon file, not the operator terms, not the
/// age scanner. English, German, Spanish, Italian and CJK were all represented;
/// Russian was simply absent. A search sample found
/// `! - Летняя Лолита реально ШКОЛЬНИЦА)) - но как ЕБЁТСЯ!!о)).mp4` sitting in
/// the index with both halves of the Layer 2 rule written out in plain Russian.
///
/// STEMS, not whole words, because Russian inflects heavily: `школьниц` covers
/// школьница / школьницы / школьницу / школьницей. The stems stop short of the
/// endings on purpose.
///
/// ⚠ These are ordinary words and are ONLY safe behind the sexual-term
/// requirement. Measured against thirteen legitimate Russian titles — the film
/// «Школьница 2», «Дневник школьницы», Dostoevsky's «Подросток», a law lecture
/// on «Несовершеннолетние», an «Ералаш» episode — a bare term list matched NINE
/// of the thirteen. Paired with a sexual term: zero.
// RU_MINOR_WORDS moved to Layer2Terms (filter/layer2_terms.rs).

/// Russian sexual terms, as they appear in filenames rather than in dictionaries.
///
/// Both ё and е spellings are listed: filenames use them interchangeably, and
/// `ебёт`/`ебет` are the same word to everyone except a byte comparison.
///
/// Kept crude and specific. Nothing here has an innocent reading — unlike
/// "секс" or "голая", which appear in medical, artistic and news titles and are
/// deliberately absent.
// RU_SEX_TERMS moved to Layer2Terms (filter/layer2_terms.rs).

// NOT added, and worth recording why:
//
//   "секс"       — "сексуальное воспитание", "сексуальная революция", and the
//                  bare noun in any documentary title. Only the instrumental
//                  case "сексом" is listed, which is what "заниматься сексом"
//                  produces and which no lecture title uses.
//   "сексуальн"  — same problem, and it is the word that leaves
//                  "Мальчик и его сексуальная зайка" uncaught. Accepted: that
//                  file needs its hash listed.
//   "эротик"     — European art cinema of the 1970s is full of it.
//   "обнажён"    — art and photography.
//   "голая"      — "Голая правда" is a 2009 romantic comedy and a stock phrase
//                  ("голая правда о детском питании"). Only the diminutive
//                  "голенькая" is kept: nobody titles a documentary that.
//
// A LIMIT that no word list fixes: "Дети и порнография — доклад ЮНЕСКО" pairs a
// minor marker with a sexual term and is a UNESCO report on the subject. Any
// pairing rule blocks writing ABOUT the crime along with the crime. Such files
// go in whitelist_hashes.txt; there is no phrasing that separates them
// automatically, because the words genuinely are the same.

/// Substring match: Cyrillic has no ASCII word characters, so the boundary rules
/// used for Latin terms would never apply here anyway — and stems are meant to
/// match inside inflected forms.
fn contains_ru_minor_word(lowered: &str, t: &Layer2Terms) -> bool {
    t.minor_ru.iter().any(|w| lowered.contains(w.as_str()))
}

fn contains_ru_sex_term(lowered: &str, t: &Layer2Terms) -> bool {
    t.sex_ru.iter().any(|w| lowered.contains(w.as_str()))
}

/// Ages at or below this need no sexual term to be actionable on their own.
///
/// Layer 2 normally requires an age claim AND a sexual context, because a
/// 12-year-old's birthday video is not our concern. That pairing has a blind
/// spot: publishers write the age and then describe the act in a language the
/// term list does not cover, or not at all. A live capture of search results
/// found twelve such files being served — "Webcam - 12yo UK girl & 10yo
/// brother", "Artem(12yo) - Дрочь", "jenny 3yo sdpa moscow" — every one
/// carrying an explicit age and no English sexual term.
///
/// Below 13, an age written into a filename on a file-sharing network is itself
/// the anomaly. Legal material does not label its participants "11yo"; the
/// notation exists to advertise. Measured on a 22 007-name review window: 4224
/// names carry an age of 12 or under, 88 of them have neither jargon nor a
/// sexual term — and all 88 are unambiguous. Not one false positive.
///
/// 12 rather than higher on purpose. At 13-17 the notation does appear in legal
/// contexts (a teenager's own upload, a documentary), and the pairing rule still
/// applies there.
// UNPAIRED_AGE_MAX moved to Layer2Terms::unpaired_age_max.

/// Words that make a small number an age of something OTHER than a person.
///
/// Whisky is the real case: "Macallan 12yo", "12 yo single malt", "aged 15 yr"
/// are ordinary product descriptions using exactly the notation this rule keys
/// on. Service intervals and warranties do the same.
///
/// Checked WITHIN A WINDOW around the number, not across the whole name: the
/// review window contains 25 names where a guard word sits far from the age and
/// the file is plainly CSAM — "(Pthc) Vintage Collection ... 11Yo Girl". A
/// whole-name check would have lost every one of them.
// AGE_GUARD_WORDS moved to Layer2Terms (filter/layer2_terms.rs).

// "vintage" and "aged" are in the list despite appearing in CSAM names too
// ("(Pthc) Vintage Collection ... 11Yo Girl"). The proximity window is what
// makes that safe: in those names the word sits many words away from the age,
// while "12yo vintage port" has it adjacent. Verified on the review window —
// all 25 names where a guard word co-occurs with an age still match.

/// How far either side of the number a guard word disqualifies it, in bytes.
/// Deliberately tight — "12yo single malt" is 15 characters, while the CSAM
/// names that merely contain "vintage" have it many words away.
// AGE_GUARD_WINDOW moved to Layer2Terms::age_guard_window.

/// True if a guard word sits close enough to `pos` to explain the number.
fn age_is_guarded(lowered: &str, pos: usize, t: &Layer2Terms) -> bool {
    let lo = pos.saturating_sub(t.age_guard_window);
    let hi = (pos + t.age_guard_window).min(lowered.len());
    // Snap to char boundaries — filenames are full of multi-byte text and
    // slicing mid-character panics.
    let lo = (lo..=pos).find(|i| lowered.is_char_boundary(*i)).unwrap_or(pos);
    let hi = (pos..=hi).rev().find(|i| lowered.is_char_boundary(*i)).unwrap_or(pos);
    let window = &lowered[lo..hi];
    t.age_guard.iter().any(|w| window.contains(w.as_str()))
}

/// Does this name carry an age of 12 or under, unguarded?
///
/// Returns the same reason string shape as `contains_minor_age_token`, with the
/// age spelled out, so a reviewer reading the export can see which number fired.
fn contains_unpaired_minor_age(original: &str, lowered: &str, t: &Layer2Terms) -> Option<String> {
    // Ask the scanner for the first token that BOTH is within the threshold and
    // uses a compact notation, rather than taking whatever came first and then
    // testing it. Those are different questions, and answering the second cost
    // us a served file: a name whose first age was "11y" (not compact) never got
    // as far as its "10yo".
    // EVERY condition goes in the predicate, including the guard check. Testing
    // them afterwards was the bug in two ways: a first token with the wrong
    // suffix hid a later valid one, and a first token sitting next to a guard
    // word hid a later unguarded one. "Macallan 12yo tasting and 9yo girl" is
    // the second case — 12yo qualifies on age and notation, is guarded by
    // "tasting", and the scan has to keep going to reach 9yo.
    let reason = scan_minor_age_token(original, |age, suffix, pos| {
        // Compact notations only. "12 years" is ordinary English — without this
        // "12 Years a Slave" is blocked — so spelled-out units, and every
        // non-English unit, keep the pairing requirement.
        age <= t.unpaired_age_max
            // "bare y" ("12y", attached with no space) is compact and IS
            // included, on measurement: 569 catches in one review window with
            // not one false positive among them. The risk it carries — a
            // Windows build number, a phone model, a car warranty — is covered
            // by the guard words, which name those contexts.
            && matches!(suffix, "yo" | "y.o" | "yr" | "yrs" | "bare y")
            // `pos` indexes `original`; the guard scan wants the lowered copy.
            // They are byte-identical in length for the ASCII digits this
            // matches on, and `age_is_guarded` snaps to char boundaries anyway.
            && !age_is_guarded(lowered, pos, t)
    })?;
    Some(format!("{reason} unpaired"))
}

/// School words paired with the highest grade that level actually has.
///
/// The grade cap is what makes the marker a MINOR-age claim rather than a bare
/// number: elementary runs 1-6 (ages ~6-12), junior high 1-3 (~12-15). A digit
/// outside the level's range is not a grade at all and must not match — "田中4"
/// is a surname followed by a number, not a fourth-year junior-high student.
///
/// ⚠ High school (高/고) and university (大学/대학) are deliberately ABSENT.
///   Their students can be 18 or over, so a grade there is not a minor-age
///   claim. This is the same reasoning that keeps 女子校生 out of
///   `CJK_MINOR_WORDS`. In particular "大学1年生" (a freshman, 18-19) must NOT
///   read as an age claim of any kind.
///
/// Longer school words come first so the specific form is tried before the bare
/// one; the scan returns on the first hit either way, so this is for clarity.
const SCHOOL_GRADES: &[(&str, u32)] = &[
    ("小学", 6),     // JP elementary, long form: 小学6年生
    ("小學", 6),     // ditto, traditional
    ("초등학교", 6), // KR elementary, long form: 초등학교 6학년
    ("中学", 3),     // JP junior high, long form: 中学2年生
    ("中學", 3),     // ditto, traditional
    ("初中", 3),     // CN junior high: 初中3年级
    ("중학교", 3),   // KR junior high
    ("小", 6),       // short forms: 小6
    ("초", 6),       // 초6
    ("中", 3),       // 中1
    ("중", 3),       // 중1
];

/// Detect Japanese/Korean/Chinese lower-school grade markers, where the grade
/// number follows the school word: "中1", "小6", "중1", "초6", and the long
/// forms "小学6年生", "中学2年生", "초등학교 6학년".
///
/// These are minor-age claims that `contains_minor_age_token` cannot see,
/// because the digit comes AFTER the school word rather than before a unit.
///
/// The long forms used to be reached by listing "年生"/"学年"/"학년" as age
/// suffixes, which read the grade number as an age and — since it never
/// consulted the school word — accepted university years as ages 1-4. Matching
/// the school word first is what supplies the missing context.
fn contains_school_grade_marker(s: &str) -> bool {
    for (word, max_grade) in SCHOOL_GRADES {
        let mut from = 0;
        while let Some(rel) = s[from..].find(word) {
            let abs = from + rel;
            let mut i = abs + word.len();
            // Tolerate spacing between the school word and the grade, as in
            // "초등학교 6학년".
            while s[i..].starts_with(' ') {
                i += 1;
            }
            if let Some(c) = s[i..].chars().next() {
                if let Some(d) = c.to_digit(10) {
                    if (1..=*max_grade).contains(&d) {
                        return true;
                    }
                }
            }
            from = abs + word.len();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // The tests call these as they always did; the vocabulary comes from
    // Layer2Terms::default(), which IS the vocabulary that used to be compiled
    // in. So every assertion below still pins the same behaviour as before the
    // lists moved out of the binary — which is the point of keeping them
    // unchanged.
    fn matches_layer2(original: &str, lowered: &str) -> Option<String> {
        super::matches_layer2(original, lowered, &Layer2Terms::default())
    }
    fn matches_zoo_cooccurrence(lowered: &str) -> Option<String> {
        super::matches_zoo_cooccurrence(lowered, &Layer2Terms::default())
    }
    fn contains_cjk_minor_word(s: &str) -> bool {
        super::contains_cjk_minor_word(s, &Layer2Terms::default())
    }


    // ── Regression tests from live production data (2026-07) ─────────────
    // Every string below is a REAL filename observed on the server. The blocked
    // ones passed all filter layers before this revision; the allowed ones were
    // wrongly blocked by it.

    #[test]
    fn inflected_sex_terms_are_recognised() {
        // Live: `14Yo Girl And Boy Fucking Live.mp4` was being SERVED from the
        // index. The age token was seen and the sexual context was written in
        // plain English, but "fuck" was matched with bounds on both sides, so
        // "Fucking" did not count. Same for "fucked", "nudes", "molested".
        for name in [
            "14Yo Girl And Boy Fucking Live.mp4",
            "Danish teen 14yo fucked outside.mpg",
            "boy 14yo nudes collection.avi",
            "German Little Girls Molested 14yo.avi",
            "Two boys 14 and 13 yo naked.avi",
            "Anon025 Girl 14Yo Pussy Stickam.avi",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_some(),
                "{name} must be caught"
            );
        }
    }

    #[test]
    fn sex_term_prefixes_do_not_fire_inside_words() {
        // The narrow fix, not a blanket one: terms whose continuations are NOT
        // safe stay bounded on both sides. Each of these is an ordinary word
        // that a looser rule would have taken.
        // Age 15, not 12: at 12 and under the age alone is actionable
        // (UNPAIRED_AGE_MAX), which would mask what this test is checking.
        for name in [
            "Data analysis of moral values 15yo study.pdf", // anal / oral
            "The Cumberland Gap 1080p 15yo.mkv",            // cum
            "The Sexton Blake Library 15yo.epub",           // sex
            "Cumbia Colombiana mix 15yo.mp3",               // cum
            "Nudge - Thaler and Sunstein 15yo.epub",        // nud
            "Analog Devices datasheet 15yo.pdf",            // anal
            "Cockney accent guide 15yo.pdf",                // cock
            "Dick Tracy 1990 15yo.avi",                     // not in any list
            "Virginia Woolf biography 15yo.epub",           // not in any list
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_none(),
                "{name} must NOT be caught — the age token is there, so only a \
                 wrongly-matched sex term could block it"
            );
        }
    }

    #[test]
    fn latin_minor_words_need_a_sexual_context() {
        // "toddler" USED to live here and was moved back to the operator term
        // list — see the note on LATIN_MINOR_WORDS. What remains is the German
        // equivalent, which has no innocent reading either.
        assert!(matches_layer2(
            "kleinkind hardcore fuck video.mp4",
            "kleinkind hardcore fuck video.mp4"
        )
        .is_some());

        // Without a sexual term, nothing fires.
        for innocent in [
            "Kleinkind Ernährung Ratgeber.pdf",
            "kleinkind spielzeug test 2024.mp4",
        ] {
            assert!(
                matches_layer2(innocent, &innocent.to_lowercase()).is_none(),
                "{innocent} must not be blocked"
            );
        }

        // Left-bounded, so an ordinary word containing the term is not a match.
        assert!(matches_layer2("unkleinkind xxx.avi", "unkleinkind xxx.avi").is_none());
    }

    #[test]
    fn russian_needs_both_halves() {
        // The gap this closes: nothing in any list covered Russian, and a search
        // sample found this sitting in the index with both halves of the rule
        // written out in plain Russian.
        let n = "! - Летняя Лолита реально ШКОЛЬНИЦА)) - но как ЕБЁТСЯ!!о)).mp4";
        assert!(matches_layer2(n, &n.to_lowercase()).is_some());

        for name in [
            "малолетка сосет у отчима.avi",
            "школьница трахается с учителем.mp4",
            "изнасиловал несовершеннолетнюю видео.avi",
            "подростки ебутся на даче.mpg",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_some(),
                "{name} must be caught"
            );
        }
    }

    // NOTE: the function these exercise is NOT wired into check() — see the
    // disabled call site in filter/mod.rs. They are kept so a future
    // phrase-based successor has a baseline of what it must and must not match.
    #[test]
    fn zoo_cooccurrence_catches_plain_english() {
        // The sample that prompted this: every existing zoo term is a fixed
        // string, and this name uses none of them — the animal and the act are
        // ordinary words several words apart.
        let n = "1 Animal Horse Dolly's Farm (Part 1)Small Black Pony Cums Inside \
                 Dolly's Pussy Then She Does Her Dog.mp4";
        assert!(matches_zoo_cooccurrence(&n.to_lowercase()).is_some());

        for name in [
            "girl fucked by horse.avi",
            "mare knot pussy.mpg",
            "pony cums inside her.avi",
            "k9 fuck compilation.avi",
        ] {
            assert!(
                matches_zoo_cooccurrence(&name.to_lowercase()).is_some(),
                "{name} must be caught"
            );
        }
    }

    #[test]
    fn zoo_lists_avoid_porn_slang_and_veterinary_texts() {
        // Most animal words are also porn vocabulary for a position or a person.
        // A wider list was measured first and produced ten false positives in
        // twelve real adult titles; this test is what keeps the list narrow.
        for name in [
            "Doggy Style Anal Compilation HD.mp4",   // a position, not an animal
            "Doggystyle Fuck Brazzers 2019.mp4",
            "Riding Cock Doggy Position.avi",
            "Horse Cock Dildo Toy Play - solo.mp4",  // a toy: "cock" is excluded
            "Big Dick Bull Riding Cowgirl.mp4",
            "Bitch Sucks Cock POV.mp4",
            "Beast Mode Fuck Session.mp4",
            "Pig Tails Teen Sex Comp.mp4",
        ] {
            assert!(
                matches_zoo_cooccurrence(&name.to_lowercase()).is_none(),
                "{name} must NOT be caught"
            );
        }

        // Veterinary and husbandry texts legitimately pair an animal with a
        // reproductive term.
        for name in [
            "Horse breeding stallion semen collection - veterinary.pdf",
            "Equine artificial insemination manual.pdf",
            "Mare pregnancy and breeding guide.pdf",
        ] {
            assert!(
                matches_zoo_cooccurrence(&name.to_lowercase()).is_none(),
                "{name} must NOT be caught"
            );
        }

        // Ordinary films and documentaries.
        for name in [
            "Dog Day Afternoon 1975.mkv",
            "The Horse Whisperer 1998.avi",
            "War Horse Spielberg 2011.mkv",
            "My Little Pony The Movie.mkv",
            "Wild Horses documentary BBC.mkv",
            "Black Beauty 1994 horse.mkv",
        ] {
            assert!(
                matches_zoo_cooccurrence(&name.to_lowercase()).is_none(),
                "{name} must NOT be caught"
            );
        }
    }

    #[test]
    fn zoo_cooccurrence_is_why_the_rule_is_disabled() {
        // Every one of these matched in the first live window and every one is
        // legitimate adult material. They are the measurement that took the rule
        // out of check(): the animal words ARE studio names, performer names and
        // size metaphors, so no narrowing of the lists reaches them.
        for name in [
            "Raging Stallion - Fuck Flik #1 [Blake Harper, Jason Branch].mp4",
            "Donkey Dick XXL fucks CJ Muscle Jock.mp4",
            "Lily Lou Is Fucking A Huge Horse Bad Dragon Dildo.mp4",
            // Full name, not shortened: the act word is what makes it match, and
            // trimming the title for readability removed it — the first version
            // of this test asserted a match the shortened string cannot produce.
            "BrutalSessions - Extreme Bondage And Fucking - Jesse Pony And Johnny Castle.mp4",
            "Chocolate - LadyBoys Fucked Bareback - Dark Stallion Messy Hole.mp4",
            "Onlyfans ThatYoungBlonde Fucked After Horse Show Sextape.mp4",
        ] {
            assert!(
                matches_zoo_cooccurrence(&name.to_lowercase()).is_some(),
                "{name} still matches — this test documents the failure, not a fix"
            );
        }
    }

    #[test]
    fn zoo_animal_needs_word_boundaries() {
        // "horse" must not fire inside "horseradish".
        assert!(matches_zoo_cooccurrence("horseradish sauce fucking good.avi").is_none());
    }

    #[test]
    fn russian_second_set_catches_the_plain_register() {
        // The first Russian list was written from a single filename and guessed
        // the wrong register — legal and scholastic words. A review window with
        // 428 Cyrillic names used none of them and all of these.
        for name in [
            "Самое развратное детское порно, 5 русских девочек.avi",
            "Русские Дети 6-14 Лет Занимаются Сексом Дома И На Природе.avi",
            "девочка лет 13-14 ,стриптиз, мастурбация.avi",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_some(),
                "{name} must be caught"
            );
        }
    }

    #[test]
    fn russian_common_words_stay_out_of_the_lists() {
        // "секс" and "голая" ARE in the term list — they are how these files are
        // named. What keeps these titles safe is SEX_TERM_EXCEPTIONS, and this
        // test is what stops someone from deleting that list as redundant.
        for name in [
            "Голая правда 2009 комедия.mkv",             // fixed idiom, and a film
            "Голая правда о детском питании.pdf",        // same idiom + a minor marker
            "Сексуальное воспитание детей - Спок.pdf",   // sex education
            "Эротика 70-х европейское кино.avi",         // "эротик" not listed
            "Детский психолог о половом воспитании.pdf",
            "Защита детей от совращения - методичка МВД.pdf",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_none(),
                "{name} must NOT be caught"
            );
        }
    }

    #[test]
    fn russian_minor_words_alone_block_nothing() {
        // These are ORDINARY WORDS. A bare term list matched nine of the
        // thirteen legitimate titles below — the film «Школьница 2», Dostoevsky's
        // «Подросток», a law lecture, an «Ералаш» episode. Only the pairing
        // requirement makes them usable at all, and this test is what stops
        // someone from "simplifying" them into the operator term file later.
        for name in [
            "Школьница 2 (2018) фильм HDRip.avi",
            "Дневник школьницы - драма 2005.mkv",
            "Школьница-убийца детектив.avi",
            "Малолетка - Руки Вверх.mp3",
            "Подросток Достоевский аудиокнига.mp3",
            "Трудный подросток сериал 2019.mkv",
            "Несовершеннолетние - лекция по праву.pdf",
            "Подростковая психология учебник.pdf",
            "Ералаш - Школьница и учитель.avi",
            "Подростковый возраст - Выготский.pdf",
            "Школьник года - конкурс 2019.mp4",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_none(),
                "{name} must NOT be caught"
            );
        }
    }

    #[test]
    fn russian_sex_terms_alone_block_nothing() {
        // Symmetric check: a sexual term with no minor marker is adult content,
        // which is not this filter's business.
        for name in [
            "Изнасилование - статья УК РФ комментарий.pdf",
            "Порево - панк группа дискография.rar",
            "две зрелые женщины ебутся.avi",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_none(),
                "{name} must NOT be caught"
            );
        }
    }

    #[test]
    fn russian_yo_and_ye_spellings_both_match() {
        // ебёт / ебет, сосёт / сосет — the same word to a reader, different
        // bytes to a comparison, and filenames use both.
        for name in ["школьница ебёт.avi", "школьница ебет.avi",
                     "малолетка сосёт.avi", "малолетка сосет.avi"] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_some(),
                "{name} must be caught"
            );
        }
    }

    #[test]
    fn ages_of_twelve_and_under_stand_alone() {
        // The rule these test: below 13, an age written into a filename is the
        // anomaly by itself. From a search-result capture, all served with no
        // English sexual term anywhere in the name.
        for name in [
            "Webcam - 12yo UK girl & 10yo brother (part 3).mp4",
            "jenny 3yo sdpa moscow.mov",
            "Artem(12yo)2014-02-12 - Дрочь ХД.mp4",
            "11Yr 14Yr Julia and Natasha play with the Operator.avi",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_some(),
                "{name} must be caught on the age alone"
            );
        }
    }

    #[test]
    fn the_bare_y_branch_consults_the_predicate() {
        // It used to return unconditionally, ignoring the caller entirely. Two
        // consequences, both live: the unpaired rule fired on a notation it had
        // excluded, and a bare "y" hid any later token because the scan returned
        // before reaching it.
        //
        // "bare y" is now an accepted unpaired notation on measurement — 569
        // catches in one window, no false positive — so what this pins is that
        // the GUARD still applies to it.
        for name in [
            "Windows 11y build.iso",
            "Model 12y specification.pdf",
            "iPhone 12y case review.mp4",
            "Macallan 12y single malt.jpg",
            "BMW 10y warranty.pdf",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_none(),
                "{name} must NOT be caught — a guard word sits beside the number"
            );
        }
        // ...while an unguarded one is.
        let n = "some 11y video.avi";
        assert!(matches_layer2(n, &n.to_lowercase()).is_some());
    }

    #[test]
    fn a_qualifying_age_is_found_even_when_it_is_not_the_first() {
        // THE BUG: the scan returned the first age token whatever it was, and
        // the unpaired rule then tested that one. A name whose first age used a
        // non-compact suffix therefore never reached a later compact one.
        //
        // Live case, served from the index: "11y" comes first and does not
        // qualify (bare "y"), "10yo" comes later and does.
        let n = "Prostitutas 11y little baby whore PedoDad 10yo.wmv";
        assert!(
            matches_layer2(n, &n.to_lowercase()).is_some(),
            "the later qualifying age must be found"
        );

        // Same shape, ages reversed: this one always worked, and must keep
        // working.
        let n2 = "some 10yo and 11y thing.avi";
        assert!(matches_layer2(n2, &n2.to_lowercase()).is_some());

        // And a name whose ONLY ages are non-compact still needs a sexual term,
        // or "12 Years a Slave" comes back.
        let n3 = "13 years and 15 years later.mkv";
        assert!(matches_layer2(n3, &n3.to_lowercase()).is_none());
    }

    #[test]
    fn a_guarded_age_does_not_hide_a_later_unguarded_one() {
        // The scan must get past an age a guard word disqualifies, not stop at
        // it. The second age here is far enough from "tasting" to be outside the
        // proximity window.
        let n = "Macallan 12yo tasting notes, and separately a 9yo girl video.avi";
        assert!(
            matches_layer2(n, &n.to_lowercase()).is_some(),
            "the unguarded age must still be found"
        );

        // ...but an age inside the window stays disqualified.
        let n2 = "Macallan 12yo single malt tasting notes.pdf";
        assert!(matches_layer2(n2, &n2.to_lowercase()).is_none());
    }

    #[test]
    fn spelled_out_years_still_need_a_sexual_term() {
        // THE limit on the rule above, and the reason it is safe. "12yo" is
        // file-sharing shorthand written to advertise; "12 years" is ordinary
        // English. Only the compact forms stand alone.
        //
        // Caught by the test suite, not by the sample used to validate the
        // threshold — that sample happened to contain only "12yo"/"12 yr".
        for name in [
            "12 Years a Slave (2013).mkv",
            "12 year old anaconda documentary.mp4",
            "10 year old corporate moral handbook.pdf",
            "Aged 10 years, a whisky documentary.mp4",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_none(),
                "{name} must NOT be caught — spelled-out units keep the pairing rule"
            );
        }
    }

    #[test]
    fn a_guard_word_beside_the_number_disqualifies_it() {
        // Whisky and service intervals use exactly this notation.
        for name in [
            "Macallan 12yo tasting notes.pdf",
            "Whisky 12 yo single malt review.mp4",
            "Yamaha YZ 12 yr service manual.pdf",
            "Port 10yo vintage bottle.jpg",
        ] {
            assert!(
                matches_layer2(name, &name.to_lowercase()).is_none(),
                "{name} must NOT be caught — a guard word sits beside the age"
            );
        }
        // ...but the window is tight, so a guard word far from the age does not
        // rescue a name. 25 files in one review window depend on this.
        let n = "(Pthc) Vintage Collection Inc Chinese 11Yo Girl.avi";
        assert!(
            matches_layer2(n, &n.to_lowercase()).is_some(),
            "a distant guard word must not disqualify the age"
        );
    }

    #[test]
    fn anniversary_before_the_number_is_not_an_age() {
        // Live false positive: a Brazilian studio's 16th-anniversary release.
        // The marker precedes the number, and it is accented.
        assert!(contains_minor_age_token(
            "Hot Boys - Aniversário 16 anos (16th Anniversary) HotBoys, Parte 2.mp4"
        )
        .is_none());
        // Mojibake form, which is how these arrive over the wire more often than not.
        assert!(contains_minor_age_token("Hot Boys - AniversÃ¡rio 16 anos, Parte 2.mp4").is_none());
        assert!(contains_minor_age_token("Jubiläum 15 Jahre Studio.avi").is_none());
        assert!(contains_minor_age_token("Юбилей 10 лет студии.avi").is_none());
        // English order was already covered by the AFTER list; keep it covered.
        assert!(contains_minor_age_token("16 Years Anniversary Edition.mp4").is_none());

        // The marker must be NEXT to the number. Far away, an age is still an age.
        assert!(contains_minor_age_token(
            "Anniversary Edition of a long and rambling title here - 12 years old girl sex.avi"
        )
        .is_some());
        // And an ordinary age near an unrelated word is untouched.
        assert!(contains_minor_age_token("universe 12 years old sex.avi").is_some());
    }

    #[test]
    fn regression_numbering_and_timespans_are_not_ages() {
        // Live false positives from the 2026-07-23 review, all legal content.
        // Episode/volume numbering read as an age of 0:
        assert!(contains_minor_age_token(
            "[Lust Cinema] Erika Lust XConfessions Vol. 26 Ep 0Y - Asmr - The Sound Of Sex"
        ).is_none());
        // A duration read as an age of 1:
        assert!(contains_minor_age_token(
            "Onlyfans - Cumpilation 2019, 1 Year 83 Cumshots! (Bareback)"
        ).is_none());
        // A point in the past read as an age of 3:
        assert!(contains_minor_age_token(
            "FC2-PPV-3238169 An Innocent Wife ... From About 3 Years Ago, My Wife"
        ).is_none());
        // Durations that read forward or as a gap, not an age (live FPs):
        assert!(contains_minor_age_token(
            "Bang - Phoebe Kalib - Gets Into Porn After 3 Year Dry Spell").is_none());
        assert!(contains_minor_age_token(
            "AnalMom - Amirah Adara ... Back After 10 Years").is_none());
        // CRITICAL: "N years old" is the commonest way a real age is written and
        // must ALWAYS count — the duration guard must never swallow it:
        assert!(contains_minor_age_token("9 years old girl").is_some());
        assert!(contains_minor_age_token("16 years old Teen naked").is_some());
        assert!(contains_minor_age_token("13 Year Old Sister").is_some());
        // But real ages still count, including the low ones that DO occur in
        // real material — the fix must not buy precision with coverage:
        assert!(contains_minor_age_token("3 years old girl").is_some());
        assert!(contains_minor_age_token("PornoKid LOLITA8 rare lolita 1yo whore").is_some());
        assert!(contains_minor_age_token("01yo incest GraceL baby girl").is_some());
        // An age followed by the year of capture is still an age (this is why the
        // counter guard is limited to spelled-out units).
        assert!(contains_minor_age_token("cacazinha 12yo 2013 cam").is_some());
    }

    #[test]
    fn regression_bare_y_suffix_is_an_age() {
        // Four minor ages in one name, none previously recognised: "y" was not a
        // suffix and the "G12"/"B15" form was skipped entirely.
        assert!(contains_minor_age_token("BroSis G12 B15 12y Sis Blows 15y Bro").is_some());
        assert!(contains_minor_age_token("16y girl fuck with her 8y bro").is_some());
        assert!(contains_minor_age_token("Daughter 12Yr").is_some());
    }

    #[test]
    fn regression_spanish_y_is_not_an_age() {
        // "y" = "and" in Spanish. Only the attached form counts, so a spaced "y"
        // must NOT read as an age suffix.
        assert!(contains_minor_age_token("Ana 15 y Maria en la playa").is_none());
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
        assert!(contains_minor_age_token(name).is_none());
        assert!(matches_layer2(name, &name.to_lowercase()).is_none());
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
                contains_minor_age_token(name).is_none(),
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
            assert!(matches_layer2(name, &name.to_lowercase()).is_none(),
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
            assert!(matches_layer2(name, &name.to_lowercase()).is_some(),
                "should be blocked: {name:?}"
            );
        }
    }

    #[test]
    fn detects_yo() {
        assert!(contains_minor_age_token("Some Movie 8yo Foo.mp4").is_some());
        assert!(contains_minor_age_token("8 yo bar").is_some());
        assert!(contains_minor_age_token("12yr something").is_some());
        assert!(contains_minor_age_token("10 year old").is_some());
    }

    #[test]
    fn ignores_non_age_numbers() {
        assert!(contains_minor_age_token("Linux 2024 release.iso").is_none());
        assert!(contains_minor_age_token("MP3 192kbps.mp3").is_none());
        assert!(contains_minor_age_token("v1.2.3.zip").is_none());
    }

    #[test]
    fn ignores_adult_ages() {
        assert!(contains_minor_age_token("woman 30 years old.mp4").is_none());
        assert!(contains_minor_age_token("25yo cat photo").is_none());
    }

    #[test]
    fn boundary_check() {
        // "boyo" should NOT match "yo" with age "bo" - we require digit
        assert!(contains_minor_age_token("playing.mp4").is_none());
        // "report 2024.pdf" - 2024 is too big for minor age
        assert!(contains_minor_age_token("report 2024.pdf").is_none());
    }

    #[test]
    fn layer2_combined() {
        // Real attack pattern observed in capture (sanitized):
        let lowered = "[xxx] 8yo movie.mp4".to_lowercase();
        assert!(matches_layer2("[xxx] 8yo movie.mp4", &lowered).is_some());
    }

    #[test]
    fn layer2_innocent_age_no_sex() {
        // "12 Years a Slave" - 12 is in age range but no sex term
        let s = "12 Years a Slave (2013).mkv";
        let l = s.to_lowercase();
        assert!(matches_layer2(s, &l).is_none());
    }

    #[test]
    fn layer2_sex_no_minor_age() {
        // Adult content - no minor age - should not match
        let s = "30yo-mature-adult.mp4";
        let l = s.to_lowercase();
        assert!(matches_layer2(s, &l).is_none());
    }

    // ── False-positive regression tests (root cause of 60043 CSAM blocks bug) ──
    // Short ambiguous sex terms (anal/oral/nud) were matching as substrings of
    // common innocent words (analysis/moral/Nudity-the-statue) and combined with
    // legitimate age tokens (14 years, 16 yo) caused mass false-positive blocks.

    #[test]
    fn layer2_fp_analysis_with_age() {
        let s = "16 yo behavioral analysis study.pdf";
        let l = s.to_lowercase();
        assert!(matches_layer2(s, &l).is_none(),
                "FALSE POSITIVE: 'analysis' contains 'anal' substring");
    }

    #[test]
    fn layer2_fp_years_analysis() {
        let s = "14 years analysis report.pdf";
        let l = s.to_lowercase();
        assert!(matches_layer2(s, &l).is_none());
    }

    #[test]
    fn layer2_fp_moral_with_age() {
        let s = "10 year old corporate moral handbook.pdf";
        let l = s.to_lowercase();
        assert!(matches_layer2(s, &l).is_none(),
                "FALSE POSITIVE: 'moral' contains 'oral' substring");
    }

    #[test]
    fn layer2_fp_anaconda_movie() {
        // Common movie filename with "anaconda" which contains "anac" but not "anal" — should pass
        // Test that "12 year old anaconda" doesn't FP
        let s = "12 year old anaconda documentary.mp4";
        let l = s.to_lowercase();
        // "anaconda" contains "ana" but not "anal" so should NOT match the word-bounded "anal" term
        assert!(matches_layer2(s, &l).is_none());
    }

    #[test]
    fn cjk_age_suffixes_detected() {
        // Japanese 歳/才, Korean 세 — digit 0-17 + suffix = minor age token.
        assert!(contains_minor_age_token("動画 13歳 something.mp4").is_some());
        assert!(contains_minor_age_token("13才 video").is_some());
        assert!(contains_minor_age_token("13세 clip.avi").is_some());
        // Adult ages must NOT match.
        assert!(contains_minor_age_token("25歳 woman.mp4").is_none());
        assert!(contains_minor_age_token("30세 adult.mp4").is_none());
    }

    #[test]
    fn school_grade_markers_detected() {
        assert!(contains_school_grade_marker("中1 something"));   // JHS yr1
        assert!(contains_school_grade_marker("小6 video"));        // elem yr6
        assert!(contains_school_grade_marker("중1 clip"));         // KR JHS yr1
        assert!(contains_school_grade_marker("초6 file"));         // KR elem yr6

        // Long forms — these used to be reached only via the "年生" age suffix,
        // which read the grade digit as an age.
        assert!(contains_school_grade_marker("小学6年生 ミミ"));
        assert!(contains_school_grade_marker("中学2年生 14歳 千鶴"));
        assert!(contains_school_grade_marker("小學6年生"));
        assert!(contains_school_grade_marker("初中3年级"));
        assert!(contains_school_grade_marker("초등학교 6학년"));
        assert!(contains_school_grade_marker("중학교 2학년"));

        // Grades that do not exist at that level are not grades.
        assert!(!contains_school_grade_marker("中学9年生"));
        assert!(!contains_school_grade_marker("田中4"));  // surname + number
        assert!(!contains_school_grade_marker("田中5号"));

        // ⚠ THE REGRESSION the suffix list caused: post-compulsory school years
        // belong to people who may be adults. A university freshman is 18-19 and
        // must never register as an age claim.
        assert!(!contains_school_grade_marker("大学1年生"));
        assert!(!contains_school_grade_marker("大学4年生"));
        assert!(!contains_school_grade_marker("高校3年生"));
        assert!(!contains_school_grade_marker("専門学校2年生"));
        assert!(!contains_school_grade_marker("대학교 1학년"));
    }

    #[test]
    fn grade_digits_are_not_read_as_ages() {
        // The digit before 年生/학년 is a GRADE. It must not reach the age
        // scanner at all — neither as a true age nor as a mislabelled one.
        assert!(contains_minor_age_token("大学1年生 の彼女.mp4").is_none());
        assert!(contains_minor_age_token("高校3年生 video.avi").is_none());
        assert!(contains_minor_age_token("초등학교 6학년.mp4").is_none());
        // A real age token in the same name still fires, and reports the AGE.
        let r = contains_minor_age_token("中学2年生 14歳 千鶴.avi");
        assert_eq!(r.as_deref(), Some("age 14 (歳)"));
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
        assert!(matches_layer2(s, &s.to_lowercase()).is_some());
        let s2 = "中1 ロリ clip.mp4"; // grade marker + katakana loli
        assert!(matches_layer2(s2, &s2.to_lowercase()).is_some());
    }

    #[test]
    fn cjk_fp_legit_jav_with_adult_age() {
        // Legal adult JAV with adult age + generic content — must NOT match.
        let s = "Kokoro Wato FC2 PPV 18歳 debut.mp4";
        assert!(matches_layer2(s, &s.to_lowercase()).is_none(),
                "FP: adult age 18 must not trigger");
        // Chinese film with episode/year numbers, no minor-age, no sex term.
        let s2 = "陈壮壮 第13集 高清.mp4";
        assert!(matches_layer2(s2, &s2.to_lowercase()).is_none());
    }
}
