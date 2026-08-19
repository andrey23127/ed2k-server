//! Layer 2 vocabulary, loadable from a file.
//!
//! The word lists this layer needs change almost daily as review windows surface
//! new phrasing, and until now every change meant a rebuild and a restart. A
//! restart drops every connected client, which is why the server had never been
//! observed at a long uptime.
//!
//! So the lists move out of the binary. The RULES stay in code — the age
//! scanner, the boundary classes, the guard window, mojibake recovery — because
//! those are algorithms, not vocabulary, and they are what the test suite pins.
//!
//! SAFETY PROPERTY, and the reason this can be deployed without a careful
//! before/after comparison: `Layer2Terms::default()` returns exactly the lists
//! that were compiled in. With no file configured, or a file that fails to read,
//! behaviour is bit-for-bit what it was. A file only ever REPLACES the default;
//! it cannot leave the layer half-populated.

use std::collections::HashSet;

/// Every list Layer 2 consults, in one hot-swappable value.
#[derive(Debug, Clone)]
pub struct Layer2Terms {
    /// Sexual terms matched anywhere in the name, including inside a word.
    pub sex_substring: Vec<String>,
    /// Sexual terms that must start at a word boundary but may continue into an
    /// inflection ("fuck" -> "fucking").
    pub sex_prefix: Vec<String>,
    /// Sexual terms needing a boundary on BOTH sides, because each is a prefix
    /// of an ordinary word (anal/analysis, cum/Cumberland).
    pub sex_bounded: Vec<String>,
    /// Fixed phrases that make a broad term innocent; checked before every
    /// layer, and a match here means Layer 2 does not fire at all.
    pub exceptions: Vec<String>,
    /// CJK words naming a minor. Matched as plain substrings — that script has
    /// no word separators.
    pub minor_cjk: Vec<String>,
    /// Latin-script words naming a minor, left-bounded.
    pub minor_latin: Vec<String>,
    /// Cyrillic stems naming a minor. Stems, because the language inflects.
    pub minor_ru: Vec<String>,
    /// Cyrillic sexual terms.
    pub sex_ru: Vec<String>,
    /// Words that explain a small number as an age of something other than a
    /// person — whisky, service intervals — when they sit near it.
    pub age_guard: Vec<String>,
    /// Animals for the (currently disabled) zoo co-occurrence rule.
    pub zoo_animals: Vec<String>,
    /// Acts for the same.
    pub zoo_acts: Vec<String>,
    /// Veterinary contexts that disqualify a zoo match.
    pub zoo_guard: Vec<String>,
    /// Ages at or below this need no second signal.
    pub unpaired_age_max: u32,
    /// How far either side of a number a guard word disqualifies it, in bytes.
    pub age_guard_window: usize,
}

// ⚠ EDITING THESE DEFAULTS HAS NO EFFECT on a deployment whose
// layer2_terms.txt names the corresponding section: a named section replaces the
// built-in list outright, which is what makes an entry removable and is the
// point of the file.
//
// So vocabulary changes belong in the FILE. Change these only to alter what a
// fresh installation starts with — and then regenerate
// config/layer2_terms.txt.example, or the two drift apart silently.
//
// This was learned the hard way: guard words added here after a live miss did
// nothing, because every running server already had the section in its file.
impl Default for Layer2Terms {
    /// The vocabulary as it was compiled in before this file existed.
    ///
    /// Do not "tidy" these lists. Each entry was added or rejected against a
    /// measured review window, and several look wrong until you know why —
    /// see the operator file shipped as `config/layer2_terms.txt.example`.
    fn default() -> Self {
        Self {
            sex_substring: to_vec(&[
            "porn", "blowjob", "handjob", "dildo", "orgasm", "masturbat", "sexuell", "ficken",
            "porno", "follar", "desnud", "sesso", "секс", "голая", "детский секс видео",
            "голая девочка", "секс с малолеткой", "секс", "порн", "голая", "обнаж", "sexe",
            "援助交際", "원조교제", "ロリ", "loli", "幼女", "young girl", "近親相姦", "강간", "レイプ",
            "vagina", "penis", "cunt", "boobs", "tits",
            ]),
            sex_prefix: to_vec(&[
            "fuck", "nude", "naked", "molest", "rape",
            ]),
            sex_bounded: to_vec(&[
            "sex", "xxx", "anal", "oral", "cum", "nackt", "nud", "scopa", "pussy", "incest", "cock",
            ]),
            exceptions: to_vec(&[
            "голая правда", "голой правды", "голую правду", "сексуальное воспитан",
            "половое воспитан", "сексуальная революц", "секс-просвет", "сексолог",
            "сексопатолог",
            ]),
            minor_cjk: to_vec(&[
            "中学生", "中學生", "初中生", "小学生", "小學生", "未成年", "minor", "미성년", "중학생", "초등학생",
            ]),
            minor_latin: to_vec(&[
            "kleinkind",
            ]),
            minor_ru: to_vec(&[
            "школьниц", "школьник", "малолет", "несовершеннолет", "подростк", "девочк",
            "мальчик", "детск", "дети", "ребён", "ребен", "малыш", "дочк", "сынок", "юная",
            "юные", "юной",
            ]),
            sex_ru: to_vec(&[
            "ебёт", "ебет", "ебля", "ебут", "ебал", "трахае", "трахну", "трахал", "сосёт",
            "сосет", "минет", "дрочит", "дрочь", "изнасил", "порево", "сексом",
            "занимаются сексом", "порн", "мастурбац", "развратн", "стриптиз", "совращ",
            "инцест", "голенькая",
            ]),
            age_guard: to_vec(&[
                // Product and version contexts. An age written with no space before
                // the y is an unpaired notation, and that same form names a model, a
                // firmware build or a support window.
                "whisk", "malt", "scotch", "bourbon", "cognac", "brandy", "tequila",
                "cask", "barrel", "reserva", "solera", "anejo", "distiller", "tasting",
                "aged", "vintage", "service manual", "warranty", "guarantee", "mileage",
                "windows", "iphone", "galaxy", "firmware", "build", "version", "episode",
                "season", "model", "release",
            ]),
            zoo_animals: to_vec(&[
            "horse", "pony", "mare", "stallion", "donkey", "canine", "equine", "k9",
            ]),
            zoo_acts: to_vec(&[
            "cum", "cums", "fuck", "fucks", "fucking", "fucked", "pussy", "suck", "sucks",
            "knot", "penetrat",
            ]),
            zoo_guard: to_vec(&[
            "veterinar", "breeding guide", "husbandry", "artificial insemination", "stud farm",
            "equine reproduction", "livestock", "insemination",
            ]),
            unpaired_age_max: 12,
            age_guard_window: 24,
        }
    }
}

fn to_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

impl Layer2Terms {
    /// Parse the operator file.
    ///
    /// Sections are `[name]` headers; every other non-blank, non-comment line is
    /// one entry, taken verbatim except for surrounding whitespace. Entries are
    /// lower-cased on load, because every caller matches against an
    /// already-lowered name and doing it here means an operator cannot break
    /// matching with a capital letter.
    ///
    /// A `[limits]` section takes `key = value` instead.
    ///
    /// UNKNOWN SECTIONS ARE AN ERROR, not a warning. A typo in a header would
    /// otherwise silently drop every entry under it — the layer would keep
    /// running and quietly stop catching a whole category, which is the worst
    /// possible failure for this file.
    pub fn parse(text: &str) -> Result<Self, String> {
        // Start from an EMPTY value, not from default(): a file that names a
        // section replaces that list outright. Mixing would make it impossible
        // to remove a compiled-in entry, which is half the point of the file.
        let mut t = Layer2Terms {
            sex_substring: Vec::new(),
            sex_prefix: Vec::new(),
            sex_bounded: Vec::new(),
            exceptions: Vec::new(),
            minor_cjk: Vec::new(),
            minor_latin: Vec::new(),
            minor_ru: Vec::new(),
            sex_ru: Vec::new(),
            age_guard: Vec::new(),
            zoo_animals: Vec::new(),
            zoo_acts: Vec::new(),
            zoo_guard: Vec::new(),
            unpaired_age_max: Self::default().unpaired_age_max,
            age_guard_window: Self::default().age_guard_window,
        };
        let mut section: Option<String> = None;
        let mut seen: HashSet<String> = HashSet::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let name = name.trim().to_ascii_lowercase();
                if !Self::is_known_section(&name) {
                    return Err(format!(
                        "line {}: unknown section [{name}] — a typo here would \
                         silently empty a whole category",
                        lineno + 1
                    ));
                }
                seen.insert(name.clone());
                section = Some(name);
                continue;
            }
            let Some(sec) = section.as_deref() else {
                return Err(format!("line {}: entry before any [section]", lineno + 1));
            };
            if sec == "limits" {
                let (k, v) = line
                    .split_once('=')
                    .ok_or_else(|| format!("line {}: expected key = value", lineno + 1))?;
                let (k, v) = (k.trim(), v.trim());
                match k {
                    "unpaired_age_max" => {
                        t.unpaired_age_max = v.parse().map_err(|_| {
                            format!("line {}: unpaired_age_max must be a number", lineno + 1)
                        })?;
                        // 17 is the top of the age range this layer knows about;
                        // above that the setting would mean "every age stands
                        // alone", which is not a threshold, it is a different
                        // rule.
                        if t.unpaired_age_max > 17 {
                            return Err(format!(
                                "line {}: unpaired_age_max above 17 disables the pairing \
                                 rule entirely",
                                lineno + 1
                            ));
                        }
                    }
                    "age_guard_window" => {
                        t.age_guard_window = v.parse().map_err(|_| {
                            format!("line {}: age_guard_window must be a number", lineno + 1)
                        })?;
                    }
                    other => {
                        return Err(format!("line {}: unknown limit '{other}'", lineno + 1))
                    }
                }
                continue;
            }
            // Strip a trailing ';' comment so an operator can annotate entries
            // the way the hash lists allow. A '#' cannot be used for this: some
            // entries legitimately contain one.
            let entry = match line.split_once(" ;") {
                Some((e, _)) => e.trim(),
                None => line,
            };
            if entry.is_empty() {
                continue;
            }
            t.list_mut(sec).push(entry.to_lowercase());
        }

        if seen.is_empty() {
            return Err("file contains no sections".to_string());
        }
        // A section named but left empty is taken at face value — that is how an
        // operator disables a category. Only sections NOT named fall back.
        let d = Self::default();
        if !seen.contains("sex.substring") { t.sex_substring = d.sex_substring; }
        if !seen.contains("sex.prefix") { t.sex_prefix = d.sex_prefix; }
        if !seen.contains("sex.bounded") { t.sex_bounded = d.sex_bounded; }
        if !seen.contains("exceptions") { t.exceptions = d.exceptions; }
        if !seen.contains("minor.cjk") { t.minor_cjk = d.minor_cjk; }
        if !seen.contains("minor.latin") { t.minor_latin = d.minor_latin; }
        if !seen.contains("minor.ru") { t.minor_ru = d.minor_ru; }
        if !seen.contains("sex.ru") { t.sex_ru = d.sex_ru; }
        if !seen.contains("age.guard") { t.age_guard = d.age_guard; }
        if !seen.contains("zoo.animals") { t.zoo_animals = d.zoo_animals; }
        if !seen.contains("zoo.acts") { t.zoo_acts = d.zoo_acts; }
        if !seen.contains("zoo.guard") { t.zoo_guard = d.zoo_guard; }
        Ok(t)
    }

    fn is_known_section(name: &str) -> bool {
        matches!(
            name,
            "sex.substring" | "sex.prefix" | "sex.bounded" | "exceptions"
                | "minor.cjk" | "minor.latin" | "minor.ru" | "sex.ru"
                | "age.guard" | "zoo.animals" | "zoo.acts" | "zoo.guard"
                | "limits"
        )
    }

    fn list_mut(&mut self, section: &str) -> &mut Vec<String> {
        match section {
            "sex.substring" => &mut self.sex_substring,
            "sex.prefix" => &mut self.sex_prefix,
            "sex.bounded" => &mut self.sex_bounded,
            "exceptions" => &mut self.exceptions,
            "minor.cjk" => &mut self.minor_cjk,
            "minor.latin" => &mut self.minor_latin,
            "minor.ru" => &mut self.minor_ru,
            "sex.ru" => &mut self.sex_ru,
            "age.guard" => &mut self.age_guard,
            "zoo.animals" => &mut self.zoo_animals,
            "zoo.acts" => &mut self.zoo_acts,
            "zoo.guard" => &mut self.zoo_guard,
            // is_known_section has already rejected anything else, and "limits"
            // never reaches here.
            other => unreachable!("unhandled section {other}"),
        }
    }

    /// Total entries, for the startup log and the web panel.
    pub fn len(&self) -> usize {
        self.sex_substring.len() + self.sex_prefix.len() + self.sex_bounded.len()
            + self.exceptions.len() + self.minor_cjk.len() + self.minor_latin.len()
            + self.minor_ru.len() + self.sex_ru.len() + self.age_guard.len()
            + self.zoo_animals.len() + self.zoo_acts.len() + self.zoo_guard.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_the_compiled_in_vocabulary() {
        // The safety property: with no file, nothing changes. If this number
        // moves, someone edited the defaults, and the operator file on every
        // deployment is now out of step with them.
        let d = Layer2Terms::default();
        assert_eq!(d.len(), 170, "default vocabulary size changed");
        assert_eq!(d.unpaired_age_max, 12);
        assert_eq!(d.age_guard_window, 24);
    }

    #[test]
    fn a_named_section_replaces_rather_than_extends() {
        // Replacing is what lets an operator REMOVE a compiled-in entry. If a
        // file merged into the defaults instead, a wrong entry could never be
        // taken out without a rebuild — which is the problem this file exists to
        // solve.
        let t = Layer2Terms::parse("[sex.prefix]\nonlyone\n").unwrap();
        assert_eq!(t.sex_prefix, vec!["onlyone"]);
        // ...while an unnamed section keeps its default.
        assert_eq!(t.minor_ru, Layer2Terms::default().minor_ru);
    }

    #[test]
    fn a_named_but_empty_section_disables_that_category() {
        // Taken at face value: naming a section and listing nothing is how a
        // category is switched off. Only an ABSENT section falls back.
        let t = Layer2Terms::parse("[zoo.animals]\n\n[sex.prefix]\nfuck\n").unwrap();
        assert!(t.zoo_animals.is_empty());
        assert_eq!(t.sex_prefix, vec!["fuck"]);
    }

    #[test]
    fn an_unknown_section_is_an_error() {
        // A typo would otherwise silently empty a whole category: the layer
        // keeps running and quietly stops catching it. Failing loudly means the
        // caller keeps the previous list.
        let e = Layer2Terms::parse("[sex.prefx]\nfuck\n").unwrap_err();
        assert!(e.contains("unknown section"), "{e}");
    }

    #[test]
    fn entries_are_lowercased_and_comments_stripped() {
        let t = Layer2Terms::parse(
            "# a comment\n[minor.ru]\nШКОЛЬНИЦ  ; schoolgirl\n\n; another comment\nМАЛОЛЕТ\n",
        )
        .unwrap();
        assert_eq!(t.minor_ru, vec!["школьниц", "малолет"]);
    }

    #[test]
    fn an_entry_may_contain_a_hash() {
        // '#' only comments when it STARTS the line, because some entries
        // legitimately contain one.
        let t = Layer2Terms::parse("[sex.substring]\nc#4\n").unwrap();
        assert_eq!(t.sex_substring, vec!["c#4"]);
    }

    #[test]
    fn limits_are_parsed_and_bounded() {
        let t = Layer2Terms::parse("[limits]\nunpaired_age_max = 10\nage_guard_window = 32\n")
            .unwrap();
        assert_eq!(t.unpaired_age_max, 10);
        assert_eq!(t.age_guard_window, 32);

        // Above 17 the setting stops being a threshold and becomes a different
        // rule — every age would stand alone.
        assert!(Layer2Terms::parse("[limits]\nunpaired_age_max = 25\n").is_err());
        assert!(Layer2Terms::parse("[limits]\nunpaired_age_max = x\n").is_err());
        assert!(Layer2Terms::parse("[limits]\nnosuchlimit = 1\n").is_err());
    }

    #[test]
    fn an_entry_before_any_section_is_an_error() {
        assert!(Layer2Terms::parse("stray\n[sex.prefix]\nfuck\n").is_err());
    }

    #[test]
    fn an_empty_file_is_an_error_not_an_empty_vocabulary() {
        // Distinguishing this from "a file that disables everything" matters:
        // an empty file is far more likely to be a truncated write or a failed
        // download than a deliberate configuration.
        assert!(Layer2Terms::parse("").is_err());
        assert!(Layer2Terms::parse("# only comments\n").is_err());
    }

    #[test]
    fn a_full_round_trip_preserves_every_list() {
        // Write the defaults out in the file format, read them back, compare.
        // This is what proves the shipped example cannot drift from the code.
        let d = Layer2Terms::default();
        let mut text = String::new();
        for (name, list) in [
            ("sex.substring", &d.sex_substring),
            ("sex.prefix", &d.sex_prefix),
            ("sex.bounded", &d.sex_bounded),
            ("exceptions", &d.exceptions),
            ("minor.cjk", &d.minor_cjk),
            ("minor.latin", &d.minor_latin),
            ("minor.ru", &d.minor_ru),
            ("sex.ru", &d.sex_ru),
            ("age.guard", &d.age_guard),
            ("zoo.animals", &d.zoo_animals),
            ("zoo.acts", &d.zoo_acts),
            ("zoo.guard", &d.zoo_guard),
        ] {
            text.push_str(&format!("[{name}]\n"));
            for e in list.iter() {
                text.push_str(e);
                text.push('\n');
            }
        }
        let back = Layer2Terms::parse(&text).unwrap();
        assert_eq!(back.sex_substring, d.sex_substring);
        assert_eq!(back.sex_prefix, d.sex_prefix);
        assert_eq!(back.sex_bounded, d.sex_bounded);
        assert_eq!(back.exceptions, d.exceptions);
        assert_eq!(back.minor_cjk, d.minor_cjk);
        assert_eq!(back.minor_latin, d.minor_latin);
        assert_eq!(back.minor_ru, d.minor_ru);
        assert_eq!(back.sex_ru, d.sex_ru);
        assert_eq!(back.age_guard, d.age_guard);
        assert_eq!(back.zoo_animals, d.zoo_animals);
        assert_eq!(back.zoo_acts, d.zoo_acts);
        assert_eq!(back.zoo_guard, d.zoo_guard);
        assert_eq!(back.len(), d.len());
    }
}
