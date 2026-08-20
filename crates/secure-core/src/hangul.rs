use zeroize::Zeroize;

use crate::input::ResolvedKey;

const TAG_DIGIT: u32 = 0x1000;
const TAG_LEADING: u32 = 0x2000;
const TAG_VOWEL: u32 = 0x3000;
const TAG_TRAILING: u32 = 0x4000;
const TAG_MASK: u32 = 0xF000;

const LEADING_KEYS: [&str; 19] = [
    "giyeok",
    "ssang-giyeok",
    "nieun",
    "digeut",
    "ssang-digeut",
    "rieul",
    "mieum",
    "bieub",
    "ssang-bieub",
    "siot",
    "ssang-siot",
    "ieung",
    "jieut",
    "ssang-jieut",
    "chieut",
    "kieuk",
    "tieut",
    "pieup",
    "hieuh",
];

const VOWEL_KEYS: [&str; 21] = [
    "a", "ae", "ya", "yae", "eo", "e", "yeo", "ye", "o", "wa", "wae", "oe", "yo", "u", "wo", "we",
    "wi", "yu", "eu", "ui", "i",
];

const TRAILING_KEYS: [&str; 27] = [
    "giyeok",
    "ssang-giyeok",
    "giyeok-siot",
    "nieun",
    "nieun-jieut",
    "nieun-hieuh",
    "digeut",
    "rieul",
    "rieul-giyeok",
    "rieul-mieum",
    "rieul-bieub",
    "rieul-siot",
    "rieul-tieut",
    "rieul-pieup",
    "rieul-hieuh",
    "mieum",
    "bieub",
    "bieub-siot",
    "siot",
    "ssang-siot",
    "ieung",
    "jieut",
    "chieut",
    "kieuk",
    "tieut",
    "pieup",
    "hieuh",
];

pub(crate) fn resolve_key(key: &str) -> Option<ResolvedKey> {
    if let Some(name) = key.strip_prefix("jamo-") {
        if let Some(index) = LEADING_KEYS.iter().position(|candidate| *candidate == name) {
            return Some(ResolvedKey::Leading(u8::try_from(index).ok()?));
        }
    }
    if let Some(name) = key.strip_prefix("vowel-") {
        if let Some(index) = VOWEL_KEYS.iter().position(|candidate| *candidate == name) {
            return Some(ResolvedKey::Vowel(u8::try_from(index).ok()?));
        }
    }
    if let Some(name) = key.strip_prefix("tail-") {
        if let Some(index) = TRAILING_KEYS
            .iter()
            .position(|candidate| *candidate == name)
        {
            return Some(ResolvedKey::Trailing(u8::try_from(index).ok()? + 1));
        }
    }
    None
}

pub(crate) fn encode_key(key: ResolvedKey) -> u32 {
    match key {
        ResolvedKey::Digit(value) => TAG_DIGIT | u32::from(value),
        ResolvedKey::Leading(value) => TAG_LEADING | u32::from(value),
        ResolvedKey::Vowel(value) => TAG_VOWEL | u32::from(value),
        ResolvedKey::Trailing(value) => TAG_TRAILING | u32::from(value),
    }
}

pub(crate) fn render(tokens: &[u32]) -> Vec<u32> {
    let mut rendered = Vec::with_capacity(tokens.len());
    let mut index = 0;
    while index < tokens.len() {
        if let Some(leading) = leading(tokens[index]) {
            if let Some(first_vowel) = tokens.get(index + 1).and_then(|token| vowel(*token)) {
                let (vowel_index, vowel_width) = combined_vowel(tokens, index + 1, first_vowel);
                let mut trailing_index = 0;
                let mut trailing_width = 0;
                if let Some(first_trailing) = tokens
                    .get(index + 1 + vowel_width)
                    .and_then(|token| trailing(*token))
                {
                    trailing_index = first_trailing;
                    trailing_width = 1;
                    if let Some(second_trailing) = tokens
                        .get(index + 2 + vowel_width)
                        .and_then(|token| trailing(*token))
                    {
                        if let Some(combined) = combine_trailing(first_trailing, second_trailing) {
                            trailing_index = combined;
                            trailing_width = 2;
                        }
                    }
                }
                let syllable = 0xAC00
                    + ((u32::from(leading) * 21 + u32::from(vowel_index)) * 28)
                    + u32::from(trailing_index);
                rendered.push(syllable);
                index += 1 + vowel_width + trailing_width;
                continue;
            }
            rendered.push(0x1100 + u32::from(leading));
            index += 1;
            continue;
        }
        if let Some(vowel) = tokens.get(index).and_then(|token| vowel(*token)) {
            rendered.push(0x1161 + u32::from(vowel));
            index += 1;
            continue;
        }
        if let Some(trailing) = tokens.get(index).and_then(|token| trailing(*token)) {
            rendered.push(0x11A7 + u32::from(trailing));
            index += 1;
            continue;
        }
        if let Some(digit) = tokens.get(index).and_then(|token| digit(*token)) {
            rendered.push(u32::from(b'0' + digit));
        }
        index += 1;
    }
    rendered
}

pub(crate) fn encode_utf8(codepoints: &mut Vec<u32>, output: &mut crate::SecretBuffer) {
    for codepoint in codepoints.iter().copied() {
        if let Some(character) = char::from_u32(codepoint) {
            let mut bytes = [0_u8; 4];
            output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
        }
    }
    codepoints.zeroize();
}

fn leading(token: u32) -> Option<u8> {
    (token & TAG_MASK == TAG_LEADING)
        .then(|| u8::try_from(token & !TAG_MASK).ok())
        .flatten()
}

fn vowel(token: u32) -> Option<u8> {
    (token & TAG_MASK == TAG_VOWEL)
        .then(|| u8::try_from(token & !TAG_MASK).ok())
        .flatten()
}

fn trailing(token: u32) -> Option<u8> {
    (token & TAG_MASK == TAG_TRAILING)
        .then(|| u8::try_from(token & !TAG_MASK).ok())
        .flatten()
}

fn digit(token: u32) -> Option<u8> {
    (token & TAG_MASK == TAG_DIGIT)
        .then(|| u8::try_from(token & !TAG_MASK).ok())
        .flatten()
}

fn combined_vowel(tokens: &[u32], index: usize, first: u8) -> (u8, usize) {
    let Some(second) = tokens.get(index + 1).and_then(|token| vowel(*token)) else {
        return (first, 1);
    };
    let combined = match (first, second) {
        (0, 20) => 1,
        (2, 20) => 3,
        (8, 0) => 9,
        (8, 1) => 10,
        (8, 20) => 11,
        (13, 4) => 14,
        (13, 5) => 15,
        (13, 20) => 16,
        (18, 20) => 19,
        _ => return (first, 1),
    };
    (combined, 2)
}

fn combine_trailing(first: u8, second: u8) -> Option<u8> {
    match (first, second) {
        (1, 19) => Some(3),
        (4, 22) => Some(5),
        (4, 27) => Some(6),
        (8, 1) => Some(9),
        (8, 16) => Some(10),
        (8, 17) => Some(11),
        (8, 19) => Some(12),
        (8, 25) => Some(13),
        (8, 26) => Some(14),
        (8, 27) => Some(15),
        (17, 19) => Some(18),
        _ => None,
    }
}
