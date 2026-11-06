use super::*;
use crate::English;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn parse(phrase: &str) -> Result<Mnemonic<English>, MnemonicError> {
    Mnemonic::<English>::new_from_phrase(phrase)
}

#[test]
fn new_from_phrase_ignores_surrounding_and_repeated_whitespace() {
    let expected = parse(PHRASE).unwrap();
    let cases = [
        format!("{PHRASE}\n"),
        format!("{PHRASE}\r\n"),
        format!(" {PHRASE}"),
        format!("\t {PHRASE} \n"),
        PHRASE.replacen(' ', "  ", 1),
        PHRASE.replace(' ', "   "),
        PHRASE.replacen(' ', "\t", 1),
        PHRASE.replacen(' ', "\n", 3),
        PHRASE.replace(' ', "\u{3000}"),
    ];
    for phrase in cases {
        let mnemonic = parse(&phrase).unwrap_or_else(|e| panic!("{phrase:?}: {e}"));
        assert_eq!(mnemonic.entropy(), expected.entropy(), "{phrase:?}");
        assert_eq!(*mnemonic.to_phrase(), PHRASE, "{phrase:?}");
    }
}

#[test]
fn new_from_phrase_still_rejects_bad_word_counts() {
    assert!(matches!(parse(""), Err(MnemonicError::InvalidWordCount(0))));
    assert!(matches!(
        parse(" \n\t "),
        Err(MnemonicError::InvalidWordCount(0))
    ));
    assert!(matches!(
        parse(&format!("{PHRASE} abandon")),
        Err(MnemonicError::InvalidWordCount(13))
    ));
}

#[test]
fn new_from_phrase_reports_word_position_ignoring_extra_whitespace() {
    let phrase = format!("  {}", PHRASE.replacen("about", "notaword", 1));
    assert!(matches!(
        parse(&phrase),
        Err(MnemonicError::InvalidWord(11))
    ));
}

#[test]
fn invalid_word_count_message_is_balanced() {
    assert_eq!(
        MnemonicError::InvalidWordCount(1).to_string(),
        "invalid word count (expected 12, 15, 18, 21, 24, found `1`)"
    );
}
