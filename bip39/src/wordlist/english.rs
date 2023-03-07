use crate::Wordlist;
use once_cell::sync::Lazy;

/// The list of words as supported in the English language.
pub const RAW_ENGLISH: &str = include_str!("./words/english.txt");

/// English word list, split into words
pub static PARSED: Lazy<Vec<&'static str>> = Lazy::new(|| RAW_ENGLISH.lines().collect());

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
/// The English wordlist that implements the Wordlist trait.
pub struct English;

impl Wordlist for English {
    fn get_all() -> &'static [&'static str] {
        PARSED.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::WordlistError;

    #[test]
    fn test_get() {
        assert_eq!(English::get(3), Ok("about"));
        assert_eq!(English::get(2044), Ok("zebra"));
        assert_eq!(English::get(2048), Err(WordlistError::InvalidIndex(2048)));
    }

    #[test]
    fn test_get_index() {
        assert_eq!(English::get_index("about"), Ok(3));
        assert_eq!(English::get_index("zebra"), Ok(2044));
        assert_eq!(
            English::get_index("somerandomword"),
            Err(WordlistError::InvalidWord("somerandomword".to_string()))
        );
    }

    #[test]
    fn test_get_all() {
        assert_eq!(English::get_all().len(), 2048);
    }
}
