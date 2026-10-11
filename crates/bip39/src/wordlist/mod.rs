/// The English wordlist
#[cfg(feature = "english")]
pub mod english;
#[cfg(feature = "english")]
pub use self::english::English;

/// The Chinese (Simplified) wordlist
#[cfg(feature = "chinese-simplified")]
pub mod chinese_simplified;
#[cfg(feature = "chinese-simplified")]
pub use self::chinese_simplified::ChineseSimplified;

/// The Chinese (Traditional) wordlist
#[cfg(feature = "chinese-traditional")]
pub mod chinese_traditional;
#[cfg(feature = "chinese-traditional")]
pub use super::chinese_traditional::ChineseTraditional;

/// The Czech wordlist
#[cfg(feature = "czech")]
pub mod czech;
#[cfg(feature = "czech")]
pub use super::czech::Czech;

/// The French wordlist
#[cfg(feature = "french")]
pub mod french;
#[cfg(feature = "french")]
pub use super::french::French;

/// The Italian wordlist
#[cfg(feature = "italian")]
pub mod italian;
#[cfg(feature = "italian")]
pub use super::italian::Italian;

/// The Japanese wordlist
#[cfg(feature = "japanese")]
pub mod japanese;
#[cfg(feature = "japanese")]
pub use super::japanese::Japanese;

/// The Korean wordlist
#[cfg(feature = "korean")]
pub mod korean;
#[cfg(feature = "korean")]
pub use super::korean::Korean;

/// The Portuguese wordlist
#[cfg(feature = "portuguese")]
pub mod portuguese;
#[cfg(feature = "portuguese")]
pub use super::portuguese::Portuguese;

/// The Spanish wordlist
#[cfg(feature = "spanish")]
pub mod spanish;
#[cfg(feature = "spanish")]
pub use super::spanish::Spanish;

use thiserror::Error;

/// The maximum length of a wordlist word, in bytes. The longest word in the built-in wordlists
/// (Korean) is 33 bytes.
pub const MAX_WORD_BYTES: usize = 33;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
/// The error type returned while interacting with wordists.
pub enum WordlistError {
    /// Describes the error when the wordlist is queried at an invalid index.
    #[error("the index `{0}` is invalid")]
    InvalidIndex(usize),
    /// Describes the error when the wordlist does not contain the queried word. The word is not
    /// included, as it may be part of a secret phrase.
    #[error("the word is not in the wordlist")]
    InvalidWord,
}

/// The Wordlist trait that every language's wordlist must implement.
pub trait Wordlist {
    /// Returns the word list as a string.
    ///
    /// Implementor's note: this MUST be sorted, contain exactly 2048 words, and each word MUST be
    /// NFKD-normalized and at most [`MAX_WORD_BYTES`] long.
    fn get_all() -> &'static [&'static str];

    /// Returns the word of a given index from the word list.
    fn get(index: usize) -> Result<&'static str, WordlistError> {
        Self::get_all()
            .get(index)
            .map(std::ops::Deref::deref)
            .ok_or(crate::WordlistError::InvalidIndex(index))
    }

    /// Returns the index of a given word from the word list.
    fn get_index(word: &str) -> Result<usize, WordlistError> {
        Self::get_all()
            .iter()
            .position(|&x| x == word)
            .ok_or(crate::WordlistError::InvalidWord)
    }
}

#[cfg(all(test, feature = "all-langs"))]
mod tests {
    use super::*;
    use unicode_normalization::is_nfkd;

    fn check<W: Wordlist>() {
        let words = W::get_all();
        assert_eq!(words.len(), 2048);
        for word in words {
            assert!(is_nfkd(word), "{word} is not NFKD");
            assert!(word.len() <= MAX_WORD_BYTES, "{word} is too long");
        }
    }

    #[test]
    fn wordlists_are_nfkd_and_bounded() {
        check::<ChineseSimplified>();
        check::<ChineseTraditional>();
        check::<Czech>();
        check::<English>();
        check::<French>();
        check::<Italian>();
        check::<Japanese>();
        check::<Korean>();
        check::<Portuguese>();
        check::<Spanish>();
    }
}
