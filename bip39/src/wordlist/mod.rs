/// The Chinese (Simplified) wordlist
pub mod chinese_simplified;
/// The Chinese (Traditional) wordlist
pub mod chinese_traditional;
/// The Czech wordlist
pub mod czech;
/// The English wordlist
pub mod english;
/// The French wordlist
pub mod french;
/// The Italian wordlist
pub mod italian;
/// The Japanese wordlist
pub mod japanese;
/// The Korean wordlist
pub mod korean;
/// The Portuguese wordlist
pub mod portuguese;
/// The Spanish wordlist
pub mod spanish;
pub use self::chinese_simplified::*;
pub use self::chinese_traditional::*;
pub use self::czech::*;
pub use self::english::*;
pub use self::french::*;
pub use self::italian::*;
pub use self::japanese::*;
pub use self::korean::*;
pub use self::portuguese::*;
pub use self::spanish::*;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
/// The error type returned while interacting with wordists.
pub enum WordlistError {
    /// Describes the error when the wordlist is queried at an invalid index.
    #[error("the index `{0}` is invalid")]
    InvalidIndex(usize),
    /// Describes the error when the wordlist does not contain the queried word.
    #[error("the word `{0}` is invalid")]
    InvalidWord(String),
}

/// The Wordlist trait that every language's wordlist must implement.
pub trait Wordlist {
    /// Returns the word list as a string.
    ///
    /// Implementor's note: this MUST be sorted
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
            .ok_or(crate::WordlistError::InvalidWord(word.to_string()))
    }
}
