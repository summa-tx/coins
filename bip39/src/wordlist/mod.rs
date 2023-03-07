/// The English wordlist
pub mod english;
pub use self::english::*;

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
            .binary_search(&word)
            .map_err(|_| crate::WordlistError::InvalidWord(word.to_string()))
    }
}
