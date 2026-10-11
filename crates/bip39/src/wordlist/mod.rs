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

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The number of words in a BIP-39 wordlist.
pub const WORDLIST_LEN: usize = 2048;

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
    /// Implementor's note: this MUST be sorted, contain exactly [`WORDLIST_LEN`] words, and each
    /// word MUST be NFKD-normalized and at most [`MAX_WORD_BYTES`] long.
    fn get_all() -> &'static [&'static str];

    /// Returns the word of a given index from the word list.
    fn get(index: usize) -> Result<&'static str, WordlistError> {
        Self::get_all()
            .get(index)
            .map(std::ops::Deref::deref)
            .ok_or(crate::WordlistError::InvalidIndex(index))
    }

    /// Returns the index of a given word from the word list.
    ///
    /// Scans the whole wordlist in constant time, so timing does not reveal which word matched.
    fn get_index(word: &str) -> Result<usize, WordlistError> {
        let target = PaddedWord::from_word(word).ok_or(WordlistError::InvalidWord)?;

        let mut index = Zeroizing::new(0u32);
        let mut found = Choice::from(0);
        for (i, candidate) in checked_words::<Self>().iter().enumerate() {
            let matches = target.ct_eq_word(candidate);
            index.conditional_assign(&(i as u32), matches);
            found |= matches;
        }
        bool::from(found)
            .then_some(*index as usize)
            .ok_or(WordlistError::InvalidWord)
    }
}

/// Returns `W`'s words. Panics if the wordlist does not contain [`WORDLIST_LEN`] words, as 11-bit
/// indices would then map to the wrong words.
fn checked_words<W: Wordlist + ?Sized>() -> &'static [&'static str] {
    let words = W::get_all();
    assert_eq!(
        words.len(),
        WORDLIST_LEN,
        "wordlists must contain {WORDLIST_LEN} words"
    );
    words
}

/// Iterates over a wordlist word's bytes, zero-padded to [`MAX_WORD_BYTES`]. Panics if the word
/// is too long.
fn padded_bytes(word: &str) -> impl Iterator<Item = u8> + '_ {
    assert!(
        word.len() <= MAX_WORD_BYTES,
        "wordlist words must be at most {MAX_WORD_BYTES} bytes"
    );
    word.bytes()
        .chain(std::iter::repeat(0))
        .take(MAX_WORD_BYTES)
}

/// A word zero-padded to [`MAX_WORD_BYTES`], so comparisons and copies don't depend on its
/// length. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct PaddedWord {
    buf: [u8; MAX_WORD_BYTES],
    len: u8,
}

impl PaddedWord {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0u8; MAX_WORD_BYTES],
            len: 0,
        }
    }

    /// Pads `word`. Returns `None` if it is longer than [`MAX_WORD_BYTES`].
    fn from_word(word: &str) -> Option<Self> {
        let mut padded = Self::new();
        padded
            .buf
            .get_mut(..word.len())?
            .copy_from_slice(word.as_bytes());
        padded.len = word.len() as u8;
        Some(padded)
    }

    /// Compares against a wordlist word in constant time.
    fn ct_eq_word(&self, word: &str) -> Choice {
        padded_bytes(word)
            .zip(&self.buf)
            .fold((word.len() as u8).ct_eq(&self.len), |acc, (a, b)| {
                acc & a.ct_eq(b)
            })
    }

    /// Assigns a wordlist word to `self` if `choice` is set, in constant time.
    fn conditional_assign_word(&mut self, word: &str, choice: Choice) {
        self.buf
            .iter_mut()
            .zip(padded_bytes(word))
            .for_each(|(byte, padded)| byte.conditional_assign(&padded, choice));
        self.len.conditional_assign(&(word.len() as u8), choice);
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len as usize]).expect("wordlist words are UTF-8")
    }
}

/// Copies the word at wordlist `index` into `out`. Scans the whole wordlist in constant time, so
/// memory access patterns do not reveal the index.
pub(crate) fn word_at<W: Wordlist>(index: usize, out: &mut PaddedWord) {
    let index = index as u32;
    for (i, candidate) in checked_words::<W>().iter().enumerate() {
        out.conditional_assign_word(candidate, (i as u32).ct_eq(&index));
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
