use crate::{
    wordlist::{word_at, PaddedWord},
    Wordlist, MAX_WORD_BYTES,
};
use coins_bip32::{path::DerivationPath, xkeys::XPriv, Bip32Error};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256, Sha512};
use std::marker::PhantomData;
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PBKDF2_ROUNDS: u32 = 2048;
const PBKDF2_BYTES: usize = 64;

/// Each word encodes an 11-bit index into the wordlist.
const BITS_PER_WORD: usize = 11;
/// Entropy length of the longest (24-word) mnemonic.
const MAX_ENTROPY_BYTES: usize = 32;
/// Entropy plus checksum of the longest mnemonic: 24 words * 11 bits = 264 bits.
const MAX_ENCODED_BYTES: usize = 33;

#[derive(Debug, Error)]
/// The error type returned while interacting with mnemonics.
pub enum MnemonicError {
    /// Describes the error when the mnemonic's entropy length is invalid.
    #[error("the mnemonic's entropy length `{0}` is invalid")]
    InvalidEntropyLength(usize),
    /// Describes the error when the phrase's checksum does not match its entropy.
    #[error("the phrase's checksum is invalid")]
    InvalidChecksum,
    /// Describes the error when the word at the given position is not in the wordlist.
    #[error("the word at position `{0}` is not in the wordlist")]
    InvalidWord(usize),
    /// Describes the error when the word count provided for mnemonic generation is invalid.
    #[error("invalid word count (expected 12, 15, 18, 21, 24, found `{0}`")]
    InvalidWordCount(usize),
    /// Describes an error propagated from the BIP-32 crate.
    #[error(transparent)]
    Bip32Error(#[from] Bip32Error),
}

/// The number of words in a BIP-39 mnemonic. Determines the entropy length and checksum width.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WordCount {
    /// 12 words, 128 bits of entropy.
    Twelve,
    /// 15 words, 160 bits of entropy.
    Fifteen,
    /// 18 words, 192 bits of entropy.
    Eighteen,
    /// 21 words, 224 bits of entropy.
    TwentyOne,
    /// 24 words, 256 bits of entropy.
    TwentyFour,
}

impl WordCount {
    /// Returns the number of words in the mnemonic.
    pub const fn words(self) -> usize {
        match self {
            Self::Twelve => 12,
            Self::Fifteen => 15,
            Self::Eighteen => 18,
            Self::TwentyOne => 21,
            Self::TwentyFour => 24,
        }
    }

    /// Returns the entropy length in bytes. Every 3 words encode 32 bits of entropy.
    pub const fn entropy_bytes(self) -> usize {
        self.words() / 3 * 4
    }

    /// Returns the checksum length in bits. Every 3 words encode 1 bit of checksum.
    pub const fn checksum_bits(self) -> usize {
        self.words() / 3
    }

    const fn from_words(words: usize) -> Option<Self> {
        match words {
            12 => Some(Self::Twelve),
            15 => Some(Self::Fifteen),
            18 => Some(Self::Eighteen),
            21 => Some(Self::TwentyOne),
            24 => Some(Self::TwentyFour),
            _ => None,
        }
    }

    fn from_entropy_bytes(bytes: usize) -> Option<Self> {
        Some(bytes)
            .filter(|bytes| bytes % 4 == 0)
            .and_then(|bytes| Self::from_words(bytes / 4 * 3))
    }

    /// Masks the checksum bits, which occupy the most significant bits of a byte.
    const fn checksum_mask(self) -> u8 {
        0xff << (8 - self.checksum_bits())
    }
}

impl TryFrom<usize> for WordCount {
    type Error = MnemonicError;

    fn try_from(words: usize) -> Result<Self, Self::Error> {
        Self::from_words(words).ok_or(MnemonicError::InvalidWordCount(words))
    }
}

/// Mnemonic entropy. Zeroized on drop and compared in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Entropy {
    buf: [u8; MAX_ENTROPY_BYTES],
    #[zeroize(skip)]
    count: WordCount,
}

impl Entropy {
    /// Generates new entropy for a mnemonic of the given length.
    pub fn random<R: Rng + CryptoRng + ?Sized>(count: WordCount, rng: &mut R) -> Self {
        let mut entropy = Self {
            buf: [0u8; MAX_ENTROPY_BYTES],
            count,
        };
        rng.fill_bytes(&mut entropy.buf[..count.entropy_bytes()]);
        entropy
    }

    /// Instantiates entropy from a slice. Fails if the slice is not exactly 16, 20, 24, 28, or 32
    /// bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MnemonicError> {
        let count = WordCount::from_entropy_bytes(bytes.len())
            .ok_or(MnemonicError::InvalidEntropyLength(bytes.len()))?;
        let mut buf = [0u8; MAX_ENTROPY_BYTES];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { buf, count })
    }

    /// Returns the number of words in the corresponding mnemonic.
    pub const fn word_count(&self) -> WordCount {
        self.count
    }

    /// Returns the raw entropy bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.count.entropy_bytes()]
    }

    /// Computes the checksum: the leading `checksum_bits` of `sha256(entropy)`, left-aligned in a
    /// byte.
    fn checksum(&self) -> u8 {
        let mut hash = Sha256::digest(self.as_bytes());
        let checksum = hash[0] & self.count.checksum_mask();
        hash[..].zeroize();
        checksum
    }
}

impl TryFrom<&[u8]> for Entropy {
    type Error = MnemonicError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes)
    }
}

macro_rules! impl_entropy_from_array {
    ($($len:literal),*) => {$(
        impl From<[u8; $len]> for Entropy {
            fn from(mut bytes: [u8; $len]) -> Self {
                let entropy = Self::from_slice(&bytes).expect("valid entropy length");
                bytes.zeroize();
                entropy
            }
        }
    )*};
}

impl_entropy_from_array!(16, 20, 24, 28, 32);

impl ConstantTimeEq for Entropy {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl PartialEq for Entropy {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Entropy {}

impl std::fmt::Debug for Entropy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entropy")
            .field("word_count", &self.count)
            .finish_non_exhaustive()
    }
}

/// Entropy followed by its checksum, packed MSB-first as 11-bit wordlist indices. Zeroized on
/// drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct EncodedEntropy([u8; MAX_ENCODED_BYTES]);

impl EncodedEntropy {
    const fn new() -> Self {
        Self([0u8; MAX_ENCODED_BYTES])
    }

    /// Encodes `entropy` followed by its checksum.
    fn from_entropy(entropy: &Entropy) -> Self {
        let mut encoded = Self::new();
        let len = entropy.count.entropy_bytes();
        encoded.0[..len].copy_from_slice(entropy.as_bytes());
        encoded.0[len] = entropy.checksum();
        encoded
    }

    /// Decodes the entropy of a `count`-word phrase, verifying its checksum in constant time.
    fn to_entropy(&self, count: WordCount) -> Result<Entropy, MnemonicError> {
        let len = count.entropy_bytes();
        let entropy = Entropy::from_slice(&self.0[..len])?;
        let checksum = self.0[len] & count.checksum_mask();
        bool::from(checksum.ct_eq(&entropy.checksum()))
            .then_some(entropy)
            .ok_or(MnemonicError::InvalidChecksum)
    }

    /// Reads the 11-bit wordlist index of the word at `position`.
    fn read_index(&self, position: usize) -> usize {
        let start = position * BITS_PER_WORD;
        (start..start + BITS_PER_WORD).fold(0, |index, bit| {
            (index << 1) | ((self.0[bit / 8] >> (7 - bit % 8)) & 1) as usize
        })
    }

    /// Writes the 11-bit wordlist `index` of the word at `position`.
    fn write_index(&mut self, position: usize, index: usize) {
        let start = position * BITS_PER_WORD;
        for (i, bit) in (start..start + BITS_PER_WORD).enumerate() {
            let value = ((index >> (BITS_PER_WORD - 1 - i)) & 1) as u8;
            self.0[bit / 8] |= value << (7 - bit % 8);
        }
    }
}

/// Returns `prefix` followed by the NFKD normalization of `s`, as BIP-39 requires for phrases and
/// passphrases. The output is allocated at its exact length, so growing it never leaves
/// unzeroized copies behind.
fn nfkd(prefix: &str, s: &str) -> Zeroizing<String> {
    let len = prefix.len() + s.nfkd().map(char::len_utf8).sum::<usize>();
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.push_str(prefix);
    out.extend(s.nfkd());
    out
}

/// Mnemonic represents entropy that can be represented as a phrase. A mnemonic can be used to
/// deterministically generate an extended private key or derive its child keys.
///
/// The entropy is zeroized on drop, and comparisons are constant time.
#[derive(Clone)]
pub struct Mnemonic<W>
where
    W: Wordlist,
{
    /// Entropy used to generate mnemonic.
    entropy: Entropy,
    /// Wordlist used to produce phrases from entropy.
    _wordlist: PhantomData<W>,
}

impl<W: Wordlist> ZeroizeOnDrop for Mnemonic<W> {}

impl<W: Wordlist> ConstantTimeEq for Mnemonic<W> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.entropy.ct_eq(&other.entropy)
    }
}

impl<W: Wordlist> PartialEq for Mnemonic<W> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<W: Wordlist> Eq for Mnemonic<W> {}

impl<W: Wordlist> std::fmt::Debug for Mnemonic<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mnemonic")
            .field("word_count", &self.word_count())
            .finish_non_exhaustive()
    }
}

impl<W> std::str::FromStr for Mnemonic<W>
where
    W: Wordlist,
{
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new_from_phrase(s)
    }
}

impl<W> Mnemonic<W>
where
    W: Wordlist,
{
    /// Returns a new mnemonic of the given length, generated using the provided random number
    /// generator.
    pub fn random<R: Rng + CryptoRng + ?Sized>(count: WordCount, rng: &mut R) -> Self {
        Self::new_from_entropy(Entropy::random(count, rng))
    }

    /// Returns a new mnemonic instantiated from an existing entropy.
    pub const fn new_from_entropy(entropy: Entropy) -> Self {
        Self {
            entropy,
            _wordlist: PhantomData,
        }
    }

    /// Returns a new mnemonic for a given phrase. The 12-24 space-separated words are used to
    /// calculate the entropy that must have produced it.
    ///
    /// The phrase is NFKD-normalized first, so composed characters and ideographic spaces (as
    /// used in Japanese phrases) are accepted.
    pub fn new_from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        let phrase = nfkd("", phrase);
        let count = WordCount::try_from(phrase.split(' ').count())?;

        let mut encoded = EncodedEntropy::new();
        for (position, word) in phrase.split(' ').enumerate() {
            let index = W::get_index(word).map_err(|_| MnemonicError::InvalidWord(position))?;
            encoded.write_index(position, index);
        }

        encoded.to_entropy(count).map(Self::new_from_entropy)
    }

    /// Returns the mnemonic's entropy.
    pub const fn entropy(&self) -> &Entropy {
        &self.entropy
    }

    /// Returns the number of words in the mnemonic.
    pub const fn word_count(&self) -> WordCount {
        self.entropy.word_count()
    }

    /// Converts the mnemonic into an NFKD-normalized, space-separated phrase.
    pub fn to_phrase(&self) -> Zeroizing<String> {
        let encoded = EncodedEntropy::from_entropy(&self.entropy);

        // Allocate the maximum length up front. Growing the string would leave unzeroized copies
        // of the phrase behind in freed memory.
        let words = self.word_count().words();
        let mut phrase = Zeroizing::new(String::with_capacity(words * (MAX_WORD_BYTES + 1)));
        let mut word = PaddedWord::new();
        for position in 0..words {
            if position > 0 {
                phrase.push(' ');
            }
            word_at::<W>(encoded.read_index(position), &mut word);
            phrase.push_str(word.as_str());
        }
        phrase
    }

    /// Returns the master private key of the corresponding mnemonic.
    pub fn master_key(&self, password: Option<&str>) -> Result<XPriv, MnemonicError> {
        Ok(XPriv::root_from_seed(
            self.to_seed(password)?.as_slice(),
            None,
        )?)
    }

    /// Returns the derived child private key of the corresponding mnemonic at the given index.
    pub fn derive_key<E, P>(&self, path: P, password: Option<&str>) -> Result<XPriv, MnemonicError>
    where
        E: Into<Bip32Error>,
        P: TryInto<DerivationPath, Error = E>,
    {
        Ok(self.master_key(password)?.derive_path(path)?)
    }

    /// Convert to a bip23 seed
    pub fn to_seed(
        &self,
        password: Option<&str>,
    ) -> Result<Zeroizing<[u8; PBKDF2_BYTES]>, MnemonicError> {
        // The phrase is already NFKD-normalized, as wordlist words are.
        let salt = nfkd("mnemonic", password.unwrap_or(""));

        let mut seed = Zeroizing::new([0u8; PBKDF2_BYTES]);
        pbkdf2::<Hmac<Sha512>>(
            self.to_phrase().as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            seed.as_mut(),
        )
        .expect("cannot have invalid length");

        Ok(seed)
    }
}

#[cfg(all(test, feature = "english"))]
mod tests {
    use crate::English;
    use coins_bip32::enc::{MainnetEncoder, XKeyEncoder};

    use super::*;

    type W = English;

    #[test]
    fn test_word_count_params() {
        // BIP-39: (words, entropy bytes, checksum bits)
        let expected = [
            (WordCount::Twelve, 12, 16, 4),
            (WordCount::Fifteen, 15, 20, 5),
            (WordCount::Eighteen, 18, 24, 6),
            (WordCount::TwentyOne, 21, 28, 7),
            (WordCount::TwentyFour, 24, 32, 8),
        ];
        for (count, words, bytes, checksum_bits) in expected {
            assert_eq!(count.words(), words);
            assert_eq!(count.entropy_bytes(), bytes);
            assert_eq!(count.checksum_bits(), checksum_bits);
            assert_eq!(WordCount::try_from(words).unwrap(), count);
            assert_eq!(WordCount::from_entropy_bytes(bytes), Some(count));
        }
    }

    #[test]
    fn test_invalid_word_count() {
        assert!(matches!(
            WordCount::try_from(11),
            Err(MnemonicError::InvalidWordCount(11))
        ));
        let phrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        assert!(matches!(
            phrase.parse::<Mnemonic<W>>(),
            Err(MnemonicError::InvalidWordCount(11))
        ));
    }

    #[test]
    fn test_invalid_entropy_length() {
        for len in [0, 15, 17, 21, 33] {
            assert!(matches!(
                Entropy::from_slice(&vec![0u8; len]),
                Err(MnemonicError::InvalidEntropyLength(l)) if l == len
            ));
        }
    }

    #[test]
    fn test_invalid_word_in_phrase() {
        let phrase = "zoo zoo zoo mnemonic zoo zoo zoo zoo zoo zoo zoo zoo";
        let err = phrase.parse::<Mnemonic<W>>().unwrap_err();
        assert!(matches!(err, MnemonicError::InvalidWord(3)));
        assert!(!err.to_string().contains("mnemonic"));
    }

    #[test]
    fn test_invalid_checksum() {
        let phrase = "zoo zone zoo zone zoo zone zoo zone zoo zone zoo zone";
        let err = phrase.parse::<Mnemonic<W>>().unwrap_err();
        assert!(matches!(err, MnemonicError::InvalidChecksum));
        assert!(!err.to_string().contains("zoo"));
    }

    #[test]
    fn test_debug_redacts_entropy() {
        let entropy = Entropy::from([0xab; 16]);
        assert_eq!(format!("{entropy:?}"), "Entropy { word_count: Twelve, .. }");
        let mnemonic = Mnemonic::<W>::new_from_entropy(entropy);
        assert_eq!(
            format!("{mnemonic:?}"),
            "Mnemonic { word_count: Twelve, .. }"
        );
    }

    #[test]
    fn test_entropy_eq() {
        let a = Entropy::from([1u8; 16]);
        let mut bytes = [1u8; 16];
        bytes[15] = 2;
        assert_eq!(a, Entropy::from([1u8; 16]));
        assert_ne!(a, Entropy::from(bytes));
        assert_ne!(a, Entropy::from([1u8; 20]));
    }

    /// A wordlist violating the 2048-word requirement.
    struct Truncated;

    impl Wordlist for Truncated {
        fn get_all() -> &'static [&'static str] {
            &English::get_all()[..2047]
        }
    }

    #[test]
    #[should_panic(expected = "wordlists must contain 2048 words")]
    fn test_wordlist_length_guard_parse() {
        let _ = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .parse::<Mnemonic<Truncated>>();
    }

    #[test]
    #[should_panic(expected = "wordlists must contain 2048 words")]
    fn test_wordlist_length_guard_to_phrase() {
        Mnemonic::<Truncated>::new_from_entropy(Entropy::from([0u8; 16])).to_phrase();
    }

    #[test]
    fn test_random_round_trip() {
        let mut rng = rand::rng();
        for words in [12, 15, 18, 21, 24] {
            let count = WordCount::try_from(words).unwrap();
            let mnemonic = Mnemonic::<W>::random(count, &mut rng);
            assert_eq!(mnemonic.word_count(), count);
            assert_eq!(mnemonic.entropy().as_bytes().len(), count.entropy_bytes());

            let phrase = mnemonic.to_phrase();
            assert_eq!(phrase.split(' ').count(), words);
            assert_eq!(phrase.parse::<Mnemonic<W>>().unwrap(), mnemonic);
        }
    }

    // (entropy, phrase, seed, extended_private_key)
    const TESTCASES: [(&str, &str, &str, &str); 26] = [
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
            "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
            "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
        ),
        (
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
            "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
            "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm"
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
            "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
            "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
            "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"
        ),
        (
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
            "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
            "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk"
        ),
        (
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
            "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"
        ),
        (
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
            "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"
        ),
        (
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
            "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"
        ),
        (
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
            "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"
        ),
        (
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
            "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"
        ),
        (
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
            "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"
        ),
        (
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
            "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"
        ),
        (
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
            "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX"
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
            "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
        ),
        (
            "d292b36884b647974ff2167649e8255c8226a942",
            "spoon night surface annual good slight divert drift iron exercise announce ribbon carbon feed answer",
            "1c662e030a65b8e943a7f7fb304a1ecf415dcd1c99bfd587efae245ca9270058e853df0070abe61af152756c63a0b67ed74bf6e916b112289499e6052ccacc19",
            "xprv9s21ZrQH143K3pskpuVw5DMEBZ1hWZnVxwTpPc4QqjCPHbinjx5dyosHqPubQbGRoKdPci6hYRdr2QNDc2GwhCpSEAtKMrsjiBbYJJLfFj9"
        ),
        (
            "608945c274e181d9376c651255db6481ccb525532554eaea611cbbd1",
            "gauge enforce identify truth blossom uncle tank million banner put summer adjust slender naive erode pride turtle fantasy elbow jeans bar",
            "79da8e9aaeea7b28f9045fb0e4763fef5a7aae300b34c9f32aa8bb9a4aacd99896943beb22bbf9b50646658fd72cdf993b16a7cb5b7a77d1b443cf41f5183067",
            "xprv9s21ZrQH143K2Cy1ePyrB2tRcm97F6YFMzDZkhy9QS6PeCDtiDuZLrtt9WBfWhXEz8W5KbSnF7nWBKFzStfs8UPeyzbrCPPbHLC25HB8aFe"
        )
    ];

    #[test]
    fn test_from_phrase() {
        TESTCASES.iter().for_each(|(entropy_str, phrase, _, _)| {
            let expected_entropy = Entropy::from_slice(&hex::decode(entropy_str).unwrap()).unwrap();
            let mnemonic: Mnemonic<W> = phrase.parse().unwrap();
            assert_eq!(mnemonic.entropy(), &expected_entropy);
            assert_eq!(mnemonic.to_phrase().as_str(), *phrase);
        })
    }

    #[test]
    fn test_to_phrase() {
        TESTCASES
            .iter()
            .for_each(|(entropy_str, expected_phrase, _, _)| {
                let entropy = Entropy::from_slice(&hex::decode(entropy_str).unwrap()).unwrap();
                let mnemonic = Mnemonic::<W>::new_from_entropy(entropy);
                assert_eq!(mnemonic.to_phrase().as_str(), *expected_phrase)
            })
    }

    #[test]
    fn test_to_seed() {
        TESTCASES
            .iter()
            .for_each(|(entropy_str, _, expected_seed, _)| {
                let entropy = Entropy::from_slice(&hex::decode(entropy_str).unwrap()).unwrap();
                let mnemonic = Mnemonic::<W>::new_from_entropy(entropy);
                assert_eq!(
                    expected_seed,
                    &hex::encode(*mnemonic.to_seed(Some("TREZOR")).unwrap()),
                )
            });
    }

    #[test]
    fn test_master_key() {
        TESTCASES
            .iter()
            .for_each(|(_, phrase, _, expected_master_key)| {
                let mnemonic: Mnemonic<W> = phrase.parse().unwrap();
                let master_key = mnemonic.master_key(Some("TREZOR")).unwrap();
                assert_eq!(
                    MainnetEncoder::xpriv_from_base58(expected_master_key).unwrap(),
                    master_key,
                );
            });
    }

    #[test]
    fn test_derive_key_try_into_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::<W>::new_from_phrase(phrase).unwrap();
        mnemonic.derive_key(0, None).unwrap();
        mnemonic.derive_key("m/44'/61'/0'/0", None).unwrap();
    }
}

/// Japanese vectors from <https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json>.
/// Phrases use ideographic spaces and composed characters, and the passphrase requires NFKD
/// normalization.
#[cfg(all(test, feature = "japanese"))]
mod japanese_tests {
    use super::*;
    use crate::Japanese;
    use coins_bip32::enc::{MainnetEncoder, XKeyEncoder};

    const PASSPHRASE: &str = "㍍ガバヴァぱばぐゞちぢ十人十色";

    // (entropy, phrase, seed, extended_private_key)
    const TESTCASES: [(&str, &str, &str, &str); 24] = [
    (
        "00000000000000000000000000000000",
        "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
        "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
        "xprv9s21ZrQH143K258jAiWPAM6JYT9hLA91MV3AZUKfxmLZJCjCHeSjBvMbDy8C1mJ2FL5ytExyS97FAe6pQ6SD5Jt9SwHaLorA8i5Eojokfo1",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ",
        "aee025cbe6ca256862f889e48110a6a382365142f7d16f2b9545285b3af64e542143a577e9c144e101a6bdca18f8d97ec3366ebf5b088b1c1af9bc31346e60d9",
        "xprv9s21ZrQH143K3ra1D6uGQyST9UqtUscH99GK8MBh5RrgPkrQo83QG4o6H2YktwSKvoZRVXDQZQrSyCDpHdA2j8i3PW5M9LkauaaTKwym1Wf",
    ),
    (
        "80808080808080808080808080808080",
        "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あかちゃん",
        "e51736736ebdf77eda23fa17e31475fa1d9509c78f1deb6b4aacfbd760a7e2ad769c714352c95143b5c1241985bcb407df36d64e75dd5a2b78ca5d2ba82a3544",
        "xprv9s21ZrQH143K2aDKfG8hpfvRXzANmyBQWoqoUXWaSwVZcKtnmX5xTVkkHAdD9yykuuBcagjCFK6iLcBdHHxXC1g3TT9xHSu4PW6SRf3KvVy",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　ろんぶん",
        "4cd2ef49b479af5e1efbbd1e0bdc117f6a29b1010211df4f78e2ed40082865793e57949236c43b9fe591ec70e5bb4298b8b71dc4b267bb96ed4ed282c8f7761c",
        "xprv9s21ZrQH143K4WxYzpW3izjoq6e51NSZgN6AHxoKxZStsxBvtxuQDxPyvb8o4pSbxYPCyJGKewMxrHWvTBY6WEFX4svSzB2ezmatzzJW9wi",
    ),
    (
        "000000000000000000000000000000000000000000000000",
        "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あらいぐま",
        "d99e8f1ce2d4288d30b9c815ae981edd923c01aa4ffdc5dee1ab5fe0d4a3e13966023324d119105aff266dac32e5cd11431eeca23bbd7202ff423f30d6776d69",
        "xprv9s21ZrQH143K2pqcK1QdBVm9r4gL4yQX6KFTqHWctvfZa9Wjhxow63ZGpSB27mVo1BBH4D1NoTo3gVAHAeqmhm5Z9SuC8xJmFYBFz978rza",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れいぎ",
        "eaaf171efa5de4838c758a93d6c86d2677d4ccda4a064a7136344e975f91fe61340ec8a615464b461d67baaf12b62ab5e742f944c7bd4ab6c341fbafba435716",
        "xprv9s21ZrQH143K34NWKwHe5cBVDYuoKZ6iiqWczDMwGA9Ut57iCCTksDTnxE5AH3qHHvfcgwpRhyj4G7Y6FEewjVoQqq4gHN6CetyFdd3q4CR",
    ),
    (
        "808080808080808080808080808080808080808080808080",
        "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　いきなり",
        "aec0f8d3167a10683374c222e6e632f2940c0826587ea0a73ac5d0493b6a632590179a6538287641a9fc9df8e6f24e01bf1be548e1f74fd7407ccd72ecebe425",
        "xprv9s21ZrQH143K4RABcYmYKbZybgJrvpcnricsuNaZvsGVo7pupfELFY6TJw5G5XVswQodBzaRtfPkTi6aVCmC349A3yYzAZLfT7emP8m1RFX",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　りんご",
        "f0f738128a65b8d1854d68de50ed97ac1831fc3a978c569e415bbcb431a6a671d4377e3b56abd518daa861676c4da75a19ccb41e00c37d086941e471a4374b95",
        "xprv9s21ZrQH143K2ThaKxBDxUByy4gNwULJyqKQzZXyF3aLyGdknnP18KvKVZwCvBJGXaAsKd7oh2ypLbjyDn4bDY1iiSPvNkKsVAGQGj7G3PZ",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　いってい",
        "23f500eec4a563bf90cfda87b3e590b211b959985c555d17e88f46f7183590cd5793458b094a4dccc8f05807ec7bd2d19ce269e20568936a751f6f1ec7c14ddd",
        "xprv9s21ZrQH143K3skSyXVw9CTTUHgKnsysvKiJw9MQjvTSY6ysTk4sFz58htMAcqHrjLdnUhqxRtmRy5AMJyWGeuQrDGSSfmcNh7cbfnrbDty",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　まんきつ",
        "cd354a40aa2e241e8f306b3b752781b70dfd1c69190e510bc1297a9c5738e833bcdc179e81707d57263fb7564466f73d30bf979725ff783fb3eb4baa86560b05",
        "xprv9s21ZrQH143K2y9p1D6KuxqypMjbiBKkiALERahpxvb46x9giqkvmv5KxGvGJZG2mdcMunmHaazYyEqYmkx9SnfndimSmgJv5EL24X1DGqV",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　うめる",
        "6b7cd1b2cdfeeef8615077cadd6a0625f417f287652991c80206dbd82db17bf317d5c50a80bd9edd836b39daa1b6973359944c46d3fcc0129198dc7dc5cd0e68",
        "xprv9s21ZrQH143K2TuQM4HcbBBtvC19SaDgqn6cL16KTaPEazB26iCDfxABvBi9driWcbnF4rcLVpkx5iGG7zH2QcN7qNxL4cpb7mQ2G3ByAv7",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　らいう",
        "a44ba7054ac2f9226929d56505a51e13acdaa8a9097923ca07ea465c4c7e294c038f3f4e7e4b373726ba0057191aced6e48ac8d183f3a11569c426f0de414623",
        "xprv9s21ZrQH143K3XTGpC53cWswvhg6GVQ1dE1yty6F9VhBcE7rnXmStuKwtaZNXRxw5N7tsh1REyAxun1S5BCYvhD5pNwxWUMMZaHwjTmXFdb",
    ),
    (
        "77c2b00716cec7213839159e404db50d",
        "せまい　うちがわ　あずき　かろう　めずらしい　だんち　ますく　おさめる　ていぼう　あたる　すあな　えしゃく",
        "344cef9efc37d0cb36d89def03d09144dd51167923487eec42c487f7428908546fa31a3c26b7391a2b3afe7db81b9f8c5007336b58e269ea0bd10749a87e0193",
        "xprv9s21ZrQH143K2fhvZfecKw8znj6QkGGV2F2t17BWA6VnanejVWBjQeV5DspseWdSvN49rrFpocPGt7aSGk9R5wJfC1LAwFMt6hV9qS7yGKR",
    ),
    (
        "b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
        "ぬすむ　ふっかつ　うどん　こうりつ　しつじ　りょうり　おたがい　せもたれ　あつめる　いちりゅう　はんしゃ　ごますり　そんけい　たいちょう　らしんばん　ぶんせき　やすみ　ほいく",
        "b14e7d35904cb8569af0d6a016cee7066335a21c1c67891b01b83033cadb3e8a034a726e3909139ecd8b2eb9e9b05245684558f329b38480e262c1d6bc20ecc4",
        "xprv9s21ZrQH143K25BDHG8fiLEPvKD9QCWqqs8V4yz2NeZXHbDgnAYW1EL5k8KWcn1kGKmsHrqbNvePJaYWEgkEMjJEepwTFfVzzyYRN7cyJgM",
    ),
    (
        "3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
        "くのう　てぬぐい　そんかい　すろっと　ちきゅう　ほあん　とさか　はくしゅ　ひびく　みえる　そざい　てんすう　たんぴん　くしょう　すいようび　みけん　きさらぎ　げざん　ふくざつ　あつかう　はやい　くろう　おやゆび　こすう",
        "32e78dce2aff5db25aa7a4a32b493b5d10b4089923f3320c8b287a77e512455443298351beb3f7eb2390c4662a2e566eec5217e1a37467af43b46668d515e41b",
        "xprv9s21ZrQH143K2gbMb94GNwdogai6fA3vTrALH8eoNJKqPWn9KyeBMhUQLpsN5ePJkZdHsPmyDsECNLRaYiposqDDqsbk3ANk9hbsSgmVq7G",
    ),
    (
        "0460ef47585604c5660618db2e6a7e7f",
        "あみもの　いきおい　ふいうち　にげる　ざんしょ　じかん　ついか　はたん　ほあん　すんぽう　てちがい　わかめ",
        "0acf902cd391e30f3f5cb0605d72a4c849342f62bd6a360298c7013d714d7e58ddf9c7fdf141d0949f17a2c9c37ced1d8cb2edabab97c4199b142c829850154b",
        "xprv9s21ZrQH143K2Ec1okKMST9mN52SKEybSCeacWpAvPHMS5zFfMDfgwpJVXa96sd2sybGuJWE34CtSVYn42FBWLmFgmGeEmRvDriPnZVjWnU",
    ),
    (
        "72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
        "すろっと　にくしみ　なやむ　たとえる　へいこう　すくう　きない　けってい　とくべつ　ねっしん　いたみ　せんせい　おくりがな　まかい　とくい　けあな　いきおい　そそぐ",
        "9869e220bec09b6f0c0011f46e1f9032b269f096344028f5006a6e69ea5b0b8afabbb6944a23e11ebd021f182dd056d96e4e3657df241ca40babda532d364f73",
        "xprv9s21ZrQH143K2KKucNRqjGFooHw87xXFQpZGNZ1W7Vwtkr2YMkXFuxnMvqc8cegm8jkrVswEWuNEsGtFkaEedAG2cRTTtsz1bM6o8fCu3Pg",
    ),
    (
        "2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
        "かほご　きうい　ゆたか　みすえる　もらう　がっこう　よそう　ずっと　ときどき　したうけ　にんか　はっこう　つみき　すうじつ　よけい　くげん　もくてき　まわり　せめる　げざい　にげる　にんたい　たんそく　ほそく",
        "713b7e70c9fbc18c831bfd1f03302422822c3727a93a5efb9659bec6ad8d6f2c1b5c8ed8b0b77775feaf606e9d1cc0a84ac416a85514ad59f5541ff5e0382481",
        "xprv9s21ZrQH143K2MXrVTP5hyWW9js9D8qipo9vVRTKYPCB8Mtw4XE57uepG7wuHRk3ZJLGAq1tdJ4So8hYHu4gBaJ4NANPjb1CJCpDd3e9H87",
    ),
    (
        "eaebabb2383351fd31d703840b32e9e2",
        "めいえん　さのう　めだつ　すてる　きぬごし　ろんぱ　はんこ　まける　たいおう　さかいし　ねんいり　はぶらし",
        "06e1d5289a97bcc95cb4a6360719131a786aba057d8efd603a547bd254261c2a97fcd3e8a4e766d5416437e956b388336d36c7ad2dba4ee6796f0249b10ee961",
        "xprv9s21ZrQH143K3ZVFWWSR9XVXY8EMqCNdj7YUx4DKdcCFitEsSH18aPcufobUfP3w9xz1XTUThwC4cYuf8VWvSwYWs8aTTAi7mr9jDsGHYLU",
    ),
    (
        "7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
        "せんぱい　おしえる　ぐんかん　もらう　きあい　きぼう　やおや　いせえび　のいず　じゅしん　よゆう　きみつ　さといも　ちんもく　ちわわ　しんせいじ　とめる　はちみつ",
        "1fef28785d08cbf41d7a20a3a6891043395779ed74503a5652760ee8c24dfe60972105ee71d5168071a35ab7b5bd2f8831f75488078a90f0926c8e9171b2bc4a",
        "xprv9s21ZrQH143K3CXbNxjnq5iemN7AzZrtE71rvBAuZ4BnebovyS2hK3yjbAzsX6mrdxK8fa4kXPjnCC9FHpwgaPwZuCbrUJ4sj6xdPPYNeKK",
    ),
    (
        "4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
        "こころ　いどう　きあつ　そうがんきょう　へいあん　せつりつ　ごうせい　はいち　いびき　きこく　あんい　おちつく　きこえる　けんとう　たいこ　すすめる　はっけん　ていど　はんおん　いんさつ　うなぎ　しねま　れいぼう　みつかる",
        "43de99b502e152d4c198542624511db3007c8f8f126a30818e856b2d8a20400d29e7a7e3fdd21f909e23be5e3c8d9aee3a739b0b65041ff0b8637276703f65c2",
        "xprv9s21ZrQH143K2WyZ5cAUSqkC89FeL4mrEG9N9VEhh9pR2g6SQjWbXNufkfBwwaZtMfpDzip9fZjm3huvMEJASWviaGqG1A6bDmoSQzd3YFy",
    ),
    (
        "18ab19a9f54a9274f03e5209a2ac8a91",
        "うりきれ　さいせい　じゆう　むろん　とどける　ぐうたら　はいれつ　ひけつ　いずれ　うちあわせ　おさめる　おたく",
        "3d711f075ee44d8b535bb4561ad76d7d5350ea0b1f5d2eac054e869ff7963cdce9581097a477d697a2a9433a0c6884bea10a2193647677977c9820dd0921cbde",
        "xprv9s21ZrQH143K49xMPBpnqsaXt6EECMPzVAvr18EiiJMHfgEedw28JiSCpB5DLGQB19NU2iiG4g7vVnLC6jn75B4n3LHCPwhpU6o7Srd6jYt",
    ),
    (
        "18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
        "うりきれ　うねる　せっさたくま　きもち　めんきょ　へいたく　たまご　ぜっく　びじゅつかん　さんそ　むせる　せいじ　ねくたい　しはらい　せおう　ねんど　たんまつ　がいけん",
        "753ec9e333e616e9471482b4b70a18d413241f1e335c65cd7996f32b66cf95546612c51dcf12ead6f805f9ee3d965846b894ae99b24204954be80810d292fcdd",
        "xprv9s21ZrQH143K2WyY1Me9W7T8Wg7yQa9WFVAEn1vhoDkkP43dBVhsagabzEKMaz7UNtczbKkNowDLXSyVipJXVEBcpYJGBJ6ZaVDXNGoLStz",
    ),
    (
        "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
        "うちゅう　ふそく　ひしょ　がちょう　うけもつ　めいそう　みかん　そざい　いばる　うけとる　さんま　さこつ　おうさま　ぱんつ　しひょう　めした　たはつ　いちぶ　つうじょう　てさぎょう　きつね　みすえる　いりぐち　かめれおん",
        "346b7321d8c04f6f37b49fdf062a2fddc8e1bf8f1d33171b65074531ec546d1d3469974beccb1a09263440fc92e1042580a557fdce314e27ee4eabb25fa5e5fe",
        "xprv9s21ZrQH143K2qVq43Phs1xyVc6jSxXHWJ6CDJjod3cgyEin7hgeQV6Dkw6s1LSfMYxoah4bPAnW4wmXfDUS9ghBEM18xoY634CBtX8HPrA",
    ),
    ];

    #[test]
    fn test_japanese_vectors() {
        for (entropy, phrase, seed, xpriv) in TESTCASES {
            let mnemonic: Mnemonic<Japanese> = phrase.parse().unwrap();
            assert_eq!(mnemonic.entropy().as_bytes(), hex::decode(entropy).unwrap());
            assert_eq!(
                hex::encode(*mnemonic.to_seed(Some(PASSPHRASE)).unwrap()),
                seed
            );
            assert_eq!(
                mnemonic.master_key(Some(PASSPHRASE)).unwrap(),
                MainnetEncoder::xpriv_from_base58(xpriv).unwrap()
            );
        }
    }
}
