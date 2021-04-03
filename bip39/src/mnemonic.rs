use crate::{Wordlist, WordlistError};
use bitvec::prelude::*;
use coins_bip32::{path::DerivationPath, xkeys::XPriv, Bip32Error};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use std::{convert::TryInto, marker::PhantomData};
use thiserror::Error;

const PBKDF2_ROUNDS: u32 = 2048;
const PBKDF2_BYTES: usize = 64;

/// Mnemonic represents entropy that can be represented as a phrase. A mnemonic can be used to
/// deterministically generate an extended private key or derive its child keys.
pub struct Mnemonic<W: Wordlist> {
    /// Entropy used to generate mnemonic.
    entropy: Vec<u8>,
    /// Wordlist used to produce phrases from entropy.
    _wordlist: PhantomData<W>,
}

#[derive(Debug, Error)]
/// The error type returned while interacting with mnemonics.
pub enum MnemonicError {
    /// Describes the error when the mnemonic's entropy length is invalid.
    #[error("the mnemonic's entropy length `{0}` is invalid")]
    InvalidEntropyLength(usize),
    /// Describes the error when the given phrase is invalid.
    #[error("the phrase `{0}` is invalid")]
    InvalidPhrase(String),
    /// Describes the error when the word count provided for mnemonic generation is invalid.
    #[error("invalid word count (expected 12, 15, 18, 21, 24, found `{0}`")]
    InvalidWordCount(usize),
    /// Describes an error propagated from the wordlist errors.
    #[error(transparent)]
    WordlistError(#[from] WordlistError),
    /// Describes an error propagated from the BIP-32 crate.
    #[error(transparent)]
    Bip32Error(#[from] Bip32Error),
}

impl<W: Wordlist> Mnemonic<W> {
    /// Returns a new mnemonic generated using the provided random number generator.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let entropy: [u8; 16] = rng.gen();
        Self {
            entropy: entropy.to_vec(),
            _wordlist: PhantomData,
        }
    }

    /// Returns a new mnemonic given the word count, generated using the provided random number
    /// generator.
    pub fn new_with_count<R: Rng>(rng: &mut R, count: usize) -> Result<Self, MnemonicError> {
        let length: usize = match count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            wc => return Err(MnemonicError::InvalidWordCount(wc)),
        };
        let entropy: [u8; 32] = rng.gen();
        Ok(Self {
            entropy: entropy[0..length].to_vec(),
            _wordlist: PhantomData,
        })
    }

    /// Returns a new mnemonic for a given phrase. The 12-24 space-separated words are used to
    /// calculate the entropy that must have produced it.
    pub fn new_from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        let words = phrase.split(' ').collect::<Vec<&str>>();
        let length: usize = match words.len() {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            wc => return Err(MnemonicError::InvalidWordCount(wc)),
        };

        let mut entropy: BitVec<Msb0, u8> = BitVec::new();
        for word in words {
            let index = W::get_index(word)?;
            let index_u8: [u8; 2] = (index as u16).to_be_bytes();

            // 11-bits per word as per BIP-39, and max index (2047) can be represented in 11-bits.
            let index_slice = &BitVec::from_slice(&index_u8)[5..];

            entropy.append(&mut BitVec::<Msb0, u8>::from_bitslice(index_slice));
        }

        let mnemonic = Self {
            entropy: entropy.as_slice()[0..length].to_vec(),
            _wordlist: PhantomData,
        };

        // Ensures the checksum word matches the checksum word in the given phrase.
        match phrase == mnemonic.to_phrase()? {
            true => Ok(mnemonic),
            false => Err(MnemonicError::InvalidPhrase(phrase.into())),
        }
    }

    /// Converts the mnemonic into phrase.
    pub fn to_phrase(&self) -> Result<String, MnemonicError> {
        let length: usize = match self.entropy.len() {
            16 => 12,
            20 => 15,
            24 => 18,
            28 => 21,
            32 => 24,
            el => return Err(MnemonicError::InvalidEntropyLength(el)),
        };

        // Compute checksum. Checksum is the most significant (ENTROPY_BYTES/4) bits. That is also
        // equivalent to (WORD_COUNT/3).
        let mut hasher = Sha256::new();
        hasher.update(self.entropy.as_slice());
        let hash = hasher.finalize();
        let hash_0 = BitVec::<Msb0, u8>::from_element(hash[0]);
        let (checksum, _) = hash_0.split_at(length / 3);

        // Convert the entropy bytes into bits and append the checksum.
        let mut encoding = BitVec::<Msb0, u8>::from_vec(self.entropy.clone());
        encoding.append(&mut checksum.to_vec());

        // Compute the phrase in 11 bit chunks which encode an index into the word list
        let wordlist = W::get_all();
        let phrase = encoding
            .chunks(11)
            .map(|index| {
                // Convert a vector of 11 bits into a u11 number.
                let index = index
                    .iter()
                    .enumerate()
                    .map(|(i, bit)| (*bit as u16) * 2u16.pow(10 - i as u32))
                    .sum::<u16>();

                wordlist[index as usize]
            })
            .collect::<Vec<&str>>();

        Ok(phrase.join(" "))
    }
}

impl<W: Wordlist> Mnemonic<W> {
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

    fn to_seed(&self, password: Option<&str>) -> Result<Vec<u8>, MnemonicError> {
        let mut seed = vec![0u8; PBKDF2_BYTES];
        let salt = format!("mnemonic{}", password.unwrap_or(""));
        pbkdf2::<Hmac<Sha512>>(
            &self.to_phrase()?.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            &mut seed,
        );

        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use crate::English;
    use coins_bip32::enc::{MainnetEncoder, XKeyEncoder};

    use super::*;

    type W = English;

    #[test]
    #[should_panic(expected = "InvalidWordCount(11)")]
    fn test_invalid_word_count() {
        let mut rng = rand::thread_rng();
        let _mnemonic = Mnemonic::<W>::new_with_count(&mut rng, 11usize).unwrap();
    }

    #[test]
    #[should_panic(expected = "WordlistError(InvalidWord(\"mnemonic\"))")]
    fn test_invalid_word_in_phrase() {
        let phrase = "mnemonic zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo";
        let _mnemonic = Mnemonic::<W>::new_from_phrase(phrase).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "InvalidPhrase(\"zoo zone zoo zone zoo zone zoo zone zoo zone zoo zone\")"
    )]
    fn test_invalid_phrase() {
        let phrase = "zoo zone zoo zone zoo zone zoo zone zoo zone zoo zone";
        let _mnemonic = Mnemonic::<W>::new_from_phrase(phrase).unwrap();
    }

    // (entropy, phrase, seed, extended_private_key)
    const TESTCASES: [(&str, &str, &str, &str); 5] = [
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
    ];

    #[test]
    fn test_from_phrase() {
        TESTCASES.iter().for_each(|(entropy_str, phrase, _, _)| {
            let expected_entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
            let mnemonic = Mnemonic::<W>::new_from_phrase(phrase).unwrap();
            assert_eq!(mnemonic.entropy, expected_entropy);
            assert_eq!(mnemonic.to_phrase().unwrap(), phrase.to_string());
        })
    }

    #[test]
    fn test_to_phrase() {
        TESTCASES
            .iter()
            .for_each(|(entropy_str, expected_phrase, _, _)| {
                let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
                let mnemonic = Mnemonic::<W> {
                    entropy: entropy.clone(),
                    _wordlist: PhantomData,
                };
                assert_eq!(mnemonic.entropy, entropy);
                assert_eq!(mnemonic.to_phrase().unwrap(), expected_phrase.to_string())
            })
    }

    #[test]
    fn test_to_seed() {
        TESTCASES
            .iter()
            .for_each(|(entropy_str, _, expected_seed, _)| {
                let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
                let mnemonic = Mnemonic::<W> {
                    entropy,
                    _wordlist: PhantomData,
                };
                assert_eq!(
                    expected_seed,
                    &hex::encode(mnemonic.to_seed(Some("TREZOR")).unwrap()),
                )
            });
    }

    #[test]
    fn test_master_key() {
        TESTCASES
            .iter()
            .for_each(|(_, phrase, _, expected_master_key)| {
                let mnemonic = Mnemonic::<W>::new_from_phrase(phrase).unwrap();
                let master_key = mnemonic.master_key(Some("TREZOR")).unwrap();
                assert_eq!(
                    MainnetEncoder::xpriv_from_base58(expected_master_key).unwrap(),
                    master_key,
                );
            });
    }
}
