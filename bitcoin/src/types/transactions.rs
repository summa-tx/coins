//! Bitcoin transaction types and associated sighash arguments.
use std::io::Error as IOError;
use thiserror::Error;

use riemann_core::{
    hashes::hash256::Hash256Writer,
    ser::{ByteFormat, SerError},
    types::tx::Transaction,
};

use crate::{
    hashes::TXID,
    types::{
        legacy::*,
        script::Witness,
        txin::{BitcoinOutpoint, BitcoinTxIn},
        txout::TxOut,
        witness::*,
    },
};

/// Wrapper enum for returning values that may be EITHER a Witness OR a Legacy tx and the type is
/// not known in advance. While a few transaction methods have been implemented for convenience,
/// This wrapper must be explicitly unwrapped before the tx object can be signed.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum BitcoinTx {
    /// Witness
    Witness(WitnessTx),
    /// Legacy
    Legacy(LegacyTx),
}

impl From<WitnessTx> for BitcoinTx {
    fn from(w: WitnessTx) -> Self {
        BitcoinTx::Witness(w)
    }
}

impl From<LegacyTx> for BitcoinTx {
    fn from(w: LegacyTx) -> Self {
        BitcoinTx::Legacy(w)
    }
}

impl BitcoinTx {
    /// Deserialize a hex string. Determine type information from the segwit marker `0001`
    /// immediately following the version bytes. This produces a `BitcoinTx` enum that must be
    /// explicitly cast to the desired type via `into_witness` or `into_legacy`.
    ///
    /// # Note
    ///
    /// Casting directly to legacy may drop witness information if the tx is witness
    pub fn deserialize_hex(hex: &str) -> Result<BitcoinTx, TxError> {
        if &hex[8..12] == "0001" {
            WitnessTx::deserialize_hex(hex).map(BitcoinTx::Witness)
        } else {
            LegacyTx::deserialize_hex(hex).map(BitcoinTx::Legacy)
        }
    }

    /// Serialize the transaction to a hex string.
    pub fn serialize_hex(&self) -> String {
        match self {
            BitcoinTx::Witness(tx) => tx.serialize_hex(),
            BitcoinTx::Legacy(tx) => tx.serialize_hex(),
        }
    }

    /// Return the TXID of the transaction
    pub fn txid(&self) -> TXID {
        match self {
            BitcoinTx::Witness(tx) => tx.txid(),
            BitcoinTx::Legacy(tx) => tx.txid(),
        }
    }

    /// True if the wrapped tx is a witness transaction. False otherwise
    pub fn is_witness(&self) -> bool {
        match self {
            BitcoinTx::Witness(_) => true,
            _ => false,
        }
    }

    /// True if the wrapped tx is a legacy transaction. False otherwise
    pub fn is_legacy(&self) -> bool {
        match self {
            BitcoinTx::Legacy(_) => true,
            _ => false,
        }
    }

    /// Return a reference to the underlying tx as a legacy TX.
    pub fn as_legacy(&self) -> &LegacyTx {
        match self {
            BitcoinTx::Witness(tx) => tx.as_legacy(),
            BitcoinTx::Legacy(tx) => &tx,
        }
    }

    /// Consume the wrapper and convert it to a legacy tx. but `into_witness` should be
    /// preferred, as it will never drop information.
    pub fn into_legacy(self) -> LegacyTx {
        match self {
            BitcoinTx::Witness(tx) => tx.into_legacy(),
            BitcoinTx::Legacy(tx) => tx,
        }
    }

    /// Consume the wrapper and convert it to a witness tx.
    pub fn into_witness(self) -> WitnessTx {
        match self {
            BitcoinTx::Witness(tx) => tx,
            BitcoinTx::Legacy(tx) => tx.into_witness(),
        }
    }

    /// Instantiate a new `BitcoinTx`. This always returns a `BitcoinTx::Legacy`
    pub fn new<I, O>(version: u32, vin: I, vout: O, locktime: u32) -> Self
    where
        I: Into<Vec<BitcoinTxIn>>,
        O: Into<Vec<TxOut>>,
    {
        Self::Legacy(LegacyTx {
            version,
            vin: vin.into(),
            vout: vout.into(),
            locktime,
        })
    }

    /// Get the inputs from the underlying tx
    pub fn inputs(&self) -> &[BitcoinTxIn] {
        match self {
            BitcoinTx::Witness(tx) => tx.inputs(),
            BitcoinTx::Legacy(tx) => tx.inputs(),
        }
    }

    /// Get the outputs from the underlying tx
    pub fn outputs(&self) -> &[TxOut] {
        match self {
            BitcoinTx::Witness(tx) => tx.outputs(),
            BitcoinTx::Legacy(tx) => tx.outputs(),
        }
    }

    /// Get the version number from the underlying tx
    pub fn version(&self) -> u32 {
        match self {
            BitcoinTx::Witness(tx) => tx.version(),
            BitcoinTx::Legacy(tx) => tx.version(),
        }
    }

    /// Get the locktime from the underlying tx
    pub fn locktime(&self) -> u32 {
        match self {
            BitcoinTx::Witness(tx) => tx.locktime(),
            BitcoinTx::Legacy(tx) => tx.locktime(),
        }
    }

    /// Get the locktime from the underlying tx. Returns a 0-length slice for legacy txns
    pub fn witnesses(&self) -> &[Witness] {
        match self {
            BitcoinTx::Witness(tx) => tx.witnesses(),
            BitcoinTx::Legacy(_) => &[],
        }
    }
}

/// An Error type for transaction objects
#[derive(Debug, Error)]
pub enum TxError {
    /// Serialization-related errors
    #[error(transparent)]
    SerError(#[from] SerError),

    /// IOError bubbled up from a `Write` passed to a `ByteFormat::serialize` implementation.
    #[error(transparent)]
    IOError(#[from] IOError),

    /// Sighash NONE is unsupported
    #[error("SIGHASH_NONE is unsupported")]
    NoneUnsupported,

    /// Satoshi's sighash single bug. Throws an error here.
    #[error("SIGHASH_SINGLE bug is unsupported")]
    SighashSingleBug,

    /// Caller provided an unknown sighash type to `Sighash::from_u8`
    #[error("Unknown Sighash: {}", .0)]
    UnknownSighash(u8),

    /// Got an unknown flag where we expected a witness flag. May indicate a non-witness
    /// transaction.
    #[error("Witness flag not as expected. Got {:?}. Expected {:?}.", .0, [0u8, 1u8])]
    BadWitnessFlag([u8; 2]),
    // /// No inputs in vin
    // #[error("Vin may not be empty")]
    // EmptyVin,
    //
    // /// No outputs in vout
    // #[error("Vout may not be empty")]
    // EmptyVout
}

/// Type alias for result with TxError
pub type TxResult<T> = Result<T, TxError>;

/// Functions common to Bitcoin transactions. This provides a small abstraction layer over the
/// Legacy/SegWit tx divide by implementing a small common interface between them.
pub trait BitcoinTransaction:
    Transaction<
    Digest = bitcoin_spv::types::Hash256Digest,
    Error = TxError,  // Ser associated error
    TxError = TxError,
    TXID = TXID,
    TxOut = TxOut,
    TxIn = BitcoinTxIn,
    HashWriter = Hash256Writer,
>
{
    /// Returns a reference to the tx as a legacy tx.
    fn as_legacy(&self) -> &LegacyTx;

    /// Consume the tx and convert it to a legacy tx. Useful for when you have
    /// `dyn BitcoinTransaction` or `impl BitcoinTransaction` types, but `into_witness` should be
    /// preferred, as it will never drop information.
    fn into_legacy(self) -> LegacyTx;

    /// Consume the tx and convert it to a legacy tx. Useful for when you have
    /// `dyn BitcoinTransaction` or `impl BitcoinTransaction` types.
    fn into_witness(self) -> WitnessTx;

    /// Return a reference to a slice of witnesses. For legacy txins this will ALWAYS be length 0.
    /// For witness txns, this will ALWAYS be the same length as the input vector.
    fn witnesses(&self) -> &[Witness];

    /// Get a reference to the output by
    fn txout_from_outpoint(&self, outpoint: &BitcoinOutpoint) -> Option<&TxOut> {
        if outpoint.txid == self.txid() && (outpoint.idx as usize) < self.outputs().len() {
            Some(&self.outputs()[outpoint.idx as usize])
        } else {
            None
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// All possible Sighash modes
pub enum Sighash {
    /// Sign ALL inputs and ALL outputs
    All = 0x01,
    /// Sign ALL inputs and NO outputs (unsupported)
    None = 0x02,
    /// Sign ALL inputs and ONE output
    Single = 0x3,
    /// Sign ONE inputs and ALL outputs
    AllACP = 0x81,
    /// Sign ONE inputs and NO outputs (unsupported)
    NoneACP = 0x82,
    /// Sign ONE inputs and ONE output
    SingleACP = 0x83,
}

impl Sighash {
    ///
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Convert a u8 into a Sighash flag or an error.
    pub fn from_u8(flag: u8) -> Result<Sighash, TxError> {
        match flag {
            0x01 => Ok(Sighash::All),
            0x02 => Ok(Sighash::None),
            0x3 => Ok(Sighash::Single),
            0x81 => Ok(Sighash::AllACP),
            0x82 => Ok(Sighash::NoneACP),
            0x83 => Ok(Sighash::SingleACP),
            _ => Err(TxError::UnknownSighash(flag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    use bitcoin_spv::types::Hash256Digest;

    #[test]
    fn it_calculates_legacy_sighashes_and_txids() {
        // pulled from riemann helpers
        let tx_hex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx = LegacyTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "17a91424d6008f143af0cca57344069c46661aa4fcea2387";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "b85c4f8d1377cc138225dd9b319d0a4ca547f7884270640f44c5fcdf269e0fe8",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "3b67a5114cc9fc837ddd6f6ec11bde38db5f68c34ab6ece2a043d7b25f2cf8bb",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "1dab67d768be0380fc800098005d1f61744ffe585b0852f8d7adc12121a86938",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "d4687b93c0a9090dc0a3384cd3a594ce613834bb37abc56f6032e96c597547e3",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "03ee4f7a4e68f802303bc659f8f817964b4b74fe046facc3ae1be4679d622c45",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = LegacySighashArgs {
            index: 0,
            sighash_flag: Sighash::All,
            prevout_script,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);
        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);
        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);
        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_calculates_witness_sighashes_and_txids() {
        // pulled from riemann helpers
        let tx_hex = "02000000000101ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0173d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18700cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "160014758ce550380d964051086798d6546bebdca27a73";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "135754ab872e4943f7a9c30d6143c4c7187e33d0f63c75ec82a7f9a15e2f2d00",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "cc7438d5b15e93ba612dcd227cf1937c35273675b3aa7d1b771573667376ddf6",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "d04631d2742e6fd8e80e2e4309dece65becca41d37fd6bc0bcba041c52d824d5",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "ffea9cdda07170af9bc9967cedf485e9fe15b78a622e0c196c0b6fc64f40c615",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "9e77087321b870859ebf08976d665c42d9f98cad18fff6a05a91c1d2da6d6c41",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = WitnessSighashArgs {
            index: 0,
            sighash_flag: Sighash::All,
            prevout_script,
            prevout_value: 120000,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);

        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);

        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);

        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_passes_more_witness_sighash_tests() {
        // from riemann
        let tx_hex = "02000000000102ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0273d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18773d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f1870000cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "160014758ce550380d964051086798d6546bebdca27a73";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "75385c87ece4980b581cfd71bc5814f607801a87f6e0973c63dc9fda465c19c4",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "bc55c4303c82cdcc8e290c597a00d662ab34414d79ec15d63912b8be7fe2ca3c",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "9d57bf7af01a4e0baa57e749aa193d37a64e3bbc08eb88af93944f41af8dfc70",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "ffea9cdda07170af9bc9967cedf485e9fe15b78a622e0c196c0b6fc64f40c615",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "184e7bce099679b27ed958213c97d2fb971e227c6517bca11f06ccbb97dcdc30",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = WitnessSighashArgs {
            index: 1,
            sighash_flag: Sighash::All,
            prevout_script,
            prevout_value: 120000,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);
        assert_eq!(tx.witness_sighash(&args).unwrap(), all);

        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);
        assert_eq!(tx.witness_sighash(&args).unwrap(), all_anyonecanpay);

        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);
        assert_eq!(tx.witness_sighash(&args).unwrap(), single);

        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
        assert_eq!(tx.witness_sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_passes_more_legacy_sighash_tests() {
        // from riemann
        let tx_hex = "0200000002ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0273d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18773d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18700000000";
        let tx = LegacyTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "160014758ce550380d964051086798d6546bebdca27a73";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "3ab40bf1287b7be9a5c67ed0f97f80b38c5f68e53ec93bffd3893901eaaafdb2",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "2d5802fed31e1ef6a857346cc0a9085ea452daeeb3a0b5afcb16a2203ce5689d",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "ea52b62b26c1f0db838c952fa50806fb8e39ba4c92a9a88d1b4ba7e9c094517d",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "9e2aca0a04afa6e1e5e00ff16b06a247a0da1e7bbaa7cd761c066a82bb3b07d0",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "40157948972c5c97a2bafff861ee2f8745151385c7f9fbd03991ddf59b76ac81",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = LegacySighashArgs {
            index: 1,
            sighash_flag: Sighash::All,
            prevout_script,
        };

        assert_eq!(tx.sighash(&args).unwrap(), all);

        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.sighash(&args).unwrap(), all_anyonecanpay);

        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.sighash(&args).unwrap(), single);

        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_calculates_witness_txid() {
        // from mainnet: 3c7fb4af9b7bd2ba6f155318e0bc8a50432d4732ab6e36293ef45b304567b46a
        let tx_hex = "01000000000101b77bebb3ac480e99c0d95a4c812137b116e65e2f3b3a66a36d0e252928d460180100000000ffffffff03982457000000000017a91417b8e0f150215cc70bf2fb58070041d655b162dd8740e133000000000017a9142535e444f7d55f0500c1f86609d6cfc289576b698747abfb0100000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402205c6a889efa26955bef7ce2b08792e63e25eac9859080f0d83912b0ea833d7eb402205f859f4640f1600db5012b467ec05bb4ae1779640c1b5fadc8908960740e52b30147304402201c239ea25cfeadfa9493a1b0d136d70f50f821385972b7188c4329c2bf2d23a302201ee790e4b6794af6567f85a226a387d5b0222c3dc90d2fc558d09e08062b8271016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000";
        let wtxid = Hash256Digest::deserialize_hex(
            "84d85ce82c728e072bb11f379a6ed0b9127aa43905b7bae14b254bfcdce63549",
        )
        .unwrap();

        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();

        assert_eq!(tx.wtxid(), wtxid.into());
    }

    #[test]
    fn it_rejects_sighash_none() {
        let tx_hex = "02000000000102ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0273d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f18773d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f1870000cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();

        let args = WitnessSighashArgs {
            index: 0,
            sighash_flag: Sighash::None,
            prevout_script: vec![].into(),
            prevout_value: 120000,
        };

        match tx.sighash(&args) {
            Err(TxError::NoneUnsupported) => {}
            _ => assert!(false, "expected sighash none unsupported"),
        }
    }

    #[test]
    fn it_rejects_sighash_single_bug() {
        let tx_hex = "02000000000102ee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffffee9242c89e79ab2aa537408839329895392b97505b3496d5543d6d2f531b94d20000000000fdffffff0173d301000000000017a914bba5acbec4e6e3374a0345bf3609fa7cfea825f1870000cafd0700";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();

        let args = WitnessSighashArgs {
            index: 1,
            sighash_flag: Sighash::Single,
            prevout_script: vec![].into(),
            prevout_value: 120000,
        };

        match tx.sighash(&args) {
            Err(TxError::SighashSingleBug) => {}
            _ => assert!(false, "expected sighash single bug unsupported"),
        }
    }

    #[test]
    fn it_calculates_legacy_sighash_of_witness_txns() {
        // pulled from riemann helpers
        let tx_hex = "01000000000101813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac0019430600";
        let tx = WitnessTx::deserialize_hex(tx_hex).unwrap();
        assert_eq!(tx.as_legacy().clone().into_witness(), tx);
        assert_eq!(tx.serialized_length(), tx_hex.len() / 2);

        let prevout_script_hex = "17a91424d6008f143af0cca57344069c46661aa4fcea2387";
        let prevout_script = Script::deserialize_hex(prevout_script_hex).unwrap();

        let all = Hash256Digest::deserialize_hex(
            "b85c4f8d1377cc138225dd9b319d0a4ca547f7884270640f44c5fcdf269e0fe8",
        )
        .unwrap();
        let all_anyonecanpay = Hash256Digest::deserialize_hex(
            "3b67a5114cc9fc837ddd6f6ec11bde38db5f68c34ab6ece2a043d7b25f2cf8bb",
        )
        .unwrap();
        let single = Hash256Digest::deserialize_hex(
            "1dab67d768be0380fc800098005d1f61744ffe585b0852f8d7adc12121a86938",
        )
        .unwrap();
        let single_anyonecanpay = Hash256Digest::deserialize_hex(
            "d4687b93c0a9090dc0a3384cd3a594ce613834bb37abc56f6032e96c597547e3",
        )
        .unwrap();

        let txid = Hash256Digest::deserialize_hex(
            "03ee4f7a4e68f802303bc659f8f817964b4b74fe046facc3ae1be4679d622c45",
        )
        .unwrap();
        assert_eq!(tx.txid(), txid.into());

        let mut args = LegacySighashArgs {
            index: 0,
            sighash_flag: Sighash::All,
            prevout_script,
        };

        assert_eq!(tx.legacy_sighash(&args).unwrap(), all);
        args.sighash_flag = Sighash::AllACP;
        assert_eq!(tx.legacy_sighash(&args).unwrap(), all_anyonecanpay);
        args.sighash_flag = Sighash::Single;
        assert_eq!(tx.legacy_sighash(&args).unwrap(), single);
        args.sighash_flag = Sighash::SingleACP;
        assert_eq!(tx.legacy_sighash(&args).unwrap(), single_anyonecanpay);
    }

    #[test]
    fn it_gets_sighash_flags_from_u8s() {
        let cases = [
            (0x01, Sighash::All),
            (0x02, Sighash::None),
            (0x3, Sighash::Single),
            (0x81, Sighash::AllACP),
            (0x82, Sighash::NoneACP),
            (0x83, Sighash::SingleACP),
        ];
        let errors = [
            (0x84, TxError::UnknownSighash(0x84)),
            (0x16, TxError::UnknownSighash(0x16)),
            (0x34, TxError::UnknownSighash(0x34)),
            (0xab, TxError::UnknownSighash(0xab)),
            (0x39, TxError::UnknownSighash(0x39)),
            (0x00, TxError::UnknownSighash(0x00)),
            (0x30, TxError::UnknownSighash(0x30)),
            (0x4, TxError::UnknownSighash(0x4)),
        ];
        for case in cases.iter() {
            assert_eq!(Sighash::from_u8(case.0).unwrap(), case.1)
        }
        for case in errors.iter() {
            match Sighash::from_u8(case.0) {
                Err(TxError::UnknownSighash(v)) => assert_eq!(case.0, v),
                _ => assert!(false, "expected err unknown sighash"),
            }
        }
    }
}
