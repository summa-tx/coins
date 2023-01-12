use bitcoins::{
    prelude::ByteFormat,
    types::{BitcoinTxIn, ScriptType, SpendScript, TxOut, Utxo},
};
use coins_bip32::{path::DerivationPath, prelude::*};
use coins_core::ser;
use coins_ledger::common::{APDUAnswer, APDUCommand, APDUData};

use crate::LedgerBTCError;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Commands {
    GetWalletPublicKey = 0x40,
    UntrustedHashTxInputStart = 0x44,
    UntrustedHashSign = 0x48,
    UntrustedHashTxInputFinalizeFull = 0x4a,
}

pub(crate) struct InternalKeyInfo {
    pub(crate) pubkey: VerifyingKey,
    pub(crate) path: DerivationPath,
    pub(crate) chain_code: ChainCode,
}

pub(crate) fn parse_pubkey_response(deriv: &DerivationPath, data: &[u8]) -> InternalKeyInfo {
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&data[data.len() - 32..]);

    let mut pk = [0u8; 65];
    pk.copy_from_slice(&data[1..66]);
    InternalKeyInfo {
        pubkey: VerifyingKey::from_sec1_bytes(&pk).unwrap(),
        path: deriv.clone(),
        chain_code: chain_code.into(),
    }
}

// Convert a derivation path to its apdu data format
pub(crate) fn derivation_path_to_apdu_data(deriv: &DerivationPath) -> APDUData {
    let mut buf = vec![deriv.len() as u8];
    for idx in deriv.iter() {
        buf.extend(&idx.to_be_bytes());
    }
    APDUData::from(buf)
}

pub(crate) fn untrusted_hash_tx_input_start(chunk: &[u8], first: bool) -> APDUCommand {
    APDUCommand {
        ins: Commands::UntrustedHashTxInputStart as u8,
        p1: if first { 0x00 } else { 0x80 },
        p2: 0x02,
        data: APDUData::from(chunk),
        response_len: Some(64),
    }
}

pub(crate) fn untrusted_hash_tx_input_finalize(chunk: &[u8], last: bool) -> APDUCommand {
    APDUCommand {
        ins: Commands::UntrustedHashTxInputFinalizeFull as u8,
        p1: if last { 0x80 } else { 0x00 },
        p2: 0x00,
        data: APDUData::from(chunk),
        response_len: Some(64),
    }
}

pub(crate) fn untrusted_hash_sign(chunk: &[u8]) -> APDUCommand {
    APDUCommand {
        ins: Commands::UntrustedHashSign as u8,
        p1: 0x00,
        p2: 0x00,
        data: APDUData::from(chunk),
        response_len: Some(64),
    }
}

pub(crate) fn packetize_version_and_vin_length(version: u32, vin_len: u64) -> APDUCommand {
    let mut chunk = vec![];
    chunk.extend(&version.to_le_bytes());
    ser::write_compact_int(&mut chunk, vin_len).unwrap();
    untrusted_hash_tx_input_start(&chunk, true)
}

pub(crate) fn packetize_input(utxo: &Utxo, txin: &BitcoinTxIn) -> Vec<APDUCommand> {
    let mut buf = vec![0x02];
    txin.outpoint.write_to(&mut buf).unwrap();
    buf.extend(&utxo.value.to_le_bytes());
    buf.push(0x00);

    let first = untrusted_hash_tx_input_start(&buf, false);
    let second = untrusted_hash_tx_input_start(&txin.sequence.to_le_bytes(), false);

    vec![first, second]
}

pub(crate) fn packetize_input_for_signing(utxo: &Utxo, txin: &BitcoinTxIn) -> Vec<APDUCommand> {
    let mut buf = vec![0x02];
    txin.outpoint.write_to(&mut buf).unwrap();
    buf.extend(&utxo.value.to_le_bytes());
    buf.extend(utxo.signing_script().unwrap()); // should have been preflighted by `should_sign`

    buf.chunks(50)
        .map(|d| untrusted_hash_tx_input_start(d, false))
        .collect()
}

pub(crate) fn packetize_vout(outputs: &[TxOut]) -> Vec<APDUCommand> {
    let mut buf = vec![];
    ser::write_compact_int(&mut buf, outputs.len() as u64).unwrap();
    for output in outputs.iter() {
        output.write_to(&mut buf).unwrap();
    }

    let mut packets = vec![];
    // The last chunk will
    let mut chunks = buf.chunks(50).peekable();
    while let Some(chunk) = chunks.next() {
        packets.push(untrusted_hash_tx_input_finalize(
            chunk,
            chunks.peek().is_none(),
        ))
    }
    packets
}

pub(crate) fn transaction_final_packet(lock_time: u32, path: &DerivationPath) -> APDUCommand {
    let mut buf = vec![];
    buf.extend(derivation_path_to_apdu_data(path).data());
    buf.push(0x00); // deprecated
    buf.extend(&lock_time.to_le_bytes());
    buf.push(0x01); // SIGHASH_ALL
    untrusted_hash_sign(&buf)
}

// This is ugly.
pub(crate) fn modify_tx_start_packet(command: &APDUCommand) -> APDUCommand {
    let mut c = command.clone();

    let mut new_data = c.data.clone().data();
    new_data.resize(5, 0);
    new_data[4] = 0x01; // overwrite vin length

    c.p1 = 0x00;
    c.p2 = 0x80;
    c.data = new_data.into();
    c
}

pub(crate) fn parse_sig(answer: &APDUAnswer) -> Result<Signature, LedgerBTCError> {
    let mut sig = answer
        .data()
        .ok_or(LedgerBTCError::UnexpectedNullResponse)?
        .to_vec();
    sig[0] &= 0xfe;
    Ok(Signature::from_der(&sig[..sig.len() - 1]).map_err(Bip32Error::from)?)
}

pub(crate) fn should_sign(xpub: &DerivedXPub, signing_info: &[crate::app::SigningInfo]) -> bool {
    signing_info
        .iter()
        .filter(|s| s.deriv.is_some()) // filter no derivation
        .filter(|s| match s.prevout.script_pubkey.standard_type() {
            // filter SH types without spend scripts
            ScriptType::Sh(_) | ScriptType::Wsh(_) => {
                s.prevout.spend_script() != &SpendScript::Missing
            }
            _ => true,
        })
        .any(|s| {
            xpub.derivation()
                .is_possible_ancestor_of(s.deriv.as_ref().unwrap())
        })
}
