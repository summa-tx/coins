use futures::lock::Mutex;
use riemann_core::{
    tx::Transaction,
};
use rmn_bip32::{
    derived::DerivedXPub,
    model::HasPubkey,
    path::{DerivationPath, KeyDerivation},
    primitives::XKeyInfo,
};
use rmn_btc::types::{BitcoinTxIn, WitnessTx, UTXO};
use rmn_ledger::{
    common::{APDUAnswer, APDUCommand},
    transports::{Ledger, LedgerAsync},
};
use crate::{LedgerBTCError, utils::*};

/// Info required to sign an input on the ledger, including the KeyDerivation and the prevout
#[derive(Clone, Debug)]
pub struct SigningInfo {
    /// The input associated
    pub input_idx: usize,
    /// A reference to a UTXO
    pub prevout: UTXO,
    /// A reference to a key derivation if this input should be signed
    pub deriv: Option<KeyDerivation>,
}


/// A Signature and the index of the input if signs.
#[derive(Clone, Debug)]
pub struct SigInfo {
    /// the input of the signed index
    pub input_idx: usize,
    /// The signature
    pub sig: rmn_bip32::Signature,
    /// The derivation of the key that signed it
    pub deriv: KeyDerivation,
}

/// A Ledger BTC App.
///
/// This is a simple wrapper around the transport and a Secp256k1 backend
pub struct LedgerBTC {
    transport: Mutex<Ledger>,
}

// Lifecycle
impl LedgerBTC {
    /// Instantiate the application by acquiring a lock on the ledger device.
    ///
    /// # Notes
    ///
    /// - XPub lifetimes are bound to the lifetime of the backend. They can outlive the app,
    /// but not the backend
    pub async fn init() -> Result<LedgerBTC, LedgerBTCError> {
        Ok(LedgerBTC {
            transport: Mutex::new(Ledger::init().await?),
        })
    }

    /// Consume self and drop the ledger mutex
    pub fn close(self) {}
}

// XPubs
impl LedgerBTC {
    /// Get information about the public key at a certain derivation
    async fn get_key_info(
        &self,
        transport: &Ledger,
        deriv: &DerivationPath,
    ) -> Result<InternalKeyInfo, LedgerBTCError> {
        // Convert to APDU derivation format
        if deriv.len() > 10 {
            return Err(LedgerBTCError::DerivationTooLong);
        }

        let data = derivation_path_to_apdu_data(deriv);
        let command = APDUCommand {
            ins: Commands::GET_WALLET_PUBLIC_KEY as u8,
            p1: 0x00,
            p2: 0x02, // always native segwit address
            data,
            response_len: None,
        };

        let answer = transport.exchange(&command).await?;
        let data = answer
            .data()
            .ok_or(LedgerBTCError::UnexpectedNullResponse)?;

        Ok(parse_pubkey_response(deriv, &data))
    }

    /// Get an XPub with as much derivation info as possible.
    pub async fn get_xpub(
        &self,
        deriv: &DerivationPath,
    ) -> Result<DerivedXPub, LedgerBTCError> {
        let transport = self.transport.lock().await;

        let child = self.get_key_info(&transport, deriv).await?;

        if !deriv.is_empty() {
            let parent = self
                .get_key_info(&transport, &deriv.resized(deriv.len() - 1, 0))
                .await?;
            let master = self.get_key_info(&transport, &deriv.resized(0, 0)).await?;
            Ok(DerivedXPub {
                derivation: KeyDerivation {
                    root: master.pubkey.fingerprint(),
                    path: deriv.clone(),
                },
                xpub: rmn_bip32::XPub {
                    pubkey: child.pubkey,
                    info: XKeyInfo {
                        depth: deriv.len() as u8,
                        parent: parent.pubkey.fingerprint(),
                        index: *deriv.last().unwrap(),
                        chain_code: child.chain_code,
                        hint: rmn_bip32::primitives::Hint::SegWit,
                    },
                },
            })
        } else {
            Ok(DerivedXPub {
                derivation: KeyDerivation {
                    root: child.pubkey.fingerprint(),
                    path: child.path,
                },
                xpub: rmn_bip32::XPub {
                    pubkey: child.pubkey,
                    info: XKeyInfo {
                        depth: 0,
                        parent: rmn_bip32::primitives::KeyFingerprint([0u8; 4]),
                        index: 0,
                        chain_code: child.chain_code,
                        hint: rmn_bip32::primitives::Hint::SegWit,
                    },
                },
            })
        }
    }

    /// Get the master xpub
    pub async fn get_master_xpub<'a>(&self) -> Result<DerivedXPub, LedgerBTCError> {
        Ok(self.get_xpub(&Default::default()).await?)
    }
}

// Signing
impl LedgerBTC {
    // Exchange packets to get a signature response from the device.
    async fn signature_exchange(
        &self,
        transport: &Ledger,
        first_packet: &APDUCommand,
        locktime: u32,
        utxo: &UTXO,
        txin: &BitcoinTxIn,
        deriv: &DerivationPath,
    ) -> Result<APDUAnswer, LedgerBTCError> {
        let mut packets = vec![modify_tx_start_packet(first_packet)];
        packets.extend(packetize_input_for_signing(utxo, txin));
        for packet in packets.iter() {
            transport.exchange(&packet).await?;
        }
        let last_packet = transaction_final_packet(locktime, deriv);
        Ok(transport.exchange(&last_packet).await?)
    }

    // Perform the sig exchange and parse the result
    async fn get_sig(
        &self,
        transport: &Ledger,
        first_packet: &APDUCommand,
        locktime: u32,
        utxo: &UTXO,
        txin: &BitcoinTxIn,
        deriv: &DerivationPath,
    ) -> Result<rmn_bip32::Signature, LedgerBTCError> {
        parse_sig(
            &self
                .signature_exchange(transport, first_packet, locktime, utxo, txin, deriv)
                .await?,
        )
    }

    /// Get signatures for as many txins as possible.
    pub async fn get_tx_signatures(
        &self,
        tx: &WitnessTx,
        signing_info: &[SigningInfo],
    ) -> Result<Vec<SigInfo>, LedgerBTCError> {
        if signing_info.len() != tx.inputs().len() {
            return Err(LedgerBTCError::SigningInfoLengthMismatch);
        }

        // TODO refactor to use idx in signing info

        // get the master key and check at least 1 is signable
        let master = self.get_xpub(&Default::default()).await?;

        // If we have no keys, don't sign anything
        if !should_sign(&master, signing_info) {
            return Ok(vec![]);
        }

        // Lock the transport and start making packets for exchange
        let transport = self.transport.lock().await;
        let first_packet =
            packetize_version_and_vin_length(tx.version(), tx.inputs().len() as u64);
        let mut packets = vec![first_packet.clone()];

        // Packetize each inputs
        packets.extend(
            signing_info
                .iter()
                .map(|s| &s.prevout)
                .zip(tx.inputs())
                .map(|(u, i)| packetize_input(&u, i))
                .flatten()
                .collect::<Vec<_>>(),
        );

        // Packetize all outputs
        packets.extend(packetize_vout(tx.outputs()));
        // Exchange all packets
        for packet in packets.iter() {
            transport.exchange(&packet).await?;
        }

        let mut sigs = vec![];

        // For each input that we can sign, we call `get_sig`
        for (i, info) in signing_info.iter().enumerate() {
            if let Some(deriv) = &info.deriv {
                let sig = self.get_sig(
                    &transport,
                    &first_packet,
                    tx.locktime(),
                    &info.prevout,
                    &tx.inputs()[i],
                    &deriv.path,
                ).await?;
                sigs.push(SigInfo{ input_idx: info.input_idx, sig, deriv: deriv.clone()});
            }
        }
        Ok(sigs)
    }
}
