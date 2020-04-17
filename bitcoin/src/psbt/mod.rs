//! Partially Signed Bitcoin transactions (bip174)

/// Common data structures
pub mod common;
/// Global KV store
pub mod global;
/// Per-Input KV store
pub mod input;
/// Per-Output KV store
pub mod outputs;

pub use common::*;
pub use global::*;
pub use input::*;
pub use outputs::*;

use std::io::{Read, Write};

use riemann_core::{
    ser::{Ser},
    tx::{Transaction},
};

trait PST {
    /// A 4-byte prefix used to identify partially signed transactions. May vary by network.
    const MAGIC_BYTES: [u8; 4];
}

/// A BIP174 Partially Signed Bitcoin Transaction
#[derive(Debug, Clone)]
pub struct PSBT {
    global: PSBTGlobal,
    inputs: Vec<PSBTInput>,
    outputs: Vec<PSBTOutput>,
}

impl PST for PSBT {
    const MAGIC_BYTES: [u8; 4] = *b"psbt";
}

impl Ser for PSBT {
    type Error = PSBTError;

    fn to_json(&self) -> String {
        unimplemented!("TODO")
    }

    fn serialized_length(&self) -> usize {
        let mut length: usize = 5;
        length += self.global.serialized_length();
        length += self.inputs.iter().map(|i| i.serialized_length()).sum::<usize>();
        length += self.outputs.iter().map(|o| o.serialized_length()).sum::<usize>();
        length
    }

    fn deserialize<R>(reader: &mut R, _limit: usize) -> Result<Self, PSBTError>
    where
        R: Read,
        Self: std::marker::Sized
    {
        let mut prefix = [0u8; 5];
        reader.read_exact(&mut prefix)?;
        if prefix[..4] != PSBT::MAGIC_BYTES || prefix[4] != 0xff {
            return Err(PSBTError::BadPrefix);
        }

        let global = PSBTGlobal::deserialize(reader, 0)?;

        let tx = global.tx()?;

        let inputs = Vec::<PSBTInput>::deserialize(reader, tx.inputs().len())?;
        let outputs = Vec::<PSBTOutput>::deserialize(reader, tx.outputs().len())?;

        Ok(PSBT{
            global,
            inputs,
            outputs,
        })
    }

    fn serialize<W>(&self, writer: &mut W) -> Result<usize, Self::Error>
    where
        W: Write
    {
        let mut len = writer.write(&PSBT::MAGIC_BYTES)?;
        len += writer.write(&[0xffu8])?;
        len += self.global.serialize(writer)?;
        len += self.inputs.serialize(writer)?;
        len += self.outputs.serialize(writer)?;
        Ok(len)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_does_stuff() {
        let valid_cases = [
            "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000",
            "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000",
            "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000",
            "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000",
        ];
        for case in &valid_cases {
            let p = PSBT::deserialize_hex(case.to_owned().to_string()).unwrap();
            println!("{:?}", p);
        }
    }
}
