//! Holds Handshake specific types, witnesses, inputs, outputs, and transactions.

/// TODO:
pub mod txin;
pub mod txout;
pub mod lockingscript;
pub mod covenant;
pub mod tx;
// pub mod utxo;

pub use txin::*;
pub use txout::*;
pub use lockingscript::*;
pub use covenant::*;
pub use tx::*;
// pub use utxo::*;

