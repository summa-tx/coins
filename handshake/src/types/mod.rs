//! Holds Handshake specific types, witnesses, inputs, outputs, and transactions.

//pub mod transactions;
/// TODO:
pub mod txin;
pub mod txout;
pub mod lockingscript;
pub mod covenant;
//pub mod txout;
// pub mod utxo;

// pub use transactions::*;
pub use txin::*;
pub use txout::*;
pub use lockingscript::*;
pub use covenant::*;
// pub use utxo::*;

