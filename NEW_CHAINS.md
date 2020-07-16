## Implementing a new chain

This is a high-level guide to implementing a library for a new chain.

### Implementing Inputs
An input consumes some TXO referenced by its ID.

1. Select or create a struct to be your `TXOIdentifier`
  1. This is the unique in-protocol identifier for a TXO.
  1. In Bitcoin this is `bitcoins::types::txin::BitcoinOutpoint`.
  1. Add the marker trait: `impl riemann_core::types::tx::TXOIdentifier`
1. Implement a type to be your `Input`
  1. This represents the input TXOs consumed by a transaction.
  1. This could be the same as `TXOIdentifier`, depending on your protocol.
  1. In Bitcoin this is `bitcoins::types::txin::BitcoinInput`.
  1. Add the marker trait: `impl riemann_core::types::tx::Input`
  1. Associate your `TXOIdentifier` type

### Implementing Outputs
An output creates a new TXO with some value owned by some payee.

1. Select or create a struct to be your `RecipientIdentifier`
  1. This is used to identify payees in-protocol.
  1. In Bitcoin this is `bitcoins::types::script::ScriptPubkey`
  1. `impl riemann_core::types::tx::RecipientIdentifier` on your struct
1. Select or create a type to be your `Value`
  1. This type represents how the in-protocol value of a TXO.
  1. In Bitcoin this is `u64`.
  1. In Ethereum-based TXO chains this is often a `U256` struct.
  1. `impl riemann_core::types::tx::Value` on your struct.
1. Implement a type to be your `Output`
  1. This represents the output TXOs created by a transaction.
  1. In Bitcoin this is `bitcoins::types::txout::BitcoinInput`.
  1. Add the trait: `impl riemann_core::types::tx::Output`
  1. Associate your `Value` and `RecipientIdentifier` types.

### Implementing Transactions
A transaction is a list of inputs and outputs. It provides methods to access
its properties, as well as calculate its signature hash.

1. Define the hash function used by your TX:
  1. We do this so that your TX can use arbitray hashes, while keeping
    type safety.
  1. Define a `Digest` type that represents the output of your hash functions.
    1. Bitcoin uses `[u8; 32]`
  1. Define a `MarkedDigest` type (see `riemann_core::hashes::marked`) for your
    TXIDs.
  1. Define a `MarkedDigestWriter` type that can output `Digest` and
    `MarkedDigest` types.
    1. This must implement `std::io::Write`.
    1. Bitcoin uses `riemann_core::hashes::hash256::Hash256Writer`
1. Define an `Error` type to handle your errors.
  1. This should contain any errors that can occur while interacting with your
    transaction.
  1. See `bitcoins::types::transactions::TxError` for an example.
1. Define a `SighashArgs` type for your transaction.
  1. This struct should carry all the information needed to calculate the hash
    of your transaction that is signed.
1. Define a `Transaction` struct.
1. `impl riemann_core::ser::Ser` on your `Transaction`.
  1. If necessary, create a new `Error` type (see an example in
      `bitcoin/types/transaction.rs`)
  1. This ensures that your tx can be serialized easily.
  1. It is used in the default txid implementation.
1. `impl riemann_core::types::tx::Transaction` on your `Transaction`
  1. Associate your `Error`, `Digest`, `HashWriter`, `TXID`, `SighashArgs`,
   `Input`, and `Output` types.
  1. This is a simple interface for accessing inputs, outputs, and other tx
    info.
  1. If your transaction type does not have a version or a locktime, you may
    implement these as NOPs.

### Implementing the Encoder

An `AddressEncoder` tranlates between protocol-facing, and human-facing
datastructures. Typically this means managing the relationship between
addresses and their in-protocol counterparts.

1. Define an `Error` type. It's fine to reuse a previouse `Error` here.
1. Create a type to be your `Address`
  1. This represents the human-facing payee, and can be translated to a
    `RecipientIdentifier`
  1. In Bitcoin this is an enum wrapper around a `String`.
1. Create a type to be your `Encoder`
1. `impl riemann_core::enc::AddressEncoder` on your `Encoder`
  1. `encode_address` transforms a `RecipientIdentifier` to an `Address`.
  1. `decode_address` transforms an `Address` to a `RecipientIdentifier`.
  1. `string_to_address` transforms a `&str` to an `Address`
  1. Associate your `Address`, `RecipientIdentifier`, and `EncoderError` types.

### Implementing a Builder
1. Create a struct to be your `Builder`.
1. `impl riemann_core::builder::TxBuilder` for your `Builder` type
  1. Associate your `Transaction` and `AddressEncoder` from previous steps.
  1. Feel free to leave `version` and `locktime` as NOPs if unsupported by your
    protocol.

### Implementing a Network

The `Network` ensures type consistency across all previous types. For example,
it guarantees that your `Encoder`, `Builder`, and `TxOut` use the same
`RecipientIdentifier`.

1. Define a new `Error` type. It's fine to reuse a previous `Error` here.
1. Define a `Network` type.
1. `impl riemann_core::nets::Network` on your `Network`.
  1. Associate your `Error` type.
  1. Associate your `TxIn`, `TxOut`, and `Transaction` types from previous steps.
  1. Associate your `Address`, `RecipientIdentifier`, and `AddressEncoder`
    types.
  1. Associate your `Builder` type.
