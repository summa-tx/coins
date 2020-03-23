# Builder Interface Notes

Great:
```rust
let prevout: Prevout;
let tx_ins: Vec<TxIn>;
let tx_outs = Vec<TxOut>;

let builder = Network::new_transaction_builder();

let tx: WitnessTx = builder
  .version(2)
  .spend(prevout, sequence)
  .extend_inputs(tx_ins)
  .pay(value, address)
  .pay(value, output_script)
  .extend_outputs(tx_outs)
  .witness(0, witness)         /// Should always output WitnessTx
  .locktime(5801238)
  .build();

let builder = Network::new_transaction_builder();
let legacy: LegacyTx = builder
  .from("HEX_ENCODED_TX")
  .spend(prevout, sequence)
  .build();

let builder = Network::new_transaction_builder();
let another: WitnessTx = builder
  .from(legacy)
  .build();
```
