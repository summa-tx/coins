# bitcoins-wasm

This crate generates wrappers suitable for use with wasm-bindgen around the
`bitcoins` crate. The wrappers implement passthrough methods for most
functionality, and the resulting wasm libraries can be run in a browser and in
node.js.

This crate is under active development, and the API may change.

The interface aims to be as faithful to `bitcoins` as possible, however
a few compromises have been made.

- Crossing the WASM/JS barrier has generally been implemented as `clone()`.
  This prevents unsafe use of the WASM memory. This means that most structs are
  de facto passed by value.
  - example: `vin.push(txin)` clones the txin. Further modifications to `txin`
    will not be propagated to the clone in the `Vin`.
  - example: `let txin = vin.get(0)` will clone the txin before returning it.
    Modifying that `txin`  will not modify the original copy in the vin.
    Instead you must make the modifications, and then call `vin.set(0, txin)`.
- `Script`, `ScriptPubkey`, and `ScriptSig` are represented as `Uint8Array`s
  until we get around to implementing a wrapper type.
- `wasm-bindgen` does not seem to support indexing getters and setters on rust
  objects, so `.get()` and `.set()` methods have been provided
- We have not yet implemented iterator support.


## Interface

You should use the standard network interface:

```js
const btc = require('@summa-tx/bitcoins');

const addr = "bc1q....";

let tx = btc.BitcoinMainnet.tx_builder()
    .version(2)
    .spend(btc.BitcoinOutpoint.null(), 0xfffffffd)
    .pay(3000000n, addr)
    .locktime(0x87878787)
    .build();
```

## Building
- `cargo build`
- install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- `wasm-pack build`
  - specify `--target nodejs` for use in node.
- build the docs: `$ cargo rustdoc`

## Building for release
- `wasm-pack build`
- edit `package.json`
  - bump the version
  - `"name": "@summa-tx/bitcoins",`
  - add `"bitcoins_bg.js",` to the files list
