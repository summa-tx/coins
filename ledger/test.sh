#!/bin/sh

wasm-pack build --scope summa-tx --target nodejs -- --features=node --no-default-features && \
cd node_tests && \
rm -rf ./rmn_ledger && \
cp -r ../pkg ./rmn_ledger && \
npm i ./rmn_ledger && \
npm run test
