# noble-secp256k1

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/paulmillr/noble-secp256k1.git
export NOBLE_SECP256K1_PATH=$(realpath noble-secp256k1/index.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NOBLE_SECP256K1"
```

## Module compilation

```sh
cd cryptofuzz/modules/noble-secp256k1/
make
```
