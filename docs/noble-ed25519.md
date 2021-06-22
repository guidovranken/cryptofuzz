# noble-ed25519

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/paulmillr/noble-ed25519.git
export NOBLE_ED25519_PATH=$(realpath noble-ed25519/index.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NOBLE_ED25519"
```

## Module compilation

```sh
cd cryptofuzz/modules/noble-ed25519/
make
```
