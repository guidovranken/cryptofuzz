# crypto-js

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/brix/crypto-js.git
export CRYPTO_JS_PATH=$(realpath crypto-js/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTO_JS"
```

## Module compilation

```sh
cd cryptofuzz/modules/crypto-js/
make
```
