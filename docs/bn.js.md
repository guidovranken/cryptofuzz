# bn.js

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/indutny/bn.js.git
export BN_JS_PATH=$(realpath bn.js/lib/bn.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BN_JS"
```

## Module compilation

```sh
cd cryptofuzz/modules/bn.js/
make
```
