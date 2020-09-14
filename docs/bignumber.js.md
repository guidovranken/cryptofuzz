# bignumber.js

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/MikeMcl/bignumber.js.git
export BIGNUMBER_JS_PATH=$(realpath bignumber.js/bignumber.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BIGNUMBER_JS"
```

## Module compilation

```sh
cd cryptofuzz/modules/bignumber.js/
make
```
