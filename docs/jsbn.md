# bn.js

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/andyperlitch/jsbn.git
export JSBN_PATH=$(realpath jsbn/index.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_JSBN"
```

## Module compilation

```sh
cd cryptofuzz/modules/jsbn/
make
```
