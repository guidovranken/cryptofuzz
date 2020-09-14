# sjcl.js

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/bitwiseshiftleft/sjcl.git
export SJCL_PATH=$(realpath sjcl/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SJCL"
```

## Module compilation

```sh
cd cryptofuzz/modules/sjcl/
make
```
