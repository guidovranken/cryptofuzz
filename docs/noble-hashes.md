# noble-hashes

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/paulmillr/noble-hashes.git
cd noble-hashes/
npm install && npm run build-release
export NOBLE_HASHES_PATH=$(realpath build/noble-hashes.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NOBLE_HASHES"
cd ../
```

## Module compilation

```sh
cd cryptofuzz/modules/noble-hashes/
make
```
