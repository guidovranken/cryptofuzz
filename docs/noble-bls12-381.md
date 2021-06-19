# noble-bls12-381

## Library compilation

Run the steps for building [libfuzzer-js](libfuzzer-js.md) first.

```sh
git clone --depth 1 https://github.com/paulmillr/noble-bls12-381.git
cd noble-bls12-381/
cp math.ts new_index.ts 
$(awk '/^export/ {print "tail -n +"FNR+1" index.ts"; exit}' index.ts) >>new_index.ts
mv new_index.ts index.ts
npm install && npm run build
export NOBLE_BLS12_381_PATH=$(realpath index.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NOBLE_BLS12_381"
cd ../
```

## Module compilation

```sh
cd cryptofuzz/modules/noble-bls12-381/
make
```
