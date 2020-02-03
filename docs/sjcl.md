# Stanford JavaScript Crypto Library (sjcl)

## Library compilation

```sh
git clone --depth 1 https://github.com/bitwiseshiftleft/sjcl.git
cd sjcl/
./configure --with-sha1 --with-sha512 --with-ripemd160 --with-bn --with-scrypt --with-ecc --with-ctr --with-cbc
make
export SJCL_PATH=$(realpath .)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SJCL"
```

TODO libfuzzer-js

## Module compilation

```sh
cd cryptofuzz/modules/sjcl/
make
```
