```
git clone https://github.com/libecc/libecc.git
cd libecc/
git checkout cryptofuzz
export CFLAGS="$CFLAGS -DUSE_CRYPTOFUZZ"
make -j$(nproc) build/libsign.a
export LIBECC_PATH=$(realpath .)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBECC"
cd ../
```
