```
git clone --depth 1 https://github.com/ANSSI-FR/libecc.git
cd libecc/
make -j$(nproc)
export LIBECC_PATH=$(realpath .)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBECC"
cd ../
```
