```
git clone --depth 1 https://github.com/kmackay/micro-ecc.git
export MICRO_ECC_PATH=$(realpath micro-ecc/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MICRO_ECC"
```
