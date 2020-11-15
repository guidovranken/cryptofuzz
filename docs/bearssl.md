```
git clone --depth 1 https://www.bearssl.org/git/BearSSL
export BEARSSL_INCLUDE_PATH=$(realpath inc/)
export LIBBEARSSL_A_PATH=$(realpath ./build/libbearssl.a)
export CXXFLAGS=$CXXFLAGS -DCRYPTOFUZZ_BEARSSL"
```
