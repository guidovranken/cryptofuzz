```
git clone --depth 1 https://www.bearssl.org/git/BearSSL
cd BearSSL/
sed -i '/^CC = /d' conf/Unix.mk
sed -i '/^CFLAGS = /d' conf/Unix.mk
make -j$(nproc) lib
export BEARSSL_INCLUDE_PATH=$(realpath inc/)
export LIBBEARSSL_A_PATH=$(realpath ./build/libbearssl.a)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BEARSSL"
```
