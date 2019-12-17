```
git clone --depth 1 https://github.com/libtom/libtomcrypt
cd libtomcrypt
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBTOMCRYPT"
export LIBTOMCRYPT_INCLUDE_PATH=$(realpath src/headers/)
export LIBTOMCRYPT_A_PATH=$(realpath libtomcrypt.a)
```
