```
git clone --depth 1 https://github.com/jedisct1/libsodium.git
cd libsodium/
autoreconf -ivf
./configure
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBSODIUM"
export LIBSODIUM_A_PATH=$(realpath src/libsodium/.libs/libsodium.a)
export LIBSODIUM_INCLUDE_PATH=$(realpath src/libsodium/include)
```
