```
git clone --depth 1 git://git.gnupg.org/libgcrypt.git
cd libgcrypt/
autoreconf -ivf
./configure --enable-static --disable-doc
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBGCRYPT"
export LIBGCRYPT_A_PATH=$(realpath src/.libs/libgcrypt.a)
export LIBGCRYPT_INCLUDE_PATH=$(realpath src/)
export LINK_FLAGS="$LINK_FLAGS -lgpg-error"
```
