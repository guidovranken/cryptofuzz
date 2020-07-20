# wolfCrypt

## Library compilation

```sh
git clone --depth 1 https://github.com/libtom/libtommath.git
cd libtommath/
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBTOMMATH"
export LIBTOMMATH_A_PATH=$(realpath libtommath.a)
export LIBTOMMATH_INCLUDE_PATH=$(realpath .)
```
