```
hg clone https://gmplib.org/repo/gmp/ libgmp/
cd libgmp
autoreconf -ivf
./configure --enable-maintainer-mode
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBGMP"
export LIBGMP_INCLUDE_PATH=$(realpath .)
export LIBGMP_A_PATH=$(realpath .libs/libgmp.a)
```
