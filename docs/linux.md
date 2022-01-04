```
git clone --depth 1 https://github.com/smuellerDD/libkcapi.git
cd libkcapi/
autoreconf -ivf
./configure
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LINUX"
export LIBKCAPI_A_PATH=$(realpath .libs/libkcapi.a)
export LIBKCAPI_INCLUDE_PATH=$(realpath lib/)
```
