```
git clone --depth 1 https://github.com/ridiculousfish/libdivide.git
export LIBDIVIDE_PATH=$(realpath libdivide)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBDIVIDE"
```
