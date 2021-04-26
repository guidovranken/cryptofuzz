```
git clone --depth 1 https://github.com/supranational/blst
cd blst/
./build.sh
export BLST_LIBBLST_A_PATH=$(realpath libblst.a)
export BLST_INCLUDE_PATH=$(realpath bindings/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BLST"
```
