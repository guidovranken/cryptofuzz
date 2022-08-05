```sh
git clone --depth 1 https://github.com/ckormanyos/wide-integer.git
export WIDE_INTEGER_PATH=$(realpath wide-integer)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WIDE_INTEGER"
```
