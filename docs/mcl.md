```
git clone --depth 1 https://github.com/herumi/mcl.git
cd mcl/
make bint_header
mkdir build/
cd build/
cmake .. -DMCL_STATIC_LIB=on
make -j$(nproc)
export MCL_INCLUDE_PATH=$(realpath ../include/)
export MCL_LIBMCL_A_PATH=$(realpath lib/libmcl.a)
export MCL_LIBMCLBN384_A_PATH=$(realpath lib/libmclbn384.a)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MCL"
export LINK_FLAGS="$LINK_FLAGS -lgmp"
```
