# libff

## Library compilation

```sh
git clone --recursive --depth 1 https://github.com/scipr-lab/libff.git
cd libff/
mkdir build/
cd build/
cmake -DCURVE=BLS12_381 ..
make -j$(nproc)
export LIBFF_A_PATH=$(realpath libff/libff.a)
export LIBFF_INCLUDE_PATH=$(realpath ..)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBFF"
export LINK_FLAGS="$LINK_FLAGS -lgmp"
cd ../../
```
