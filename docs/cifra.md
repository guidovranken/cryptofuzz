```
git clone --depth 1 https://github.com/ctz/cifra.git
cd cifra/src/
make -j$(nproc)
cd ../../
export CIFRA_PATH=$(realpath cifra/src/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CIFRA"
```
