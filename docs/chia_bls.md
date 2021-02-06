```
git clone --depth 1 https://github.com/Chia-Network/bls-signatures.git
cd bls-signatures/
mkdir build/
cd build/
cmake ..
make -j$(nproc) bls/
export CHIA_BLS_LIBBLS_A_PATH=$(realpath libbls.a)
export CHIA_BLS_INCLUDE_PATH=$(realpath ../src/)
export CHIA_BLS_RELIC_INCLUDE_PATH_1=$(realpath _deps/relic-build/include/)
export CHIA_BLS_RELIC_INCLUDE_PATH_2=$(realpath _deps/relic-src/include/)
cd ../../
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CHIA_BLS"
```
