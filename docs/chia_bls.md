```
git clone --depth 1 https://github.com/Chia-Network/bls-signatures.git
cd bls-signatures/
mkdir build/
cd build/
cmake .. -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0
make -j$(nproc)
export CHIA_BLS_LIBBLS_A_PATH=$(realpath src/libbls.a)
export CHIA_BLS_LIBRELIC_S_A_PATH=$(realpath _deps/relic-build/lib/librelic_s.a)
export CHIA_BLS_LIBSODIUM_A_PATH=$(realpath _deps/sodium-build/libsodium.a)
export CHIA_BLS_INCLUDE_PATH=$(realpath ../src/)
export CHIA_BLS_RELIC_INCLUDE_PATH_1=$(realpath _deps/relic-build/include/)
export CHIA_BLS_RELIC_INCLUDE_PATH_2=$(realpath _deps/relic-src/include/)
cd ../../
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CHIA_BLS"
export LINK_FLAGS="-lgmp"
```
