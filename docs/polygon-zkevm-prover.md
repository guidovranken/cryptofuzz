```sh
git clone --depth 1 https://github.com/0xPolygonHermez/zkevm-prover
export ZKEVM_PROVER_PATH=$(realpath zkevm-prover/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_POLYGON_ZKEVM_PROVER"
export LINK_FLAGS="$LINK_FLAGS -lgmp"
```

