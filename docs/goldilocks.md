```sh
git clone --depth 1 https://github.com/0xPolygonHermez/goldilocks
export GOLDILOCKS_PATH=$(realpath goldilocks/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_GOLDILOCKS"
export LINK_FLAGS="$LINK_FLAGS -lgmp"
```

