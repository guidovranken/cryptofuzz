# Get Zig compiler

```
wget $(curl https://ziglang.org/download/index.json | jq -r '.master."x86_64-linux".tarball') -O zig-latest.tar.xz
tar Jxf zig-latest.tar.xz
export ZIG_BIN=$(realpath zig-linux-x86_64*/zig)
```

## Module compilation

```sh
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_ZIG"
cd cryptofuzz/modules/zig/
make
```
