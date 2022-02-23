# Get Zig compiler

```
wget 'https://ziglang.org/builds/zig-linux-x86_64-0.10.0-dev.934+acec06cfa.tar.xz'
tar Jxf zig-linux-x86_64-0.10.0-dev.934+acec06cfa.tar.xz
export ZIG_BIN=$(realpath zig-linux-x86_64-0.10.0-dev.934+acec06cfa/zig)
```

## Module compilation

```sh
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_ZIG"
cd cryptofuzz/modules/zig/
make
```
