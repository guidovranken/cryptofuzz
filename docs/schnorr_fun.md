# Rust libsecp256k1

# x64

```sh
cd cryptofuzz/modules/schnorr_fun/
make
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SCHNORR_FUN"
```

# i386

```sh
cd cryptofuzz/modules/schnorr_fun/
make -f Makefile.i386
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SCHNORR_FUN"
```
