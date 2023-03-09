```sh
wget 'https://github.com/ldc-developers/ldc/releases/download/v1.31.0/ldc2-1.31.0-linux-x86_64.tar.xz'
tar Jxf ldc2-1.31.0-linux-x86_64.tar.xz
export PATH="$(realpath ldc2-1.31.0-linux-x86_64/bin/):$PATH"
export LINK_FLAGS="$LINK_FLAGS $(realpath ldc2-1.31.0-linux-x86_64/lib/libphobos2-ldc.a)"
export LINK_FLAGS="$LINK_FLAGS $(realpath ldc2-1.31.0-linux-x86_64/lib/libdruntime-ldc.a)"
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_D"
```
