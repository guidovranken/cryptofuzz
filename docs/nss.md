# NSS

## Library compilation

```sh
mkdir sandbox && cd sandbox/
hg clone https://hg.mozilla.org/projects/nspr
hg clone https://hg.mozilla.org/projects/nss
cd nss

# FIXUP fuzz.gyp to remove reference to unavailable FuzzingEngine.
sed '/-lFuzzingEngine/d' fuzz/fuzz.gyp -i

export LDFLAGS="-Wl,--unresolved-symbols=ignore-all"

# Note that build.sh might fail because it tries to build additional
# utilities that aren't compatible with fuzzing.
./build.sh --clang --enable-fips --static --asan --disable-tests --fuzz=oss

# Optional, to ensure that the required modules were built
ninja -C out/Debug nss_static_libs nss_static

export CXXFLAGS="$CXXFLAGS -I $NSS_NSPR_PATH/dist/public/nss -I $NSS_NSPR_PATH/dist/Debug/include/nspr -DCRYPTOFUZZ_NSS"
export NSS_NSPR_PATH="$(realpath ..)"
```

## Module compilation

```sh
cd cryptofuzz/modules/nss/
make
```
