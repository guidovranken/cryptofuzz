```
git clone --depth 1 https://github.com/relic-toolkit/relic.git
cd relic/
mkdir build/
cd build/
cmake .. -DCOMP="$CFLAGS" -DQUIET=on -DRAND=CALL -DSHLIB=off -DSTBIN=off -DTESTS=0 -DBENCH=0 -DALLOC=DYNAMIC
make -j$(nproc)
cd ../..
export RELIC_PATH=$(realpath relic)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_RELIC"
```
