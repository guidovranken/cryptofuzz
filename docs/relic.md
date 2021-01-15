```
git clone --depth 1 https://github.com/relic-toolkit/relic.git
cd relic/
mkdir build/
cd build/
cmake ..
make -j$(nproc)
cd ../..
export RELIC_PATH=$(realpath relic)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_RELIC"
```
