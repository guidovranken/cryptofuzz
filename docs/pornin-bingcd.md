```sh
git clone --depth 1 https://github.com/pornin/bingcd.git
export BINGCD_PATH=$(realpath bingcd)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_PORNIN_BINGCD"
```
