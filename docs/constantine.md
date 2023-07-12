```
git clone --depth 1 https://github.com/mratsim/constantine
export CONSTANTINE_PATH=$(realpath constantine)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CONSTANTINE"
```
