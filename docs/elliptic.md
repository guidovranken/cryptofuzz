```
git clone --depth 1 https://github.com/indutny/elliptic.git
export ELLIPTIC_JS_PATH=$(realpath elliptic/dist/elliptic.min.js)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_ELLIPTIC"
```
