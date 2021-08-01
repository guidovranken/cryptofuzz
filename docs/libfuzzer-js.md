# Building libfuzer-js

This is required for fuzzing JavaScript libraries.

```
export LIBFUZZER_A_PATH="-fsanitize=fuzzer"
git clone --depth 1 https://github.com/guidovranken/libfuzzer-js.git
cd libfuzzer-js/
make
export LIBFUZZER_JS_PATH=$(realpath .)
export LINK_FLAGS="$LINK_FLAGS $LIBFUZZER_JS_PATH/js.o $LIBFUZZER_JS_PATH/quickjs/libquickjs.a"
cd ../
```
