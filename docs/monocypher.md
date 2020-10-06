# Monocypher

## Library compilation

```sh
git clone --depth 1 https://github.com/LoupVaillant/Monocypher.git
cd Monocypher/
make CC="$CC" CFLAGS="$CFLAGS"
export LIBMONOCYPHER_A_PATH=$(realpath lib/libmonocypher.a)
export MONOCYPHER_INCLUDE_PATH=$(realpath src/)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MONOCYPHER"
cd ../
```
## Module compilation

```sh
cd cryptofuzz/modules/monocypher/
make
```

