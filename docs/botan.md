# Botan

## Library compilation

```sh
git clone --depth 1 https://github.com/randombit/botan.git
cd botan/
./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" --disable-shared --disable-modules=locking_allocator
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOTAN"
export LIBBOTAN_A_PATH=`realpath libbotan-2.a`
export BOTAN_INCLUDE_PATH=`realpath build/include`
```

## Module compilation

```sh
cd cryptofuzz/modules/botan/
make
```
