# Nettle

## Library compilation

```
git clone --depth 1 https://git.lysator.liu.se/nettle/nettle
mkdir nettle-install/
cd nettle/
bash .bootstrap
./configure --disable-documentation --disable-openssl --prefix=`realpath ../nettle-install`
make -j$(nproc)
make install
export LIBNETTLE_A_PATH=`realpath ../nettle-install/lib/libnettle.a`
export NETTLE_INCLUDE_PATH=`realpath ../nettle-install/include`
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NETTLE"
```

## Module compilation

```sh
cd cryptofuzz/modules/nettle/
make
```
