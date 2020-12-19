# trezor-firmware

## Library compilation

```sh
git clone --depth 1 https://github.com/trezor/trezor-firmware.git
cd trezor-firmware/crypto/
# Rename blake2b_* functions to avoid symbol collisions with other libraries
sed -i "s/\<blake2b_\([A-Za-z_]\)/trezor_blake2b_\1/g" *.c *.h
sed -i 's/\<blake2b(/trezor_blake2b(/g' *.c *.h
cd ../../
export TREZOR_FIRMWARE_PATH=$(realpath trezor-firmware)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_TREZOR_FIRMWARE"
```
