# trezor-firmware

## Library compilation

```sh
git clone --depth 1 https://github.com/trezor/trezor-firmware.git
export TREZOR_FIRMWARE_PATH=$(realpath trezor-firmware)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_TREZOR_FIRMWARE"
```
