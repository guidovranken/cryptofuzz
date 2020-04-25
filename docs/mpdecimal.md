```
https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-2.4.2.tar.gz
tar zxvf mpdecimal-2.4.2.tar.gz
cd mpdecimal-2.4.2/
./configure && make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MPDECIMAL"
export LIBMPDEC_A_PATH=$(realpath libmpdec/libmpdec.a)
export LIBMPDEC_INCLUDE_PATH=$(realpath libmpdec/)
```
