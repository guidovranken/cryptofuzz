```
wget https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-4.0.0.tar.gz
tar zxvf mpdecimal-4.0.0.tar.gz
cd mpdecimal-4.0.0/
./configure && make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MPDECIMAL"
export LIBMPDEC_A_PATH=$(realpath libmpdec/libmpdec.a)
export LIBMPDEC_INCLUDE_PATH=$(realpath libmpdec/)
```
