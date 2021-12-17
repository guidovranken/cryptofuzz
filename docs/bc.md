```
wget https://ftp.gnu.org/gnu/bc/bc-1.07.tar.gz
tar zxf bc-1.07.tar.gz
cd bc-1.07/
./configure && make -j$(nproc)
export BC_INCLUDE_PATH=$(realpath h/)
export BC_LIBBC_A_PATH=$(realpath lib/libbc.a)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BC"
cd ../
```
