```
wget https://github.com/python/cpython/archive/v3.8.0b2.tar.gz
tar zxf v3.8.0b2.tar.gz
mkdir cpython-install
export CRYPTOFUZZ_CPYTHON_PATH=$(realpath cpython-install)
cd cpython-3.8.0b2/
CFLAGS="" ./configure --prefix=$CRYPTOFUZZ_CPYTHON_PATH && make -j $(nproc) && make install
rm -rf $CRYPTOFUZZ_CPYTHON_PATH/lib/python3.8/lib-dynload/_tkinter*.so
cd ../
$CRYPTOFUZZ_CPYTHON_PATH/bin/python3 -m venv venv
export CRYPTOFUZZ_CPYTHON_VENV_PATH=$(realpath venv/)
source venv/bin/activate
pip3 install --upgrade pip
pip install cairo_lang
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_STARKWARE"
export PYTHON_CONFIG_PATH=$CRYPTOFUZZ_CPYTHON_PATH/bin/python3-config
export CXXFLAGS="$CXXFLAGS $($PYTHON_CONFIG_PATH --cflags)"
export LINK_FLAGS="$LINK_FLAGS -rdynamic $($PYTHON_CONFIG_PATH --ldflags --embed)"
```
