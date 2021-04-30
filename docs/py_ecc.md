```
wget https://github.com/python/cpython/archive/v3.8.0b2.tar.gz
tar zxf v3.8.0b2.tar.gz
mkdir cpython-install
export CRYPTOFUZZ_CPYTHON_PATH=$(realpath cpython-install)
cd cpython-3.8.0b2/
echo -n "I3ByYWdtYSBvbmNlCiNpbmNsdWRlIDxzdGRpbnQuaD4KI2luY2x1ZGUgPHN0ZGRlZi5oPgoKI2RlZmluZSBDT1ZFUkFHRV9BUlJBWV9TSVpFIDY1NTM2CgpfX2F0dHJpYnV0ZV9fKChzZWN0aW9uKCJfX2xpYmZ1enplcl9leHRyYV9jb3VudGVycyIpKSkKdWludDhfdCBjb3ZlcmFnZV9jb3VudGVyW0NPVkVSQUdFX0FSUkFZX1NJWkVdOwoKdm9pZCBmdXp6ZXJfcmVjb3JkX2NvZGVfY292ZXJhZ2Uodm9pZCogY29kZXB0ciwgaW50IGxhc3RpKQp7CiAgICBjb3ZlcmFnZV9jb3VudGVyWyAoKHNpemVfdCkoY29kZXB0cikgXiAoc2l6ZV90KShsYXN0aSkpICUgQ09WRVJBR0VfQVJSQVlfU0laRSBdKys7Cn0K" | base64 -d >Python/python_coverage.h
sed -i '1 s/^.*$/#include "python_coverage.h"/g' Python/ceval.c
sed -i 's/case TARGET\(.*\): {/\0\nfuzzer_record_code_coverage(f->f_code, f->f_lasti);/g' Python/ceval.c
./configure --prefix=$CRYPTOFUZZ_CPYTHON_PATH && make -j $(nproc) && make install
rm -rf $CRYPTOFUZZ_CPYTHON_PATH/lib/python3.8/lib-dynload/_tkinter*.so
cd ../
$CRYPTOFUZZ_CPYTHON_PATH/bin/python3 -m venv venv
export CRYPTOFUZZ_CPYTHON_VENV_PATH=$(realpath venv/)
source venv/bin/activate
pip install git+https://github.com/ethereum/py_ecc.git
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_PY_ECC"
export PYTHON_CONFIG_PATH=$CRYPTOFUZZ_CPYTHON_PATH/bin/python3-config
export CXXFLAGS="$CXXFLAGS $($PYTHON_CONFIG_PATH --cflags)"
export LINK_FLAGS="$LINK_FLAGS -rdynamic $($PYTHON_CONFIG_PATH --ldflags --embed)"
```
