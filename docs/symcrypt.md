On `x86_64`:

```
git clone --depth 1 https://github.com/microsoft/SymCrypt.git
cd SymCrypt/
mkdir b/
cd b/
cmake ../
make symcrypt_common symcrypt_generic -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SYMCRYPT"
export SYMCRYPT_INCLUDE_PATH=$(realpath ../inc/)
export LIBSYMCRYPT_COMMON_A_PATH=$(realpath lib/libsymcrypt_common.a)
export SYMCRYPT_GENERIC_A_PATH=$(realpath lib/symcrypt_generic.a)
```

Cross-compiling for `x86` on `x86_64`:

```
git clone --depth 1 https://github.com/microsoft/SymCrypt.git
cd SymCrypt/
sed -i 's/^.*-mspeculative-load-hardening.*//g' CMakeLists.txt
mkdir b/
cd b/
setarch i386 cmake ../
make symcrypt_common symcrypt_generic -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SYMCRYPT"
export SYMCRYPT_INCLUDE_PATH=$(realpath ../inc/)
export LIBSYMCRYPT_COMMON_A_PATH=$(realpath lib/i686/Generic/libsymcrypt_common.a)
export SYMCRYPT_GENERIC_A_PATH=$(realpath lib/i686/Generic/symcrypt_generic.a)
```
