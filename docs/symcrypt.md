```
git clone --depth 1 https://github.com/microsoft/SymCrypt.git
cd SymCrypt/
# Unittests don't build with clang and are not needed anyway
sed -i "s/^add_subdirectory(unittest)$//g" CMakeLists.txt
mkdir b/
cd b/
cmake ../
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SYMCRYPT"
export SYMCRYPT_INCLUDE_PATH=$(realpath ../inc/)
export LIBSYMCRYPT_COMMON_A_PATH=$(realpath lib/x86_64/Generic/libsymcrypt_common.a)
export SYMCRYPT_GENERIC_A_PATH=$(realpath lib/x86_64/Generic/symcrypt_generic.a)
```
