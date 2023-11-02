```
git clone https://github.com/libecc/libecc.git
cd libecc/
git checkout cryptofuzz
python3 scripts/expand_libecc.py --name="secp112r2" --prime=0xdb7c2abf62e35e668076bead208b --order=0x36df0aafd8b8d7597ca10520d04b --a=0x6127c24c05f38a0aaaf65c0ef02c --b=0x51def1815db5ed74fcc34c85d709 --gx=0x4ba30ab5e892b4e1649dd0928643 --gy=0xadcd46f5882e3747def36e956e97 --cofactor=4
python3 scripts/expand_libecc.py --name="secp128r2" --prime=0xfffffffdffffffffffffffffffffffff --order=0x3fffffff7fffffffbe0024720613b5a3 --a=0xd6031998d1b3bbfebf59cc9bbff9aee1 --b=0x5eeefca380d02919dc2c6558bb6d8a5d --gx=0x7b6aa5d85e572983e6fb32a7cdebc140 --gy=0x27b6916a894d3aee7106fe805fc34b44 --cofactor=4
export CFLAGS="$CFLAGS -DUSE_CRYPTOFUZZ"
make -j$(nproc) build/libsign.a
export LIBECC_PATH=$(realpath .)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBECC"
cd ../
```
