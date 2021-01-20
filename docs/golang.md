```
git clone --depth 1 https://github.com/golang/go
export GO111MODULE=off
cd go/src/
./make.bash
export GOROOT=$(realpath ../)
export GOPATH=$GOROOT/packages
mkdir $GOPATH
export PATH=$GOROOT/bin:$PATH
export PATH=$GOROOT/packages/bin:$PATH
cd ../../
go get golang.org/x/crypto/blake2b
go get golang.org/x/crypto/blake2s
go get golang.org/x/crypto/md4
go get golang.org/x/crypto/ripemd160
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_GOLANG"
```
