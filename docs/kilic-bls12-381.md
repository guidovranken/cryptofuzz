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

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_KILIC_BLS12_381"
```
