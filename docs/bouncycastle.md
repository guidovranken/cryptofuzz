```
wget https://download.java.net/java/GA/jdk18.0.1/3f48cabb83014f9fab465e280ccf630b/10/GPL/openjdk-18.0.1_linux-x64_bin.tar.gz
tar zxf openjdk-18.0.1_linux-x64_bin.tar.gz
export JDK_PATH=$(realpath jdk-18.0.1)
export LINK_FLAGS="$LINK_FLAGS -L$JDK_PATH/lib/server/ -ljvm -Wl,-rpath=$JDK_PATH/lib/server/"
wget 'https://www.bouncycastle.org/download/bcprov-ext-jdk18on-172.jar'
export BOUNCYCASTLE_JAR=$(realpath bcprov-ext-jdk18on-172.jar)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BOUNCYCASTLE"
```
