```
wget https://download.java.net/java/GA/jdk17.0.1/2a2082e5a09d4267845be086888add4f/12/GPL/openjdk-17.0.1_linux-x64_bin.tar.gz
tar zxf openjdk-17.0.1_linux-x64_bin.tar.gz
export JDK_PATH=$(realpath jdk-17.0.1)
export LINK_FLAGS="-L$JDK_PATH/lib/server/ -ljvm -Wl,-rpath=$JDK_PATH/lib/server/"
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_JAVA"
```
