# Notes
- Runs Cryptofuzz against the default JCE provider.
- You can't build more than one libjvm based module (e.g. BouncyCastle) into cryptofuzz. This is due to libjvm's 1
  JVM/process limit.

# Building the module

```
wget https://download.java.net/java/GA/jdk18.0.1/3f48cabb83014f9fab465e280ccf630b/10/GPL/openjdk-18.0.1_linux-x64_bin.tar.gz
tar zxf openjdk-18.0.1_linux-x64_bin.tar.gz
export JDK_PATH=$(realpath jdk-18.0.1)
export LINK_FLAGS="$LINK_FLAGS -L$JDK_PATH/lib/server/ -ljvm -Wl,-rpath=$JDK_PATH/lib/server/"
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_JAVA"
```

## Amazon Corretto Crypto Provider (ACCP)
ACCP is an alternative JCE provider. Building the Java module with ACCP will install it as the preferred JCE provider
and fallback to the default JCE for any unsupported operations. The latest releases can be found [here](https://github.com/corretto/amazon-corretto-crypto-provider/releases).

```
wget https://github.com/corretto/amazon-corretto-crypto-provider/releases/download/2.3.1/AmazonCorrettoCryptoProvider-2.3.1-linux-x86_64.jar
export ACCP_JAR=$(realpath AmazonCorrettoCryptoProvider-2.3.1-linux-x86_64.jar)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_ACCP"
```

# Running with the module

If you build cryptofuzz with `-fsanitize=address` this will also enable [LeakSanitizer](https://clang.llvm.org/docs/LeakSanitizer.html). Since the JVM handles
manages its own memory and garbage collection LeakSanitizer ends up throwing lots of false positives so you should
configure suppressions for any stack trace involving libjvm.

```
# Create an LeakSanitizer suppression file that matches libjvm
echo 'leak:libjvm.so' > libjvm.supp

# Set the LSAN_OPTIONS environmental variable to activate it
export LSAN_OPTIONS=suppressions=`realpath libjvm.supp`
```
