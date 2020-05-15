# Building Cryptofuzz

There are three main steps in building Cryptofuzz to begin fuzzing:

 1. Generating Cryptofuzz Headers
 2. Building Cryptographic Libraries and Cryptofuzz Modules
 3. Building Cryptofuzz

## 1. Generating Cryptofuzz Headers

Run:

```sh
python2 gen_repository.py
```

to generate look-up tables required for the compilation of Cryptofuzz.

If you don't, you'll typically see an error message like:

    include/cryptofuzz/repository.h:23:10: fatal error: ../../repository_tbl.h: No such file or directory
       23 | #include "../../repository_tbl.h"
          |          ^~~~~~~~~~~~~~~~~~~~~~~~

## 2. Building Cryptographic Libraries and Cryptofuzz Modules

Refer to the following documentation for building your desired set of
libraries. Note that Cryptofuzz is built around differential fuzzing;
having multiple libraries for a given primitive is helpful in finding
bugs.

When building Cryptofuzz and cryptographic libraries, the suggested
compilation flags are:

```sh
export CFLAGS="-fsanitize=address,undefined,fuzzer-no-link -O2 -g"
export CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link -D_GLIBCXX_DEBUG -O2 -g"
```

Some libraries might also require `-Wl,--unresolved-symbols=ignore-all` in
order to build successfully.

Available library-specific build instructions:

 - [OpenSSL, LibreSSL, BoringSSL](openssl.md)
 - [Botan](botan.md)
 - [Crypto++](cryptopp.md)
 - [NSS](nss.md)
 - [wolfCrypt](wolfcrypt.md)
 - [mbedTLS](mbedtls.md)
 - [libtomcrypt](libtomcrypt.md)
 - [libgmp](libgmp.md)
 - [mpdecimal](mpdecimal.md)
 - [libsodium](libsodium.md)
 - [libgcrypt](libgcrypt.md)
 - [Linux crypto api](linux.md)
 - [SymCrypt](symcrypt.md)

## 3. Building Cryptofuzz

Set the fuzzing engine link:

```sh
export LIBFUZZER_LINK="-fsanitize=fuzzer"
```

Then, build Cryptofuzz:

```sh
make
```

