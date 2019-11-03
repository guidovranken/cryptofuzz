# Building Cryptofuzz

## Preparation

Run:

```python gen_repository.py```

to generate look-up tables required for the compilation of Cryptofuzz.

Set the fuzzing engine:

```sh
export LIBFUZZER_LINK="-fsanitize=fuzzer"
```

Recommended compilation flags for both Cryptofuzz and cryptographic libraries are:

```sh
export CFLAGS="-fsanitize=address,undefined,fuzzer-no-link -O2 -g"
export CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link -D_GLIBCXX_DEBUG -O2 -g"
```

## Building modules

For library-specific build instructions, please refer to:

[OpenSSL, LibreSSL, BoringSSL](openssl.md)

[Botan](botan.md)

[Crypto++](cryptopp.md)

[wolfCrypt](wolfcrypt.md)
