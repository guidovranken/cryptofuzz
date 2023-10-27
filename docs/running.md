# Running Cryptofuzz

For instructions on how to build Cryptofuzz, see [building.md](building.md).

Cryptofuzz is a [libFuzzer](https://llvm.org/docs/LibFuzzer.html) front-end
for differential fuzzing of various cryptographic libraries.

Once built, the `cryptofuzz` executable behaves like a standard libFuzzer
interface:

 - Pass `-help=1` to see available options.
 - Use `-jobs=<n>` and `-workers=<n>` to control the number of processes used.
 - Run `./cryptofuzz /path/to/corpus` to begin fuzzing. Crashes will be saved
   to `crash-<hash>`.
 - Run `./cryptofuzz --debug /path/to/crash-<hash>` to see what operations
   were performed to cause the crash.

You can use `./generate_corpus /path/to/directory` to generate a starting
corpus, but be warned, this may generate a lot of small files taking up lots
of inodes!

## Cryptofuzz specific command-line arguments
There are a number of options to customize your fuzzing run defined in [options.cpp](options.cpp).


```
--ciphers
  Comma separated list of ciphers to test.
--digests
  Comma separated list of digests to test.
--curves
  Comma separated list of curves to test.
--force-module
  Forces the module specified by a corpus entry to be the specified module.
--disable-modules
  Comma separated list of modules to skip when fuzzing.
--calcops
--min-modules
--disable-tests
--no-decrypt
--no-compare
--dump-json
--from-wycheproof
--from-ecc-diff-fuzzer
--to-ecc-diff-fuzzer
--from-botan
--from-openssl-expmod
--from-builtin-tests
--from-bignum-fuzzer
```