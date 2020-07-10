# wolfCrypt module for Cryptofuzz

This module supports several additional features.

# Pseudo-randomly induce memory failures

Compile the module with `CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES` defined.

The module hooks wolfCrypt's memory allocator (using `wolfSSL_SetAllocators`) and with this feature enabled, it will pseudo-randomly return `NULL` from the `malloc` and `realloc`.

This feature found several bugs: https://github.com/wolfSSL/wolfssl/pull/3113

# Detecting address space overflows

Compile the module with `CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED` defined.

This feature tries to detect code in the form:

```c
while ( p + len < end ) { }
```

```c
if ( p + len < end ) { }
```

and similar.

The problem with these kind of constructs is that if

- `p` is a pointer pointing to a very high memory address (eg. `0xFFFFF000` on a 32 bit system)
- `len` is  sufficiently large (eg. `0xFFFFF`) that `p + len` will overflow the pointer

memory violations can occur.

Unless `len` is untrusted and very large (32 bits or 64 bits), this is usually not detected by AddressSanitizer or Valgrind.

This feature deliberately allocates some regions at very high addresses (using `mmap` rather than `malloc`) to make any address space overflows more likely.
