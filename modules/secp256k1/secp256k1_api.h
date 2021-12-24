#pragma once

#include <stdlib.h>

/* Scalar ops */
size_t cryptofuzz_secp256k1_scalar_type_size(void);
void cryptofuzz_secp256k1_scalar_set_b32(void *r, const unsigned char *b32, int *overflow);
void cryptofuzz_secp256k1_scalar_get_b32(unsigned char *bin, const void* a);
void cryptofuzz_secp256k1_scalar_set_int(void *r, unsigned int v);
int cryptofuzz_secp256k1_scalar_is_zero(const void *a);
int cryptofuzz_secp256k1_scalar_is_one(const void *a);
int cryptofuzz_secp256k1_scalar_is_even(const void *a);
int cryptofuzz_secp256k1_scalar_eq(const void *a, const void *b);
int cryptofuzz_secp256k1_scalar_add(void *r, const void *a, const void *b);
void cryptofuzz_secp256k1_scalar_mul(void *r, const void *a, const void *b);
void cryptofuzz_secp256k1_scalar_inverse(void *r, const void *x);
void cryptofuzz_secp256k1_scalar_inverse_var(void *r, const void *x);
void cryptofuzz_secp256k1_scalar_cmov(void *r, const void *a, int flag);
unsigned int cryptofuzz_secp256k1_scalar_get_bits(const void *a, unsigned int offset, unsigned int count);
unsigned int cryptofuzz_secp256k1_scalar_get_bits_var(const void *a, unsigned int offset, unsigned int count);
int cryptofuzz_secp256k1_scalar_shr_int(void *r, int n);

/* Point ops */
size_t cryptofuzz_secp256k1_ge_size(void);
size_t cryptofuzz_secp256k1_gej_size(void);
int cryptofuzz_secp256k1_eckey_pubkey_parse(void *elem, const unsigned char *pub, size_t size);
void cryptofuzz_secp256k1_gej_set_ge(void *r, const void *a);
void cryptofuzz_secp256k1_gej_add_ge(void *r, const void *a, const void *b);
void cryptofuzz_secp256k1_gej_add_ge_var(void *r, const void *a, const void *b, void *rzr);
void cryptofuzz_secp256k1_gej_neg(void *r, const void *a);
void cryptofuzz_secp256k1_gej_double(void *r, const void *a);
void cryptofuzz_secp256k1_gej_double_var(void *r, const void *a, void *rzr);
void cryptofuzz_secp256k1_ecmult(void *r, const void* a, const void* na, const void *ng);
void cryptofuzz_secp256k1_ge_set_gej(void *r, void *a);
int cryptofuzz_secp256k1_eckey_pubkey_serialize(void *elem, unsigned char *pub, size_t *size, int compressed);
