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
#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
void cryptofuzz_secp256k1_scalar_cmov(void *r, const void *a, int flag);
#endif
unsigned int cryptofuzz_secp256k1_scalar_get_bits(const void *a, unsigned int offset, unsigned int count);
unsigned int cryptofuzz_secp256k1_scalar_get_bits_var(const void *a, unsigned int offset, unsigned int count);
int cryptofuzz_secp256k1_scalar_shr_int(void *r, int n);

size_t cryptofuzz_secp256k1_fe_size(void);
int cryptofuzz_secp256k1_fe_set_b32_limit(void *r, const unsigned char *b32);
void cryptofuzz_secp256k1_fe_set_int(void *r, const int i);
void cryptofuzz_secp256k1_fe_get_b32(unsigned char *bin, void* a, const int var);
void cryptofuzz_secp256k1_fe_add(void *r, const void *a);
void cryptofuzz_secp256k1_fe_mul(void *r, const void* a, const void *b);
void cryptofuzz_secp256k1_fe_sqr(void *r, const void *a);
void cryptofuzz_secp256k1_fe_inv(void *r, const void *a);
void cryptofuzz_secp256k1_fe_inv_var(void *r, const void *a);
int cryptofuzz_secp256k1_fe_sqrt(void *r, const void *a);
int cryptofuzz_secp256k1_fe_is_odd(const void *a);
int cryptofuzz_secp256k1_fe_is_zero(const void *a);
void cryptofuzz_secp256k1_fe_clear(void *r);
int cryptofuzz_secp256k1_fe_equal(const void *a, const void *b);
int cryptofuzz_secp256k1_fe_equal_var(const void *a, const void *b);
int cryptofuzz_secp256k1_fe_cmp_var(const void *a, const void *b);
void cryptofuzz_secp256k1_fe_cmov(void *r, const void *a, const int flag);
size_t cryptofuzz_secp256k1_fe_storage_size(void);
void cryptofuzz_secp256k1_fe_to_storage(void *r, const void *a);
void cryptofuzz_secp256k1_fe_from_storage(void *r, const void *a);
#ifdef SECP256K1_WIDEMUL_INT128
size_t cryptofuzz_secp256k1_fe_signed62_size(void);
void cryptofuzz_secp256k1_fe_to_signed62(void *r, const void *a);
void cryptofuzz_secp256k1_fe_from_signed62(void *r, const void *a);
#endif

/* Point ops */
size_t cryptofuzz_secp256k1_ge_size(void);
size_t cryptofuzz_secp256k1_gej_size(void);
int cryptofuzz_secp256k1_eckey_pubkey_parse(void *elem, const unsigned char *pub, size_t size);
void cryptofuzz_secp256k1_gej_set_ge(void *r, const void *a);
void cryptofuzz_secp256k1_gej_add_ge(void *r, const void *a, const void *b);
void cryptofuzz_secp256k1_gej_add_ge_var(void *r, const void *a, const void *b, void *rzr);
void cryptofuzz_secp256k1_gej_neg(void *r, const void *a);
#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
void cryptofuzz_secp256k1_gej_double(void *r, const void *a);
#endif
void cryptofuzz_secp256k1_gej_double_var(void *r, const void *a, void *rzr);
#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
void cryptofuzz_secp256k1_ecmult(void *r, const void* a, const void* na, const void *ng);
#endif
void cryptofuzz_secp256k1_ge_set_gej(void *r, void *a);
int cryptofuzz_secp256k1_eckey_pubkey_serialize(void *elem, unsigned char *pub, size_t *size, int compressed);
