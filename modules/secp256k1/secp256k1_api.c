#include <secp256k1.h>
#include <src/libsecp256k1-config.h>
#include <src/scalar_impl.h>
#include <src/group_impl.h>
#include <src/field_impl.h>
#include <src/ecmult_impl.h>
#include <src/eckey_impl.h>
#include <src/scratch_impl.h>

size_t cryptofuzz_secp256k1_scalar_type_size(void) {
    return sizeof(secp256k1_scalar);
}

void cryptofuzz_secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    secp256k1_scalar_set_b32(r, b32, overflow);
}

void cryptofuzz_secp256k1_scalar_get_b32(unsigned char *bin, const void* a) {
    secp256k1_scalar_get_b32(bin, a);
}

void cryptofuzz_secp256k1_scalar_set_int(secp256k1_scalar *r, unsigned int v) {
    secp256k1_scalar_set_int(r, v);
}

int cryptofuzz_secp256k1_scalar_is_zero(const secp256k1_scalar *a) {
    return secp256k1_scalar_is_zero(a);
}

int cryptofuzz_secp256k1_scalar_is_one(const secp256k1_scalar *a) {
    return secp256k1_scalar_is_one(a);
}

int cryptofuzz_secp256k1_scalar_is_even(const secp256k1_scalar *a) {
    return secp256k1_scalar_is_even(a);
}

int cryptofuzz_secp256k1_scalar_eq(const secp256k1_scalar *a, const secp256k1_scalar *b) {
    return secp256k1_scalar_eq(a, b);
}

int cryptofuzz_secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    return secp256k1_scalar_add(r, a, b);
}

void cryptofuzz_secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    secp256k1_scalar_mul(r, a, b);
}

void cryptofuzz_secp256k1_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *x) {
    secp256k1_scalar_inverse(r, x);
}

void cryptofuzz_secp256k1_scalar_inverse_var(secp256k1_scalar *r, const secp256k1_scalar *x) {
    secp256k1_scalar_inverse_var(r, x);
}

void cryptofuzz_secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag) {
    secp256k1_scalar_cmov(r, a, flag);
}

unsigned int cryptofuzz_secp256k1_scalar_get_bits(const void *a, unsigned int offset, unsigned int count) {
    return secp256k1_scalar_get_bits(a, offset, count);
}

unsigned int cryptofuzz_secp256k1_scalar_get_bits_var(const void *a, unsigned int offset, unsigned int count) {
    return secp256k1_scalar_get_bits_var(a, offset, count);
}

int cryptofuzz_secp256k1_scalar_shr_int(void *r, int n) {
    return secp256k1_scalar_shr_int(r, n);
}

size_t cryptofuzz_secp256k1_ge_size(void) {
    return sizeof(secp256k1_ge);
}

size_t cryptofuzz_secp256k1_gej_size(void) {
    return sizeof(secp256k1_gej);
}

int cryptofuzz_secp256k1_eckey_pubkey_parse(secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    return secp256k1_eckey_pubkey_parse(elem, pub, size);
}

void cryptofuzz_secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) {
    secp256k1_gej_set_ge(r, a);
}

void cryptofuzz_secp256k1_gej_add_ge(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b) {
    secp256k1_gej_add_ge(r, a, b);
}

void cryptofuzz_secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, secp256k1_fe *rzr) {
    secp256k1_gej_add_ge_var(r, a, b, rzr);
}

void cryptofuzz_secp256k1_gej_neg(secp256k1_gej *r, const secp256k1_gej *a) {
    secp256k1_gej_neg(r, a);
}

void cryptofuzz_secp256k1_gej_double(void *r, const void *a) {
    secp256k1_gej_double(r, a);
}
void cryptofuzz_secp256k1_gej_double_var(void *r, const void *a, void *rzr) {
    secp256k1_gej_double_var(r, a, rzr);
}

void cryptofuzz_secp256k1_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    secp256k1_ecmult(r, a, na, ng);
}

void cryptofuzz_secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a) {
    secp256k1_ge_set_gej(r, a);
}

int cryptofuzz_secp256k1_eckey_pubkey_serialize(secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    return secp256k1_eckey_pubkey_serialize(elem, pub, size, compressed);
}
