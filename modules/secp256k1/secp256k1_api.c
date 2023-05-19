#include <secp256k1.h>
#include <src/scalar_impl.h>
#include <src/group_impl.h>
#include <src/field_impl.h>
#include <src/ecmult_impl.h>
#include <src/eckey_impl.h>
#if !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
#include <src/scratch_impl.h>
#endif
#if defined(__i386__)
#include <src/int128_struct.h>
#else
#include <src/int128_native_impl.h>
#endif

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

#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
void cryptofuzz_secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag) {
    secp256k1_scalar_cmov(r, a, flag);
}
#endif

unsigned int cryptofuzz_secp256k1_scalar_get_bits(const void *a, unsigned int offset, unsigned int count) {
    return secp256k1_scalar_get_bits(a, offset, count);
}

unsigned int cryptofuzz_secp256k1_scalar_get_bits_var(const void *a, unsigned int offset, unsigned int count) {
    return secp256k1_scalar_get_bits_var(a, offset, count);
}

int cryptofuzz_secp256k1_scalar_shr_int(void *r, int n) {
    return secp256k1_scalar_shr_int(r, n);
}

size_t cryptofuzz_secp256k1_fe_size(void) {
    return sizeof(secp256k1_fe);
}

int cryptofuzz_secp256k1_fe_set_b32_limit(secp256k1_fe *r, const unsigned char *b32) {
    return secp256k1_fe_set_b32_limit(r, b32);
}

void cryptofuzz_secp256k1_fe_set_int(void *r, const int i) {
    secp256k1_fe_set_int(r, i);
}

void cryptofuzz_secp256k1_fe_get_b32(unsigned char *bin, void* a, const int var) {
    if ( var == 0 ) {
        secp256k1_fe_normalize(a);
    } else {
        secp256k1_fe_normalize_var(a);
    }

    secp256k1_fe_get_b32(bin, a);
}

void cryptofuzz_secp256k1_fe_add(void *r, const void *a) {
    secp256k1_fe_add(r, a);
}

void cryptofuzz_secp256k1_fe_mul(void *r, const void* a, const void *b) {
    secp256k1_fe_mul(r, a, b);
}

void cryptofuzz_secp256k1_fe_sqr(void *r, const void *a) {
    secp256k1_fe_sqr(r, a);
}

void cryptofuzz_secp256k1_fe_inv(void *r, const void *a) {
    secp256k1_fe_inv(r, a);
}

void cryptofuzz_secp256k1_fe_inv_var(void *r, const void *a) {
    secp256k1_fe_inv_var(r, a);
}

int cryptofuzz_secp256k1_fe_sqrt(void *r, const void *a) {
    return secp256k1_fe_sqrt(r, a);
}

int cryptofuzz_secp256k1_fe_is_odd(const void *a) {
    return secp256k1_fe_is_odd(a);
}

int cryptofuzz_secp256k1_fe_is_zero(const void *a) {
    return secp256k1_fe_is_zero(a);
}

void cryptofuzz_secp256k1_fe_clear(void *r) {
    secp256k1_fe_clear(r);
}

int cryptofuzz_secp256k1_fe_equal(const void *a, const void *b) {
    return secp256k1_fe_equal(a, b);
}

int cryptofuzz_secp256k1_fe_equal_var(const void *a, const void *b) {
    return secp256k1_fe_equal_var(a, b);
}

int cryptofuzz_secp256k1_fe_cmp_var(const void *a, const void *b) {
    return secp256k1_fe_cmp_var(a, b);
}

void cryptofuzz_secp256k1_fe_cmov(void *r, const void *a, const int flag) {
    secp256k1_fe_cmov(r, a, flag);
}

size_t cryptofuzz_secp256k1_fe_storage_size(void) {
    return sizeof(secp256k1_fe_storage);
}

void cryptofuzz_secp256k1_fe_to_storage(void *r, const void *a) {
    secp256k1_fe_to_storage(r, a);
}

void cryptofuzz_secp256k1_fe_from_storage(void *r, const void *a) {
    secp256k1_fe_from_storage(r, a);
}

#ifdef SECP256K1_WIDEMUL_INT128
size_t cryptofuzz_secp256k1_fe_signed62_size(void) {
    return sizeof(secp256k1_modinv64_signed62);
}

void cryptofuzz_secp256k1_fe_to_signed62(void *r, const void *a) {
    secp256k1_fe_to_signed62(r, a);
}

void cryptofuzz_secp256k1_fe_from_signed62(void *r, const void *a) {
    secp256k1_fe_from_signed62(r, a);
}
#endif

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

#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
void cryptofuzz_secp256k1_gej_double(void *r, const void *a) {
    secp256k1_gej_double(r, a);
}
#endif

void cryptofuzz_secp256k1_gej_double_var(void *r, const void *a, void *rzr) {
    secp256k1_gej_double_var(r, a, rzr);
}

#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
void cryptofuzz_secp256k1_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    secp256k1_ecmult(r, a, na, ng);
}
#endif

void cryptofuzz_secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a) {
    secp256k1_ge_set_gej(r, a);
}

int cryptofuzz_secp256k1_eckey_pubkey_serialize(secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    return secp256k1_eckey_pubkey_serialize(elem, pub, size, compressed);
}
