#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include "bn_ops.h"

/* Not included in public headers */
#if defined(CRYPTOFUZZ_BORINGSSL)
extern "C" {
    int bn_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
    int bn_div_consttime(BIGNUM *quotient, BIGNUM *remainder, const BIGNUM *numerator, const BIGNUM *divisor, unsigned divisor_min_bits, BN_CTX *ctx);
    int bn_lcm_consttime(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
    uint16_t bn_mod_u16_consttime(const BIGNUM *bn, uint16_t d);
    int bn_abs_sub_consttime(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
    int bn_is_relatively_prime(int *out_relatively_prime, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
}
#endif

/* Not included in public headers */
#if defined(CRYPTOFUZZ_LIBRESSL)
extern "C" {
    int BN_gcd_ct(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx);
    int bn_isqrt(BIGNUM *out_sqrt, int *out_perfect, const BIGNUM *n, BN_CTX *in_ctx);
    int bn_is_perfect_square(int *out_perfect, const BIGNUM *n, BN_CTX *ctx);
    int BN_div_ct(BIGNUM *quotient, BIGNUM *remainder, const BIGNUM *numerator, const BIGNUM *divisor, BN_CTX *ctx);
    int BN_mod_ct(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
    int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
            const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
            BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
            const BIGNUM *m, BN_CTX *ctx);
}
#endif

#define GET_WHICH(max) uint8_t which = 0; try { which = ds.Get<uint8_t>(); which %= ((max)+1); } catch ( ... ) { }

namespace cryptofuzz {
namespace module {
namespace OpenSSL_bignum {

bool Add::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    GET_WHICH(2);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ(BN_add(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            CF_NORET(bn.CopyResult(res));
            break;
        case    1:
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_EQ(BN_is_negative(bn[1].GetPtr()), 0);
            CF_ASSERT_EQ(BN_uadd(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;
        case    2:
            {
                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);

                CF_ASSERT_EQ(BN_add_word(bn.GetDestPtr(0), *val), 1);

                CF_CHECK_EQ(res.Set(bn[0]), true);
            }
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool Sub::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    GET_WHICH(3);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ(BN_sub(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            CF_NORET(bn.CopyResult(res));
            break;

    /* OpenSSL and LibreSSL return a positive value for BN_usub(A,B)
     * where A > B
     */
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    1:
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_EQ(BN_is_negative(bn[1].GetPtr()), 0);
            CF_CHECK_EQ(BN_usub(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;
#endif
        case    2:
            {
                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);

                CF_ASSERT_EQ(BN_sub_word(bn.GetDestPtr(0), *val), 1);

                CF_CHECK_EQ(res.Set(bn[0]), true);
            }
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    3:
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_EQ(BN_is_negative(bn[1].GetPtr()), 0);
            CF_CHECK_GTE(BN_cmp(bn[0].GetPtr(), bn[1].GetPtr()), 0);
            CF_CHECK_EQ(bn_abs_sub_consttime(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
#endif
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool Mul::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ(BN_mul(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            CF_NORET(bn.CopyResult(res));
            break;
        case    1:
            {
                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);

                CF_ASSERT_EQ(BN_mul_word(bn.GetDestPtr(0), *val), 1);

                CF_CHECK_EQ(res.Set(bn[0]), true);
            }
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool Mod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    GET_WHICH(7);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ_COND(
                    BN_mod(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[1].GetPtr()));
            break;
        case    1:
            /* "BN_mod() corresponds to BN_div() with dv set to NULL" */
            CF_ASSERT_EQ_COND(
                    BN_div(nullptr, res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[1].GetPtr()));
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    2:
            {
                bool use_divisor_min_bits = false;
                try { use_divisor_min_bits = ds. Get<bool>(); } catch ( ... ) { }

                CF_CHECK_EQ(bn_div_consttime(
                            nullptr,
                            res.GetDestPtr(),
                            bn[0].GetPtr(),
                            bn[1].GetPtr(),
                            use_divisor_min_bits ? BN_num_bits(bn[1].GetPtrConst()) : 0,
                            ctx.GetPtr()), 1);
            }
            break;
        case    3:
            CF_NORET(util::HintBignumPow2());
            CF_CHECK_EQ(BN_is_pow2(bn[1].GetPtr()), 1);
            CF_CHECK_EQ(BN_mod_pow2(res.GetDestPtr(), bn[0].GetPtr(), BN_num_bits(bn[1].GetPtr()) - 1), 1);
            break;
        case    4:
            {
                std::optional<uint64_t> v64;

                /* Convert bn[1] to uint64_t if possible */
                CF_CHECK_NE(v64 = bn[1].AsUint64(), std::nullopt);

                /* Try to convert the uint64_t to uint16_t */
                uint16_t v16;
                CF_CHECK_EQ(v16 = *v64, *v64);

                CF_CHECK_GT(v16, 1);

                /* This condition is imposed by bn_mod_u16_consttime, which
                 * triggers an assert failure otherwise
                 */
                CF_CHECK_LTE(BN_num_bits_word(v16 - 1), 16);

                /* ret = bn[0] MOD v16 (which is bn[1]) */
                const auto ret = bn_mod_u16_consttime(bn[0].GetPtr(), v16);
                res.SetUint32(ret);
            }
            break;
#endif
        case    5:
            {
                /* BN_mod_word handles negative inputs in a different way
                 * than other modulo functions
                 */
                CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);

                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);
                CF_CHECK_NE(*val, 0);

                const auto ret = BN_mod_word(bn[0].GetPtr(), *val);

                CF_CHECK_TRUE(res.SetWord(ret));
            }
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    6:
            CF_NORET(util::HintBignumPow2());
            CF_CHECK_EQ(BN_is_pow2(bn[1].GetPtr()), 1);
            CF_CHECK_EQ(BN_nnmod_pow2(res.GetDestPtr(), bn[0].GetPtr(), BN_num_bits(bn[1].GetPtr()) - 1), 1);
            break;
#endif
#if defined(CRYPTOFUZZ_LIBRESSL)
        case    7:
            CF_ASSERT_EQ_COND(
                    BN_mod_ct(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[1].GetPtr()));
            break;
#endif
        default:
            goto end;
            break;
    }

    /* OpenSSL and derivatives deal with negative inputs
     * to Mod differently than some other libraries.
     * Compute the result but don't return it.
     */
    if (    !BN_is_negative(bn[0].GetPtr()) &&
            !BN_is_negative(bn[1].GetPtr()) ) {
        ret = true;
    }

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;
#if defined(CRYPTOFUZZ_OPENSSL_098)
    {
        Bignum zero(ds);
        CF_CHECK_EQ(zero.New(), true);
        CF_CHECK_NE(BN_cmp(bn[1].GetPtr(), zero.GetPtr()), 0);
        CF_CHECK_NE(BN_cmp(bn[2].GetPtr(), zero.GetPtr()), 0);
    }
#endif
    GET_WHICH(6);
    switch ( which ) {
        case    0:
            {
                /* Hint to call RSAZ_1024_mod_exp_avx2 */
                /* https://github.com/openssl/openssl/blob/128d1c3c0a12fe68175a460e06daf1e0d940f681/crypto/bn/bn_exp.c#L664 */
                try {
                    const auto data = ds.GetData(0, 128, 128);
                    CF_NORET(util::HintBignum(util::BinToDec(data)));
                } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }
            }

            {
                /* Hint to call RSAZ_512_mod_exp */
                /* https://github.com/openssl/openssl/blob/128d1c3c0a12fe68175a460e06daf1e0d940f681/crypto/bn/bn_exp.c#L675 */
                try {
                    const auto data = ds.GetData(0, 64, 64);
                    CF_NORET(util::HintBignum(util::BinToDec(data)));
                } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }
            }

            {
                /* Hint to find https://boringssl-review.googlesource.com/c/boringssl/+/52825 */
                /* (and possibly similar bugs) */
                const boost::multiprecision::cpp_int v = rand() % 50;
                const boost::multiprecision::cpp_int h = boost::multiprecision::pow(v, 95 + (rand() % 10));
                const auto hint = h.str();
                CF_NORET(util::HintBignum(hint));
            }

            CF_ASSERT_EQ_COND(
                    BN_mod_exp_mont_consttime(
                        res.GetDestPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        bn[2].GetPtr(),
                        ctx.GetPtr(),
                        nullptr),
                    1,
#if !defined(CRYPTOFUZZ_BORINGSSL)
                    BN_is_zero(bn[2].GetPtr()) || !BN_is_odd(bn[2].GetPtr()));
#else
                    BN_is_zero(bn[2].GetPtr()) ||
                    !BN_is_odd(bn[2].GetPtr()) ||
                    BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()) >= 0);
#endif
            break;
        case    1:
            CF_ASSERT_EQ_COND(
                    BN_mod_exp_mont(
                        res.GetDestPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        bn[2].GetPtr(),
                        ctx.GetPtr(),
                        nullptr),
                    1,
#if !defined(CRYPTOFUZZ_BORINGSSL)
                    BN_is_zero(bn[2].GetPtr()) || !BN_is_odd(bn[2].GetPtr()));
#else
                    BN_is_zero(bn[2].GetPtr()) ||
                    !BN_is_odd(bn[2].GetPtr()) ||
                    BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()) >= 0);
#endif
            break;
        case    2:
            CF_ASSERT_EQ_COND(
                    BN_mod_exp(
                        res.GetDestPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        bn[2].GetPtr(),
                        ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[2].GetPtr()) || !BN_is_odd(bn[2].GetPtr()));
            break;
        case    3:
#if !defined(CRYPTOFUZZ_BORINGSSL)
            CF_CHECK_EQ(BN_mod_exp_simple(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
#else
            goto end;
#endif
            break;
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        case    4:
            {
                {
                    uint8_t which = 0;

                    try {
                        which = ds.Get<uint8_t>() % 4;
                    } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

                    int factor_size = 0;

                    switch ( which ) {
                        case    1:
                            factor_size = 1024;
                            break;
                        case    2:
                            factor_size = 1536;
                            break;
                        case    3:
                            factor_size = 2048;
                            break;
                    }

                    if ( which != 0 ) {
                        {
                            Bignum hint_base(ds);
                            CF_CHECK_TRUE(hint_base.New());
                            BN_rand(hint_base.GetDestPtr(), factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
                            util::HintBignumOpt(hint_base.ToString());
                        }

                        {
                            Bignum hint_exp(ds);
                            CF_CHECK_TRUE(hint_exp.New());
                            BN_rand(hint_exp.GetDestPtr(), factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
                            util::HintBignumOpt(hint_exp.ToString());
                        }

                        {
                            Bignum hint_mod(ds);
                            CF_CHECK_TRUE(hint_mod.New());
                            BN_rand(hint_mod.GetDestPtr(), factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
                            util::HintBignumOpt(hint_mod.ToString());
                        }
                    }
                }

                Bignum r_mont_const_x2_2(ds);
                CF_CHECK_TRUE(r_mont_const_x2_2.New());

                const auto base = bn[0].GetPtr();
                const auto exp = bn[1].GetPtr();
                const auto mod = bn[2].GetPtr();

                CF_CHECK_EQ(BN_mod_exp_mont_consttime_x2(
                            res.GetDestPtr(),
                            base, exp, mod, nullptr,

                            r_mont_const_x2_2.GetDestPtr(),
                            base, exp, mod, nullptr,
                            ctx.GetPtr()), 1);
            }
            break;
#endif
        case    5:
            {
                Bignum one(ds);
                CF_CHECK_EQ(one.New(), true);
                BN_one(one.GetDestPtr());

                BIGNUM const * a2 = one.GetPtr();
                BIGNUM const * p2 = BN_is_zero(bn[3].GetPtr()) ? a2 : bn[3].GetPtr();
                /* a2^p2 == 1 */

                /* result = (a1^p1 * a2^p2) % m */
                CF_CHECK_EQ(BN_mod_exp2_mont(
                            res.GetDestPtr(),
                            bn[0].GetPtr(), bn[1].GetPtr(),
                            a2, p2,
                            bn[2].GetPtr(),
                            ctx.GetPtr(), NULL), 1);

                /* Unlike other exponentation functions,
                 * with BN_mod_exp2_mont,
                 * exponentiation by 0 doesn't result in 1
                 */
                CF_CHECK_NE(BN_is_zero(bn[1].GetPtr()), 1);
            }
            break;
        case    6:
            {
                const auto val = bn[0].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);
                CF_CHECK_EQ(BN_mod_exp_mont_word(res.GetDestPtr(), *val, bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr(), nullptr), 1);
            }
            break;
        default:
            goto end;
            break;

    }

    ret = true;

end:
    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_ASSERT_EQ(BN_sqr(bn.GetResPtr(), bn[0].GetPtr(), ctx.GetPtr()), 1);
    CF_NORET(bn.CopyResult(res));

    ret = true;

    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ(BN_gcd(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            CF_NORET(bn.CopyResult(res));
            break;
#if defined(CRYPTOFUZZ_LIBRESSL)
        case    1:
            CF_CHECK_EQ(BN_gcd_ct(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
#endif
        default:
            goto end;
    }

    ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ_COND(
                    BN_mod_add(
                        res.GetDestPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        bn[2].GetPtr(),
                        ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[2].GetPtr()));
            break;
        case    1:
            {
                Bignum zero(ds);
                CF_CHECK_EQ(zero.New(), true);

                /* "... may be used if both a and b are non-negative and less than m" */
                CF_CHECK_GTE(BN_cmp(bn[0].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_GTE(BN_cmp(bn[1].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[1].GetPtr(), bn[2].GetPtr()), 0);
                CF_ASSERT_EQ(
                        BN_mod_add_quick(
                            res.GetDestPtr(),
                            bn[0].GetPtr(),
                            bn[1].GetPtr(),
                            bn[2].GetPtr()),
                        1);
            }
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ_COND(
                    BN_mod_sub(
                        res.GetDestPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        bn[2].GetPtr(),
                        ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[2].GetPtr()));
            break;
        case    1:
            {
                Bignum zero(ds);
                CF_CHECK_EQ(zero.New(), true);

                /* "... may be used if both a and b are non-negative and less than m" */
                CF_CHECK_GTE(BN_cmp(bn[0].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_GTE(BN_cmp(bn[1].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[1].GetPtr(), bn[2].GetPtr()), 0);
                CF_ASSERT_EQ(BN_mod_sub_quick(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 1);
                break;
            }
            /* bn_mod_sub_fixed_top is disabled because it puts the output bignum
             * in a state that is not compatible with the rest of the bignum API.
             *
             * Discussion: https://github.com/openssl/openssl/issues/14767
             */
#if 0
        case    2:
            /*
               "BN_mod_sub variant that may be used if both a and b are non-negative,
               a is less than m, while b is of same bit width as m. It's implemented
               as subtraction followed by two conditional additions."
               */

            CF_CHECK_LT(bn[0].GetPtr(), bn[2].GetPtr());
            CF_CHECK_EQ(BN_num_bits(bn[1].GetPtr()), BN_num_bits(bn[2].GetPtr()));
            CF_CHECK_EQ(bn_mod_sub_fixed_top(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 1);
            break;
#endif
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    bool ret = false;
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL)
    BN_RECP_CTX* recp = nullptr;
#endif

    GET_WHICH(2);
    switch ( which ) {
        case    0:
            {
                BIGNUM* r = bn.GetResPtr();
                const BIGNUM* a = bn[0].GetPtr();
                const BIGNUM* b = bn[1].GetPtr();
                const BIGNUM* m = bn[2].GetPtr();
                CF_ASSERT_EQ_COND(
                        BN_mod_mul(
                            r, a, b, m,
                            ctx.GetPtr()),
                        1,
                        /* Can fail with zero modulus */
                        BN_is_zero(m) ||
                        /* Aliasing result and modulus is prohibited */
                        r == m);
                CF_NORET(bn.CopyResult(res));
            }
            break;
#if !defined(CRYPTOFUZZ_OPENSSL_098)
        /* Bug */
        case    1:
            {
                BN_MONT_CTX mont(ds);

                /* Set mod */
                CF_CHECK_EQ(BN_MONT_CTX_set(mont.GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);

                Bignum bn0_mont(ds);
                /* bn0 to mont */
                {
                    CF_CHECK_TRUE(bn0_mont.New());
                    CF_CHECK_EQ(BN_nnmod(bn0_mont.GetDestPtr(), bn[0].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
                    auto bn0_mont_ptr = bn0_mont.GetDestPtr();
                    CF_CHECK_EQ(BN_to_montgomery(bn0_mont_ptr, bn0_mont_ptr, mont.GetPtr(), ctx.GetPtr()), 1);
                }

                Bignum bn1_mont(ds);
                /* bn1 to mont */
                {
                    CF_CHECK_TRUE(bn1_mont.New());
                    CF_CHECK_EQ(BN_nnmod(bn1_mont.GetDestPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
                    auto bn1_mont_ptr = bn1_mont.GetDestPtr();
                    CF_CHECK_EQ(BN_to_montgomery(bn1_mont_ptr, bn1_mont_ptr, mont.GetPtr(), ctx.GetPtr()), 1);
                }

                /* mul mod */
                CF_ASSERT_EQ(BN_mod_mul_montgomery(res.GetDestPtr(), bn0_mont.GetPtr(), bn1_mont.GetPtr(), mont.GetPtr(), ctx.GetPtr()), 1);

                /* result from mont */
                auto resPtr = res.GetDestPtr();
                CF_CHECK_EQ(BN_from_montgomery(resPtr, resPtr, mont.GetPtr(), ctx.GetPtr()), 1);
            }
            break;
#endif
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL)
        case    2:
            {
                const bool is_neg = BN_is_negative(bn[0].GetPtr()) ||
                    BN_is_negative(bn[1].GetPtr());
                CF_CHECK_NE(recp = BN_RECP_CTX_new(), nullptr);
                CF_CHECK_EQ(BN_RECP_CTX_set(recp, bn[2].GetPtr(), ctx.GetPtr()), 1);
                CF_CHECK_EQ(BN_mod_mul_reciprocal(
                            bn.GetResPtr(),
                            bn[0].GetPtr(),
                            bn[1].GetPtr(),
                            recp,
                            ctx.GetPtr()), 1);
                CF_CHECK_FALSE(is_neg);
                CF_NORET(bn.CopyResult(res));
            }
            break;
#endif
        default:
            goto end;
            break;
    }

    ret = true;

end:
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL)
    CF_NORET(BN_RECP_CTX_free(recp));
#endif

    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    bool ret = false;

    GET_WHICH(0);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ_COND(
                    BN_mod_sqr(
                        res.GetDestPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[1].GetPtr()));
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    bool ret = false;

    bool fail = false;

    GET_WHICH(2);
    switch ( which ) {
        case    0:
            {
                BIGNUM* r = bn.GetResPtr();
                const BIGNUM* a = bn[0].GetPtr();
                const BIGNUM* n = bn[1].GetPtr();
                CF_CHECK_NE(r, n);
                fail = true;
                CF_CHECK_NE(BN_mod_inverse(r, a, n, ctx.GetPtr()), nullptr);
                CF_NORET(bn.CopyResult(res));
                fail = false;
            }
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    1:
            {
                int out_no_inverse;
                CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[1].GetPtr()), 0);
                CF_CHECK_EQ(BN_is_odd(bn[1].GetPtr()), 1);
                fail = true;
                CF_CHECK_EQ(BN_mod_inverse_odd(res.GetDestPtr(), &out_no_inverse, bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
                fail = false;
            }
            break;
        case    2:
            {
                int out_no_inverse;
                BN_MONT_CTX mont(ds);

                /* Set mod */
                CF_CHECK_EQ(BN_MONT_CTX_set(mont.GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

                /* invmod */
                CF_CHECK_EQ(BN_mod_inverse_blinded(res.GetDestPtr(), &out_no_inverse, bn[0].GetPtr(), mont.GetPtr(), ctx.GetPtr()), 1);

                if ( out_no_inverse ) {
                    fail = true;
                }
            }
            break;
#endif
        default:
            goto end;
            break;
    }

    ret = true;

end:
    if ( fail == true ) {
        res.Set("0");
        return true;
    }

    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    int cmpRes;

    GET_WHICH(2);
    switch ( which ) {
        case    0:
            cmpRes = BN_cmp(bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_EQ(BN_is_negative(bn[1].GetPtr()), 0);
            cmpRes = BN_ucmp(bn[0].GetPtr(), bn[1].GetPtr());
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    2:
            {
                auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);
                cmpRes = BN_cmp_word(bn[0].GetPtr(), *val);
            }
            break;
#endif
        default:
            goto end;
            break;
    }

    if ( cmpRes > 0 ) {
        cmpRes = 1;
    } else if ( cmpRes < 0 ) {
        cmpRes = -1;
    }

    res.Set( std::to_string(cmpRes) );

    ret = true;

end:
    return ret;
}

bool Div::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL)
    BN_RECP_CTX* recp = nullptr;
#endif

    GET_WHICH(4);
    switch ( which ) {
        case    0:
            CF_ASSERT_EQ_COND(
                    BN_div(
                        res.GetDestPtr(),
                        nullptr,
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[1].GetPtr()));
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    1:
            {
                bool use_divisor_min_bits = false;
                try { use_divisor_min_bits = ds. Get<bool>(); } catch ( ... ) { }

                CF_CHECK_EQ(bn_div_consttime(
                            res.GetDestPtr(),
                            nullptr,
                            bn[0].GetPtr(),
                            bn[1].GetPtr(),
                            use_divisor_min_bits ? BN_num_bits(bn[1].GetPtrConst()) : 0,
                            ctx.GetPtr()), 1);
            }
            break;
#endif
        case    2:
            {
                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);

                CF_CHECK_NE(BN_div_word(bn.GetDestPtr(0), *val), (BN_ULONG)-1);
                CF_CHECK_EQ(res.Set(bn[0]), true);
            }
            break;
#if defined(CRYPTOFUZZ_LIBRESSL)
        case    3:
            CF_ASSERT_EQ_COND(
                    BN_div_ct(
                        res.GetDestPtr(),
                        nullptr,
                        bn[0].GetPtr(),
                        bn[1].GetPtr(),
                        ctx.GetPtr()),
                    1,
                    BN_is_zero(bn[1].GetPtr()));
            break;
#endif
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL)
        case    4:
            {
                const bool is_neg = BN_is_negative(bn[0].GetPtr());
                CF_CHECK_NE(recp = BN_RECP_CTX_new(), nullptr);
                CF_CHECK_EQ(BN_RECP_CTX_set(recp, bn[1].GetPtr(), ctx.GetPtr()), 1);
                CF_CHECK_EQ(BN_div_recp(
                            res.GetDestPtr(),
                            nullptr,
                            bn[0].GetPtr(),
                            recp,
                            ctx.GetPtr()), 1);
                CF_CHECK_FALSE(is_neg);
            }
            break;
#endif
        default:
            goto end;
            break;
    }

    ret = true;

end:
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL)
    CF_NORET(BN_RECP_CTX_free(recp));
#endif

    return ret;
}

bool IsPrime::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
    /* Prevent timeouts */
    if ( BN_num_bits(bn[0].GetPtr()) > 3000 ) {
        return false;
    }

    const int ret = BN_is_prime_ex(bn[0].GetPtr(), 0, nullptr, nullptr);
    if ( ret == -1 ) {
        return false;
    }

    res.Set( std::to_string(ret) );

    return true;
#else
    (void)res;
    (void)bn;
    return false;
#endif
}

bool Sqrt::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

#if defined(CRYPTOFUZZ_BORINGSSL)
    CF_CHECK_EQ(BN_sqrt(res.GetDestPtr(), bn[0].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
#elif defined(CRYPTOFUZZ_LIBRESSL)
    int perfect;
    CF_CHECK_EQ(bn_isqrt(res.GetDestPtr(), &perfect, bn[0].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
#else
    (void)res;
    (void)bn;
    (void)ctx;

#endif
    return ret;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_negative(bn[0].GetPtr())) );

    return true;
}

bool IsEq::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

#if defined(CRYPTOFUZZ_BORINGSSL)
    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            res.Set( std::to_string(BN_equal_consttime(bn[0].GetPtr(), bn[1].GetPtr())) );
            break;
        case    1:
            {
                auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);
                res.Set( std::to_string(BN_is_word(bn[0].GetPtr(), *val)) );
            }
            break;
        default:
            goto end;
    }

    ret = true;

end:

    return ret;
#else
    (void)res;
    (void)bn;
    return false;
#endif
}

bool IsEven::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(!BN_is_odd(bn[0].GetPtr())) );

    return true;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_odd(bn[0].GetPtr())) );

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_zero(bn[0].GetPtr())) );

    return true;
}

bool IsOne::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_one(bn[0].GetPtr())) );

    return true;
}

bool Jacobi::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

#if !defined(CRYPTOFUZZ_BORINGSSL)
    const int jacobi = BN_kronecker(bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr());
#else
    const int jacobi = bn_jacobi(bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr());
#endif

    CF_CHECK_NE(jacobi, -2);

    res.Set( std::to_string(jacobi) );

    ret = true;
end:

    return ret;
}

/* OpenSSL 0.9.8 has memory bugs in these functions */
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_OPENSSL_098) && !defined(CRYPTOFUZZ_LIBRESSL)
bool Mod_NIST_192::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_ASSERT_EQ(BN_nist_mod_192(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

    return ret;
}

bool Mod_NIST_224::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_ASSERT_EQ(BN_nist_mod_224(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

    return ret;
}

bool Mod_NIST_256::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_ASSERT_EQ(BN_nist_mod_256(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

    return ret;
}

bool Mod_NIST_384::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_ASSERT_EQ(BN_nist_mod_384(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

    return ret;
}

bool Mod_NIST_521::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_ASSERT_EQ(BN_nist_mod_521(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

    return ret;
}
#endif

#if 0
bool SqrtMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    /* Disabled due to slowness of primality testing */
#if 0
    (void)ds;
    bool ret = false;

    /* Third parameter to BN_mod_sqrt must be prime */
    CF_CHECK_EQ(BN_is_prime_ex(bn[1].GetPtr(), 64, ctx.GetPtr(), nullptr), 1);
    CF_CHECK_NE(BN_mod_sqrt(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), nullptr);

    ret = true;

end:
    return ret;
#else
    (void)ds;
    (void)res;
    (void)bn;
    (void)ctx;
    return false;
#endif
}
#endif

bool SqrtMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;
    bool setzero = true;

    CF_CHECK_NE(BN_mod_sqrt(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), nullptr);
    {
        auto resPtr = res.GetDestPtr();
        CF_CHECK_EQ(BN_mod_mul(resPtr, resPtr, resPtr, bn[1].GetPtr(), ctx.GetPtr()), 1);
    }

    setzero = false;

end:
    if ( setzero ) {
        BN_zero(res.GetDestPtr());
    }

    ret = true;

    return ret;
}

#if defined(CRYPTOFUZZ_BORINGSSL)
bool LCM::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(bn_lcm_consttime(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}
#endif

bool Exp::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_exp(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Abs::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    if ( BN_is_negative(bn[0].GetPtr()) ) {
        Bignum zero(ds);
        CF_CHECK_EQ(zero.New(), true);

        GET_WHICH(1);
        switch ( which ) {
            case    0:
                CF_ASSERT_EQ(BN_sub(res.GetDestPtr(), zero.GetPtr(), bn[0].GetPtr()), 1);
                break;
            case    1:
                {
                    auto bn0 = bn[0].GetPtr();
                    CF_ASSERT_EQ(BN_sub(res.GetDestPtr(), bn0, bn0), 1);
                }
                {
                    auto resPtr = res.GetDestPtr();
                    CF_ASSERT_EQ(BN_sub(resPtr, resPtr, bn[0].GetPtr()), 1);
                }
                break;
            default:
                goto end;
                break;
        }
    } else {
        CF_CHECK_NE(BN_copy(res.GetDestPtr(), bn[0].GetPtr()), nullptr);
    }

    ret = true;

end:
    return ret;
}

bool RShift::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;
    std::optional<int> places;

    GET_WHICH(1);

    CF_CHECK_NE(places = bn[1].AsInt(), std::nullopt);

    switch ( which ) {
        case    0:
            CF_ASSERT_EQ(BN_rshift(res.GetDestPtr(), bn[0].GetPtr(), *places), 1);
            break;
        case    1:
            if ( *places != 1 ) {
                goto end;
            }
            CF_ASSERT_EQ(BN_rshift1(res.GetDestPtr(), bn[0].GetPtr()), 1);
            break;
        default:
            goto end;
    }

    ret = true;

end:
    return ret;
}

bool LShift1::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;
    bool ret = false;

    CF_ASSERT_EQ(BN_lshift1(res.GetDestPtr(), bn[0].GetPtr()), 1);

    ret = true;

    return ret;
}

bool SetBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;
    bool ret = false;
    std::optional<int> pos;

    CF_CHECK_NE(pos = bn[1].AsInt(), std::nullopt);

    CF_ASSERT_EQ(BN_set_bit(bn.GetDestPtr(0), *pos), 1);
    CF_CHECK_NE(BN_copy(res.GetDestPtr(), bn[0].GetPtr()), nullptr);

    ret = true;

end:
    return ret;
}

bool ClearBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;
    bool ret = false;
    std::optional<int> pos;

    CF_CHECK_NE(pos = bn[1].AsInt(), std::nullopt);

    CF_CHECK_EQ(BN_clear_bit(bn.GetDestPtr(0), *pos), 1);
    CF_CHECK_NE(BN_copy(res.GetDestPtr(), bn[0].GetPtr()), nullptr);

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;
    bool ret = false;
    std::optional<int> pos;

    CF_CHECK_NE(pos = bn[1].AsInt(), std::nullopt);

    res.Set( std::to_string(BN_is_bit_set(bn[0].GetPtr(), *pos)) );

    ret = true;

end:
    return ret;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;

    int cmpRes = BN_ucmp(bn[0].GetPtr(), bn[1].GetPtr());

    if ( cmpRes > 0 ) {
        cmpRes = 1;
    } else if ( cmpRes < 0 ) {
        cmpRes = -1;
    }

    res.Set( std::to_string(cmpRes) );

    return true;
}

bool ModLShift::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;
    bool ret = false;
    std::optional<int> places;

    GET_WHICH(3);

    CF_CHECK_NE(places = bn[1].AsInt(), std::nullopt);

    switch ( which ) {
        case    0:
            CF_CHECK_EQ(BN_mod_lshift(res.GetDestPtr(), bn[0].GetPtr(), *places, bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    1:
            /* BN_mod_lshift_quick acts like BN_mod_lshift but requires that a be non-negative and less than m. */
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()), 0);
            CF_CHECK_EQ(BN_mod_lshift_quick(res.GetDestPtr(), bn[0].GetPtr(), *places, bn[2].GetPtr()), 1);
            break;
        case    2:
            CF_NORET(util::HintBignum("1"));
            CF_CHECK_EQ(*places, 1);
            CF_CHECK_EQ(BN_mod_lshift1(res.GetDestPtr(), bn[0].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    3:
            CF_NORET(util::HintBignum("1"));
            CF_CHECK_EQ(*places, 1);
            /* BN_mod_lshift1_quick acts like BN_mod_lshift1 but requires that a be non-negative and less than m. */
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()), 0);
            CF_CHECK_EQ(BN_mod_lshift1_quick(res.GetDestPtr(), bn[0].GetPtr(), bn[2].GetPtr()), 1);
            break;
        default:
            goto end;
    }

    ret = true;

end:
    return ret;
}

bool IsPow2::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;

#if defined(CRYPTOFUZZ_BORINGSSL)
    CF_NORET(util::HintBignumPow2());
    res.Set( std::to_string(BN_is_pow2(bn[0].GetPtr())) );

    return true;
#else
    (void)res;
    (void)bn;

    return false;
#endif
}

bool Mask::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;
    bool ret = false;

    std::optional<int> places;

    CF_CHECK_NE(places = bn[1].AsInt(), std::nullopt);
    CF_CHECK_EQ(BN_mask_bits(bn[0].GetDestPtr(), *places), 1);
    CF_CHECK_EQ(res.Set(bn[0]), true);

    ret = true;

end:
    return ret;
}

bool IsCoprime::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
#if defined(CRYPTOFUZZ_BORINGSSL)
    (void)ds;

    bool ret = false;
    int out_relatively_prime;

    CF_CHECK_EQ(bn_is_relatively_prime(&out_relatively_prime, bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
    CF_CHECK_EQ(res.Set( std::to_string(out_relatively_prime) ), true);

    ret = true;
end:
    return ret;
#else
    (void)ds;
    (void)res;
    (void)bn;
    (void)ctx;
    return false;
#endif
}

bool Rand::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
#if defined(CRYPTOFUZZ_OPENSSL_098)
    (void)bn;
#endif

    bool ret = false;

    GET_WHICH(3);
    switch ( which ) {
#if !defined(CRYPTOFUZZ_OPENSSL_098)
        case    0:
            CF_CHECK_EQ(BN_rand_range(res.GetDestPtr(), bn[0].GetPtr()), 1);
            break;
        case    1:
            CF_CHECK_EQ(BN_pseudo_rand_range(res.GetDestPtr(), bn[0].GetPtr()), 1);
            break;
#endif

        case    2:
            {
                const auto bits = ds.Get<uint8_t>();
                const auto top = ds.Get<uint8_t>();
                const auto bottom = ds.Get<uint8_t>();
#if defined(CRYPTOFUZZ_OPENSSL_098)
                /* Bug */
                goto end;
#endif
                CF_CHECK_EQ(BN_rand(res.GetDestPtr(), bits, top, bottom), 1);
            }
            break;
        case    3:
            {
                const auto bits = ds.Get<uint8_t>();
                const auto top = ds.Get<uint8_t>();
                const auto bottom = ds.Get<uint8_t>();
#if defined(CRYPTOFUZZ_OPENSSL_098)
                /* Bug */
                goto end;
#endif
                CF_CHECK_EQ(BN_pseudo_rand(res.GetDestPtr(), bits, top, bottom), 1);
            }
            break;
        default:
            ret = false;
            break;
    }

    ret = true;

end:
    return ret;
}

bool IsSquare::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

#if defined(CRYPTOFUZZ_LIBRESSL)
    ret = true;

    int perfect;
    CF_CHECK_EQ(bn_is_perfect_square(&perfect, bn[0].GetPtr(), ctx.GetPtr()), 1);

    res.Set( std::to_string(perfect) );

    ret = true;

end:
#else
    (void)res;
    (void)bn;
    (void)ctx;

#endif
    return ret;
}

bool Neg::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)bn;
    (void)ctx;

    bool ret = false;

    CF_CHECK_NE(BN_copy(res.GetDestPtr(), bn[0].GetPtr()), nullptr);
    CF_NORET(BN_set_negative(res.GetDestPtr(), !BN_is_negative(bn[0].GetPtr())));

    ret = true;

end:
    return ret;
}

bool RandRange::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    bool ret = false;

    CF_CHECK_EQ(BN_is_zero(bn[0].GetPtr()), 1);
    CF_CHECK_EQ(BN_rand_range(bn.GetResPtr(), bn[1].GetPtr()), 1);
    CF_NORET(bn.CopyResult(res));

    ret = true;
end:
    return ret;
}

} /* namespace OpenSSL_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
