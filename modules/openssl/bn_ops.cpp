#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

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
}
#endif

namespace cryptofuzz {
namespace module {
namespace OpenSSL_bignum {

bool Add::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_add(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;
        case    1:
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_EQ(BN_is_negative(bn[1].GetPtr()), 0);
            CF_CHECK_EQ(BN_uadd(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;
        case    2:
            {
                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);

                CF_CHECK_EQ(BN_add_word(bn.GetDestPtr(0), *val), 1);

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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_sub(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
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

                CF_CHECK_EQ(BN_sub_word(bn.GetDestPtr(0), *val), 1);

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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            {
                CF_CHECK_EQ(BN_mul(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            }
            break;
        case    1:
            {
                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);

                CF_CHECK_EQ(BN_mul_word(bn.GetDestPtr(0), *val), 1);

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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    1:
            /* "BN_mod() corresponds to BN_div() with dv set to NULL" */
            CF_CHECK_EQ(BN_div(nullptr, res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
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
                const auto val = bn[1].AsBN_ULONG();
                CF_CHECK_NE(val, std::nullopt);
                CF_CHECK_NE(*val, 0);

                const auto ret = BN_mod_word(bn[0].GetPtr(), *val);

                /* Try to convert the BN_ULONG to uint32_t */
                uint32_t ret32;
                CF_CHECK_EQ(ret32 = ret, ret);

                res.SetUint32(ret32);
            }
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    6:
            CF_NORET(util::HintBignumPow2());
            CF_CHECK_EQ(BN_is_pow2(bn[1].GetPtr()), 1);
            CF_CHECK_EQ(BN_nnmod_pow2(res.GetDestPtr(), bn[0].GetPtr(), BN_num_bits(bn[1].GetPtr()) - 1), 1);
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

bool ExpMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_exp_mont_consttime(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr(), nullptr), 1);
            break;
        case    1:
            CF_CHECK_EQ(BN_mod_exp_mont(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr(), nullptr), 1);
            break;
        case    2:
            CF_CHECK_EQ(BN_mod_exp(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    3:
#if !defined(CRYPTOFUZZ_BORINGSSL)
            CF_CHECK_EQ(BN_mod_exp_simple(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
#else
            goto end;
#endif
            break;
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
        case    4:
            {
                {
                    uint8_t which = 0;

                    try {
                        which = ds.Get<uint8_t>() % 4;
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

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

    CF_CHECK_EQ(BN_sqr(res.GetDestPtr(), bn[0].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_gcd(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_add(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
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
                CF_CHECK_EQ(BN_mod_add_quick(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 1);
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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_sub(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
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
                CF_CHECK_EQ(BN_mod_sub_quick(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 1);
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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_mul(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_sqr(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_NE(BN_mod_inverse(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), nullptr);
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    1:
            {
                int out_no_inverse;
                CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[1].GetPtr()), 0);
                CF_CHECK_EQ(BN_is_odd(bn[1].GetPtr()), 1);
                CF_CHECK_EQ(BN_mod_inverse_odd(res.GetDestPtr(), &out_no_inverse, bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            }
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

bool Cmp::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    int cmpRes;

    switch ( ds.Get<uint8_t>() ) {
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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_div(res.GetDestPtr(), nullptr, bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
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
        default:
            goto end;
            break;
    }

    ret = true;

end:
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

    switch ( ds.Get<uint8_t>() ) {
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

#if !defined(CRYPTOFUZZ_BORINGSSL)
bool Mod_NIST_192::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_192(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_224::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_224(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_256::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_256(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_384::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_384(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_521::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_521(res.GetDestPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}
#endif

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

        switch ( ds.Get<uint8_t>() ) {
            case    0:
                CF_CHECK_EQ(BN_sub(res.GetDestPtr(), zero.GetPtr(), bn[0].GetPtr()), 1);
                break;
            case    1:
                {
                    auto bn0 = bn[0].GetPtr();
                    CF_CHECK_EQ(BN_sub(res.GetDestPtr(), bn0, bn0), 1);
                }
                {
                    auto resPtr = res.GetDestPtr();
                    CF_CHECK_EQ(BN_sub(resPtr, resPtr, bn[0].GetPtr()), 1);
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

    CF_CHECK_NE(places = bn[1].AsInt(), std::nullopt);

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_rshift(res.GetDestPtr(), bn[0].GetPtr(), *places), 1);
            break;
        case    1:
            if ( *places != 1 ) {
                goto end;
            }
            CF_CHECK_EQ(BN_rshift1(res.GetDestPtr(), bn[0].GetPtr()), 1);
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

    CF_CHECK_EQ(BN_lshift1(res.GetDestPtr(), bn[0].GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool SetBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const {
    (void)ctx;
    (void)ds;
    bool ret = false;
    std::optional<uint64_t> pos;

    CF_CHECK_NE(pos = bn[1].AsInt(), std::nullopt);

    CF_CHECK_EQ(BN_set_bit(bn.GetDestPtr(0), *pos), 1);
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
    std::optional<uint64_t> places;

    CF_CHECK_NE(places = bn[1].AsInt(), std::nullopt);

    switch ( ds.Get<uint8_t>() ) {
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
            CF_CHECK_EQ(*places, 1);
            CF_CHECK_EQ(BN_mod_lshift1(res.GetDestPtr(), bn[0].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    3:
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

    std::optional<uint64_t> places;

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
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_rand_range(res.GetDestPtr(), bn[0].GetPtr()), 1);
            break;
        case    1:
            CF_CHECK_EQ(BN_pseudo_rand_range(res.GetDestPtr(), bn[0].GetPtr()), 1);
            break;
        case    2:
            {
                const auto bits = ds.Get<uint8_t>();
                const auto top = ds.Get<uint8_t>();
                const auto bottom = ds.Get<uint8_t>();
                CF_CHECK_EQ(BN_rand(res.GetDestPtr(), bits, top, bottom), 1);
            }
            break;
        case    3:
            {
                const auto bits = ds.Get<uint8_t>();
                const auto top = ds.Get<uint8_t>();
                const auto bottom = ds.Get<uint8_t>();
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

} /* namespace OpenSSL_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
