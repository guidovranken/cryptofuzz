#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <type_traits>

#include "bn_ops.h"

#define GET_WHICH(max) uint8_t which = 0; try { which = ds.Get<uint8_t>(); which %= ((max)+1); } catch ( ... ) { }
#define GET_OPTIONAL_BN() (ds.Get<bool>() ? bn.GetDestPtr(3) : nullptr)

namespace cryptofuzz {
namespace module {

namespace wolfCrypt_detail {
    WC_RNG* GetRNG(void);
    WC_RNG* GetSystemRNG(void);
}

namespace wolfCrypt_bignum {

namespace wolfCrypt_bignum_detail {

    template <class ReturnType>
    static ReturnType assertRet(const ReturnType ret) {
        static_assert(std::is_same<ReturnType, int>());

        if ( ret > 0 ) {
            CF_ASSERT(0, "Result of mp_* function is not negative or zero");
        }

        return ret;
    }
#define MP_CHECK_EQ(expr, res) CF_CHECK_EQ(::cryptofuzz::module::wolfCrypt_bignum::wolfCrypt_bignum_detail::assertRet(expr), res);

    static int compare(Bignum& A, Bignum& B, Datasource& ds) {
        util::HintBignumOpt(A.ToDecString());
        util::HintBignumOpt(B.ToDecString());

        bool swap = false;
        try {
            swap = ds.Get<bool>();
        } catch ( ... ) { }

        if ( swap == false ) {
            return mp_cmp(A.GetPtr(), B.GetPtr());
        } else {
            const auto ret = mp_cmp(B.GetPtr(), A.GetPtr());

            /* Because the operands were swapped, invert the result */
            if ( ret == MP_LT ) {
                return MP_GT;
            } else if ( ret == MP_GT ) {
                return MP_LT;
            } else {
                return ret;
            }
        }
    }

#if !defined(WOLFSSL_SP_MATH) && (!defined(USE_FAST_MATH) || defined(WOLFSSL_SP_MATH_ALL))
    static std::optional<int> isPowerOf2(Bignum& A, Datasource& ds) {
        std::optional<int> ret = std::nullopt;
        wolfCrypt_bignum::Bignum tmp(ds);

        auto numBits = mp_count_bits(A.GetPtr());
        CF_CHECK_GTE(numBits, 1);
        numBits--;
        MP_CHECK_EQ(mp_copy(A.GetPtr(), tmp.GetPtr()), MP_OKAY);
#if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH)
        CF_NORET(mp_rshb(tmp.GetPtr(), numBits));
#else
        MP_CHECK_EQ(mp_rshb(tmp.GetPtr(), numBits), MP_OKAY);
#endif
        MP_CHECK_EQ(mp_mul_2d(tmp.GetPtr(), numBits, tmp.GetPtr()), MP_OKAY);

        {
            /* Use the nearest exponent of 2 as a hint for the mutator */
            const auto s = tmp.ToDecString();

            util::HintBignumOpt(s);
        }

        CF_CHECK_EQ(compare(A, tmp, ds), MP_EQ);

        ret = numBits;
end:
        return ret;
    }
#endif
}

bool Add::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_add(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            ret = true;
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                MP_CHECK_EQ(mp_add_d(bn[0].GetPtr(), *op, bn.GetResPtr()), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
                ret = true;
            }
            break;
    }

end:
    return ret;
}

bool Sub::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    /* SP math cannot represent negative numbers, so ensure the result
     * of the subtracton is always >= 0.
     *
     * Still run the subtraction operation to see if this can cause
     * memory errors, but don't return the result.
     */
    bool negative = false;
    if ( wolfCrypt_bignum_detail::compare(bn[0], bn[1], ds) == MP_LT) {
        negative = true;
    }
#endif

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_sub(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            ret = true;
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                MP_CHECK_EQ(mp_sub_d(bn[0].GetPtr(), *op, bn.GetResPtr()), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
                ret = true;
            }
            break;
    }

end:
#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    if ( negative == true ) {
        return false;
    }
#endif
    return ret;
}

bool Mul::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH(3);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_mul(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            ret = true;
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                MP_CHECK_EQ(mp_mul_d(bn[0].GetPtr(), *op, bn.GetResPtr()), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
                ret = true;
            }
            break;
#if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
        case    2:
            util::HintBignum("2");
            CF_CHECK_EQ(mp_cmp_d(bn[1].GetPtr(), 2), MP_EQ);
            MP_CHECK_EQ(mp_mul_2(bn[0].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            ret = true;
            break;
#endif
        case    3:
            {
                const auto numBits = mp_cnt_lsb(bn[1].GetPtr());
                CF_CHECK_GTE(numBits, DIGIT_BIT);
                CF_CHECK_EQ(numBits % DIGIT_BIT, 0);

                wolfCrypt_bignum::Bignum multiplier(ds);
                MP_CHECK_EQ(mp_2expt(multiplier.GetPtr(), numBits), MP_OKAY);
                CF_CHECK_EQ(wolfCrypt_bignum_detail::compare(bn[1], multiplier, ds), MP_EQ);

                MP_CHECK_EQ(mp_lshd(bn.GetDestPtr(0), numBits / DIGIT_BIT), MP_OKAY);
                MP_CHECK_EQ(mp_copy(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
                ret = true;
            }
            break;
    }

end:
    return ret;
}

bool Div::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    GET_WHICH(3);
    switch ( which ) {
        case    0:
            {
                auto r = bn.GetResPtr();
                auto optional_bn = GET_OPTIONAL_BN();
                if ( optional_bn == r ) {
                    /* Prevent that the two result pointers are equal */
                    optional_bn = nullptr;
                }
                MP_CHECK_EQ(mp_div(bn[0].GetPtr(), bn[1].GetPtr(), r, optional_bn), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
            }
            break;
        case    1:
#if !defined(WOLFSSL_SP_MATH)
            util::HintBignum("2");
            CF_CHECK_EQ(mp_cmp_d(bn[1].GetPtr(), 2), MP_EQ);
            MP_CHECK_EQ(mp_div_2(bn[0].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#endif
#if !defined(USE_FAST_MATH)
        case    2:
            {
                mp_digit remainder;
                util::HintBignum("3");
                CF_CHECK_EQ(mp_cmp_d(bn[1].GetPtr(), 3), MP_EQ);
                MP_CHECK_EQ(mp_div_3(bn[0].GetPtr(), bn.GetResPtr(), ds.Get<bool>() ? &remainder : nullptr), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
            }
            break;
#endif
#if defined(WOLFSSL_SP_MATH_ALL)
        case    3:
            {
                const auto divisor = bn[1].AsUnsigned<mp_digit>();
                mp_digit remainder;
                CF_CHECK_NE(divisor, std::nullopt);
                MP_CHECK_EQ(mp_div_d(bn[0].GetPtr(), *divisor, bn.GetResPtr(), ds.Get<bool>() ? &remainder : nullptr), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
            }
#endif
        default:
            goto end;
    }

    /* wolfCrypt uses different rounding logic with negative divisior.
     * The result is still computed, but don't return it
     */
    CF_CHECK_EQ(mp_isneg(bn[0].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    try {
        switch ( ds.Get<uint8_t>() % 5 ) {
            case    0:
            {
                auto data = ds.GetData(0, 1024 / 8, 1024 / 8);
                /* Odd */
                data[1024 / 8 - 1] |= 1;
                util::HintBignum(util::BinToDec(data));
            }
            break;
            case    1:
            {
                auto data = ds.GetData(0, 1536 / 8, 1536 / 8);
                data[1536 / 8 - 1] |= 1;
                util::HintBignum(util::BinToDec(data));
            }
            break;
            case    2:
            {
                auto data = ds.GetData(0, 2048 / 8, 2048 / 8);
                data[2048 / 8 - 1] |= 1;
                util::HintBignum(util::BinToDec(data));
            }
            break;
            case    3:
            {
                auto data = ds.GetData(0, 3072 / 8, 3072 / 8);
                data[3072 / 8 - 1] |= 1;
                util::HintBignum(util::BinToDec(data));
            }
            break;
            case    4:
            {
                auto data = ds.GetData(0, 4096 / 8, 4096 / 8);
                data[4096 / 8 - 1] |= 1;
                util::HintBignum(util::BinToDec(data));
            }
            break;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    bool return_result = false;

#if defined(WOLFSSL_SP_MATH)
    return_result = true;
#else
    if (
            !mp_iszero(bn[1].GetPtr()) &&
            !mp_isneg(bn[0].GetPtr()) &&
            !mp_isneg(bn[1].GetPtr()) &&
            !mp_isneg(bn[2].GetPtr()) ) {
            return_result = true;
    }
#endif


    GET_WHICH(9);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_exptmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#if defined(WOLFSSL_SP_MATH_ALL) || defined(USE_FAST_MATH)
        case    1:
            MP_CHECK_EQ(mp_exptmod_nct(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#endif
        case    2:
            MP_CHECK_EQ(mp_exptmod_ex(bn[0].GetPtr(), bn[1].GetPtr(), bn[1].GetPtr()->used, bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#if defined(WOLFSSL_SP_MATH)
            /* ZD 15548 */
#if !defined(__aarch64__)
        case    3:
            MP_CHECK_EQ(sp_ModExp_1024(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#endif
        case    4:
            MP_CHECK_EQ(sp_ModExp_1536(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
        case    5:
            MP_CHECK_EQ(sp_ModExp_2048(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
        case    6:
            MP_CHECK_EQ(sp_ModExp_3072(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#if !defined(__i386__)
        case    7:
            MP_CHECK_EQ(sp_ModExp_4096(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#endif
#endif
#if !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL) && !defined(USE_FAST_MATH)
        case    8:
            MP_CHECK_EQ(mp_exptmod_fast(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr(), 0), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#endif
#if !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL) && !defined(USE_FAST_MATH)
        case    9:
            {
                util::HintBignum("2");
                CF_CHECK_EQ(mp_cmp_d(bn[0].GetPtr(), 2), MP_EQ);
                MP_CHECK_EQ(mp_exptmod_base_2(bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
            }
            break;
#endif
        default:
            goto end;
    }

    CF_CHECK_TRUE(return_result);

end:
    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    MP_CHECK_EQ(mp_sqr(bn[0].GetPtr(), bn.GetResPtr()), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    bool ret = false;

    /* mp_gcd does not support negative numbers */
    CF_CHECK_NE(mp_cmp_d(bn[0].GetPtr(), 0), MP_LT);
    CF_CHECK_NE(mp_cmp_d(bn[1].GetPtr(), 0), MP_LT);

    MP_CHECK_EQ(mp_gcd(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    GET_WHICH(1);

    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_invmod(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#define HAVE_MP_INVMOD_MONT_CT 1

#if defined(USE_INTEGER_HEAP_MATH)
 /* Heapmath does not have mp_invmod_mont_ct */
 #undef HAVE_MP_INVMOD_MONT_CT
#elif defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_INVMOD_MONT_CT)
 /* SP math has mp_invmod_mont_ct only if WOLFSSL_SP_INVMOD_MONT_CT is defined */
 #undef HAVE_MP_INVMOD_MONT_CT
#endif

#if defined(HAVE_MP_INVMOD_MONT_CT)
        case    1:
            {
                mp_digit mp;
                wolfCrypt_bignum::Bignum tmp1(ds);
                wolfCrypt_bignum::Bignum tmp2(ds);
                int is_prime;

                /* Modulus must be > 2 and prime */
                CF_CHECK_EQ(mp_cmp_d(bn[1].GetPtr(), 2), MP_GT);
                MP_CHECK_EQ(mp_prime_is_prime_ex(bn[1].GetPtr(), 30, &is_prime, wolfCrypt_detail::GetRNG()), MP_OKAY);
                CF_CHECK_EQ(is_prime, 1);

                MP_CHECK_EQ(mp_montgomery_setup(bn[1].GetPtr(), &mp), MP_OKAY);
                MP_CHECK_EQ(mp_montgomery_calc_normalization(tmp1.GetPtr(), bn[1].GetPtr()), MP_OKAY);
                MP_CHECK_EQ(mp_mulmod(bn[0].GetPtr(), tmp1.GetPtr(), bn[1].GetPtr(), tmp2.GetPtr()), MP_OKAY);
                MP_CHECK_EQ(mp_invmod_mont_ct(tmp2.GetPtr(), bn[1].GetPtr(), res.GetPtr(), mp), MP_OKAY);
                MP_CHECK_EQ(mp_montgomery_reduce(res.GetPtr(), bn[1].GetPtr(), mp), MP_OKAY);
            }
            break;
#undef HAVE_MP_INVMOD_MONT_CT
#endif

#if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
#if 0
        case    2:
            MP_CHECK_EQ(mp_invmod_slow(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
#endif
#endif
        default:
            goto end;
    }

    ret = true;

end:
    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    int cmpRes = 0;
    GET_WHICH(1);
    switch ( which ) {
        case    0:
            cmpRes = wolfCrypt_bignum_detail::compare(bn[0], bn[1], ds);
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                cmpRes = mp_cmp_d(bn[0].GetPtr(), *op);
            }
            break;
        default:
            goto end;
    }

    switch ( cmpRes ) {
        case    MP_GT:
            CF_CHECK_EQ( res.Set("1"), true);
            break;
        case    MP_LT:
            CF_CHECK_EQ( res.Set("-1"), true);
            break;
        case    MP_EQ:
            CF_CHECK_EQ( res.Set("0"), true);
            break;
        default:
            CF_ASSERT(0, "Compare result is not one of (MP_GT, MP_LT, MP_EQ)");
    }

    ret = true;

end:
    return ret;
}

bool Abs::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    MP_CHECK_EQ(mp_abs(bn[0].GetPtr(), bn.GetResPtr()), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool Neg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    (void)res;
    (void)bn;
#else
    CF_CHECK_EQ(res.Set("0"), true);
    MP_CHECK_EQ(mp_sub(res.GetPtr(), bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
#endif

    return ret;
}

bool RShift::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    std::optional<uint64_t> _numBits;
    int numBits;

    GET_WHICH(2);
    CF_CHECK_NE(_numBits = bn[1].AsUint64(), std::nullopt);
    CF_CHECK_LTE(_numBits, 2147483647);

    numBits = *_numBits;

    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_copy(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
#if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH)
            CF_NORET(mp_rshb(res.GetPtr(), numBits));
#else
            MP_CHECK_EQ(mp_rshb(res.GetPtr(), numBits), MP_OKAY);
#endif
            ret = true;
            break;
#if !defined(WOLFSSL_SP_MATH)
        case    1:
            MP_CHECK_EQ(mp_div_2d(bn[0].GetPtr(), numBits, res.GetPtr(), GET_OPTIONAL_BN()), MP_OKAY);
            ret = true;
            break;
#endif
#if !defined(WOLFSSL_SP_MATH)
        case    2:
            {
                /* Check if number of bits to shift is a multiple of a full digit */
                CF_CHECK_EQ(numBits % (sizeof(mp_digit) * 8), 0);

                MP_CHECK_EQ(mp_copy(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

                const auto numDigits = numBits / (sizeof(mp_digit) * 8);
                CF_NORET(mp_rshd(res.GetPtr(), numDigits));

                ret = true;
            }
            break;
#endif
    }

end:

    return ret;
}

bool LShift1::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    MP_CHECK_EQ(mp_mul_2d(bn[0].GetPtr(), 1, bn.GetResPtr()), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:
#endif

    return ret;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    (void)res;
    (void)bn;
#else
    CF_CHECK_EQ( res.Set( std::to_string(mp_isneg(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:
#endif
    return ret;
}

bool IsEq::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    const bool isEq = wolfCrypt_bignum_detail::compare(bn[0], bn[1], ds) == MP_EQ;
    CF_CHECK_EQ( res.Set( std::to_string(isEq ? 1 : 0) ), true);

    ret = true;

end:
    return ret;
}

bool IsZero::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ( res.Set( std::to_string(mp_iszero(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:
    return ret;
}

bool IsOne::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ( res.Set( std::to_string(mp_isone(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:
    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    MP_CHECK_EQ(mp_mulmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)ds;
    (void)res;
    (void)bn;
#else
    GET_WHICH(1);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_addmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
        case    1:
            /* mp_addmod_ct does not support negative numbers */
            CF_CHECK_NE(mp_cmp_d(bn[0].GetPtr(), 0), MP_LT);
            CF_CHECK_NE(mp_cmp_d(bn[1].GetPtr(), 0), MP_LT);
            CF_CHECK_NE(mp_cmp_d(bn[2].GetPtr(), 0), MP_LT);

            CF_CHECK_EQ(wolfCrypt_bignum_detail::compare(bn[0], bn[1], ds), MP_LT)
            CF_CHECK_EQ(wolfCrypt_bignum_detail::compare(bn[1], bn[2], ds), MP_LT)
            MP_CHECK_EQ(mp_addmod_ct(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
        default:
            goto end;
    }

    ret = true;

end:
#endif
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)ds;
    (void)res;
    (void)bn;
#else
    GET_WHICH(1);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_submod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
        case    1:
            /* mp_submod_ct does not support negative numbers */
            CF_CHECK_NE(mp_cmp_d(bn[0].GetPtr(), 0), MP_LT);
            CF_CHECK_NE(mp_cmp_d(bn[1].GetPtr(), 0), MP_LT);
            CF_CHECK_NE(mp_cmp_d(bn[2].GetPtr(), 0), MP_LT);

            /* mp_submod_ct documentation states that:
             *
             * A < modulo
             * B < modulo
             */
            CF_CHECK_EQ(wolfCrypt_bignum_detail::compare(bn[0], bn[2], ds), MP_LT)
            CF_CHECK_EQ(wolfCrypt_bignum_detail::compare(bn[1], bn[2], ds), MP_LT)

            MP_CHECK_EQ(mp_submod_ct(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
        default:
            goto end;
    }

    ret = true;

end:
#endif
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    MP_CHECK_EQ(mp_sqrmod(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    std::optional<uint64_t> _bitPos;
#if defined(WOLFSSL_SP_MATH_ALL)
    unsigned int bitPos;
#else
    mp_digit bitPos;
#endif
    int isBitSet;

    CF_CHECK_NE(_bitPos = bn[1].AsUint64(), std::nullopt);

    bitPos = *_bitPos;
    /* Ensure no truncation has occurred */
    CF_CHECK_EQ(bitPos, *_bitPos);

    CF_CHECK_GTE(isBitSet = mp_is_bit_set(bn[0].GetPtr(), bitPos), 0);
    CF_CHECK_EQ( res.Set(isBitSet ? "1" : "0"), true);

    ret = true;

end:
#endif
    return ret;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool SetBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    std::optional<uint64_t> _bitPos;
    mp_digit bitPos;

    CF_CHECK_NE(_bitPos = bn[1].AsUint64(), std::nullopt);

    bitPos = *_bitPos;
    /* Ensure no truncation has occurred */
    CF_CHECK_EQ(bitPos, *_bitPos);

    MP_CHECK_EQ(mp_copy(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
    MP_CHECK_EQ(mp_set_bit(res.GetPtr(), bitPos), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool LCM::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
#if \
    defined(WOLFSSL_SP_MATH) || \
    (defined(WOLFSSL_SP_MATH_ALL) && \
        !(!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(WC_RSA_BLINDING)) \
    )
    (void)ds;
    (void)res;
    (void)bn;
    return false;
#else
    (void)ds;

    bool ret = false;

    /* mp_lcm does not support negative numbers */
    CF_CHECK_NE(mp_cmp_d(bn[0].GetPtr(), 0), MP_LT);
    CF_CHECK_NE(mp_cmp_d(bn[1].GetPtr(), 0), MP_LT);

    MP_CHECK_EQ(mp_lcm(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:
    return ret;
#endif
}

bool Mod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH(4);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_mod(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            break;
#if !defined(WOLFSSL_SP_MATH)
        case    1:
            {
                /* Input must not be negative */
                CF_CHECK_NE(mp_cmp_d(bn[0].GetPtr(), 0), MP_LT);

                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                mp_digit modResult;
                MP_CHECK_EQ(mp_mod_d(bn[0].GetPtr(), *op, &modResult), MP_OKAY);
                CF_CHECK_EQ(res.Set(std::to_string(modResult)), true);
            }
            break;
        case    2:
            {
                /* mp_div_2_mod_ct does not support negative numbers */
                CF_CHECK_NE(mp_cmp_d(bn[0].GetPtr(), 0), MP_LT);
                CF_CHECK_NE(mp_cmp_d(bn[0].GetPtr(), 0), MP_LT);

                /* bn[0] *= 2 */
                MP_CHECK_EQ(mp_mul_d(bn[0].GetPtr(), 2, bn.GetDestPtr(0)), MP_OKAY);

                CF_CHECK_EQ(wolfCrypt_bignum_detail::compare(bn[0], bn[1], ds), MP_LT)
                MP_CHECK_EQ(mp_div_2_mod_ct(bn[0].GetPtr(), bn[1].GetPtr(), bn.GetResPtr()), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
            }
            break;
        case    3:
            {
                mp_digit mp;
                wolfCrypt_bignum::Bignum tmp(ds);

                MP_CHECK_EQ(mp_montgomery_setup(bn[1].GetPtr(), &mp), MP_OKAY);
                MP_CHECK_EQ(mp_montgomery_calc_normalization(tmp.GetPtr(), bn[1].GetPtr()), MP_OKAY);
                MP_CHECK_EQ(mp_mulmod(bn[0].GetPtr(), tmp.GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
                MP_CHECK_EQ(mp_montgomery_reduce(res.GetPtr(), bn[1].GetPtr(), mp), MP_OKAY);
            }
            break;
#endif
#if !defined(WOLFSSL_SP_MATH) && (!defined(USE_FAST_MATH) || defined(WOLFSSL_SP_MATH_ALL))
        case    4:
            {
                std::optional<int> exponent = std::nullopt;

                /* Negative modulo not supported */
                CF_CHECK_NE(mp_cmp_d(bn[1].GetPtr(), 0), MP_LT);

                CF_CHECK_NE(exponent = wolfCrypt_bignum_detail::isPowerOf2(bn[1], ds), std::nullopt);

                MP_CHECK_EQ(mp_mod_2d(bn[0].GetPtr(), *exponent, bn.GetResPtr()), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
            }
            break;
#endif
        default:
            goto end;
    }

    ret = true;

end:
    return ret;
}

bool IsEven::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_iszero(bn[0].GetPtr()), false);

    CF_CHECK_EQ( res.Set( std::to_string(mp_iseven(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:

    return ret;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ( res.Set( std::to_string(mp_isodd(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:

    return ret;
}

bool MSB::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const int bit = mp_leading_bit(bn[0].GetPtr());

    CF_ASSERT(bit == 0 || bit == 1, "mp_leading_bit result is not one of (0, 1)");

    CF_CHECK_EQ( res.Set( std::to_string(bit) ), true);

    ret = true;

end:

    return ret;
}

bool NumBits::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const auto numBits = mp_count_bits(bn[0].GetPtr());

    CF_ASSERT(numBits >= 0, "mp_count_bits result is negative");

    CF_CHECK_EQ( res.Set( std::to_string(numBits) ), true);

    ret = true;

end:
    return ret;
}

bool Set::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH(3);
    switch ( which ) {
        case    0:
            MP_CHECK_EQ(mp_copy(bn[0].GetPtr(), bn.GetResPtr()), MP_OKAY);
            CF_CHECK_TRUE(bn.CopyResult(res));
            ret = true;
            break;
        case    1:
            {
                /* See ZD 16084 */
                CF_CHECK_LTE(mp_count_bits(bn[0].GetPtr()), DIGIT_BIT);

                const auto op = bn[0].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                MP_CHECK_EQ(mp_set(bn.GetResPtr(), *op), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
                ret = true;
            }
            break;
        case    2:
            {
                /* mp_exch alters the value of bn[0], so invalidate the cache. */
                bn.InvalidateCache();

                /* mp_exch always returns a value */
                MP_CHECK_EQ(mp_exch(bn.GetResPtr(), bn[0].GetPtr()), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));

                ret = true;
            }
            break;
        case    3:
            {
                const auto op = bn[0].AsUnsigned<unsigned long>();
                CF_CHECK_NE(op, std::nullopt);
                MP_CHECK_EQ(mp_set_int(bn.GetResPtr(), *op), MP_OKAY);
                CF_CHECK_TRUE(bn.CopyResult(res));
                ret = true;
            }
            break;
    }

end:
    return ret;
}

#if defined(HAVE_COMP_KEY) && !defined(WOLFSSL_SP_MATH)
  #define HAVE_MP_JACOBI 1
#endif

#if defined(HAVE_MP_JACOBI)
extern "C" {
int mp_jacobi(mp_int* a, mp_int* n, int* c);
}
#endif

bool Jacobi::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    (void)ds;

#if !defined(HAVE_MP_JACOBI)
    (void)res;
    (void)bn;
#else
    if ( mp_isodd(bn[1].GetPtr()) ) {
        int jacobi;
        MP_CHECK_EQ(mp_jacobi(bn[0].GetPtr(), bn[1].GetPtr(), &jacobi), MP_OKAY);

        switch ( jacobi ) {
            case    1:
                CF_CHECK_EQ( res.Set("1"), true);
                break;
            case    -1:
                CF_CHECK_EQ( res.Set("-1"), true);
                break;
            case    0:
                CF_CHECK_EQ( res.Set("0"), true);
                break;
            default:
                CF_ASSERT(0, "mp_jacobi result is not one of (-1, 0, 1)");
        }

        ret = true;
    }

end:
#endif

    return ret;
}

bool Exp2::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const auto exponent = bn[0].AsUnsigned<unsigned int>();
    CF_CHECK_NE(exponent, std::nullopt);
#if defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
    CF_CHECK_LT(*exponent / DIGIT_BIT, FP_SIZE);
#endif
    MP_CHECK_EQ(mp_2expt(bn.GetResPtr(), *exponent), MP_OKAY);
    CF_CHECK_TRUE(bn.CopyResult(res));

    ret = true;

end:

    return ret;
}

bool NumLSZeroBits::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if (defined(USE_FAST_MATH) && !defined(HAVE_COMP_KEY))
    (void)res;
    (void)bn;
#else
    const auto numBits = mp_cnt_lsb(bn[0].GetPtr());

    CF_ASSERT(numBits >= 0, "mp_cnt_lsb result is negative");

    CF_CHECK_EQ( res.Set( std::to_string(numBits) ), true);

    ret = true;

end:
#endif

    return ret;
}

bool CondSet::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const int doCopy = mp_iszero(bn[1].GetPtr()) ? 0 : 1;
    CF_CHECK_EQ(res.Set("0"), true);
    MP_CHECK_EQ(mp_cond_copy(bn[0].GetPtr(), doCopy, res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Rand::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    (void)bn;

    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            {
                const auto len = ds.Get<uint16_t>() % 512;
                MP_CHECK_EQ(mp_rand(res.GetPtr(), len, wolfCrypt_detail::GetRNG()), MP_OKAY);
                ret = true;
            }
            break;
        case    1:
            {
                const auto len = ds.Get<uint16_t>() % 100;
                MP_CHECK_EQ(mp_rand_prime(res.GetPtr(), len, wolfCrypt_detail::GetRNG(), nullptr), MP_OKAY);
                ret = true;
            }
            break;
    }

end:
    return ret;
}

bool Zero::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)bn;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            CF_NORET(mp_zero(res.GetPtr()));
            break;
        case    1:
            CF_NORET(mp_forcezero(res.GetPtr()));
            break;
    }

    return true;
}

bool Prime::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)bn;

    bool ret = false;

    uint16_t len = 2;
    try {
        /* Cap at 100; much larger will timeout */
        len = ds.Get<uint16_t>() % 100;
    } catch ( ... ) { }

    MP_CHECK_EQ(mp_rand_prime(res.GetPtr(), len, wolfCrypt_detail::GetRNG(), nullptr), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool IsPrime::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    int r;

    /* Prevent timeouts */
    CF_CHECK_LTE(mp_count_bits(bn[0].GetPtr()), 1000);

    /* Must be system RNG; otherwise the fuzzer will PRNG seeds that will
     * incorrectly regard a prime as composite.
     */
    CF_CHECK_EQ(mp_prime_is_prime_ex(bn[0].GetPtr(), 256, &r, wolfCrypt_detail::GetSystemRNG()), MP_OKAY);
    CF_CHECK_EQ( res.Set( std::to_string(r) ), true);

    ret = true;

end:
    return ret;
}


} /* namespace wolfCrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
