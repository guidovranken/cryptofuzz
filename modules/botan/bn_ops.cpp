#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/divide.h>
#include <botan/internal/curve_nistp.h>

#include "bn_ops.h"

namespace cryptofuzz {
namespace module {
namespace Botan_bignum {

#if !defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
 #define GET_UINT8_FOR_SWITCH() ds.Get<uint8_t>()
#else
 #define GET_UINT8_FOR_SWITCH() 0
#endif /* CRYPTOFUZZ_BOTAN_IS_ORACLE */

bool Add::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] + bn[1];

    return true;
}

bool Sub::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] - bn[1];

    return true;
}

bool Mul::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] * bn[1];

    return true;
}

bool Div::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                CF_CHECK_TRUE(bn[1] != 0);
                res = ::Botan::ct_divide(bn[0], bn[1]);
                return true;
            case    1:
                {
                    CF_CHECK_TRUE(bn[1] != 0);
                    ::Botan::BigInt dummy;
                    /* noret */ ::Botan::vartime_divide(bn[0], bn[1], res, dummy);
                }
                return true;
            case    2:
                {
                    CF_CHECK_TRUE(bn[1] != 0);
                    CF_CHECK_TRUE(bn[1] < 256);
                    uint8_t dummy;
                    /* noret */ ::Botan::ct_divide_u8(bn[0], bn[1].byte_at(0), res, dummy);
                }
                return true;
            case    3:
                /* / operator */
                res = bn[0] / bn[1];
                return true;
            case    4:
                /* /= operator */
                res = bn[0];
                res /= bn[1];
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when divisor is 0 */
        if ( bn[1] == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

end:
    return false;
}

bool Mod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                {
                    try {
                        const Botan::Modular_Reducer reducer(bn[1]);
                        res = reducer.reduce(bn[0]);
                    } catch ( ::Botan::Invalid_State& e ) {
                        /* Modular reducer is expected to throw an exception when modulo is 0 */
                        if ( bn[1] == 0 ) {
                            return false;
                        }

                        /* Rethrow */
                        throw e;
                    }
                }
                return true;
            case    1:
                res = ct_modulo(bn[0], bn[1]);
                return true;
            case    2:
                /* % operator */
                res = bn[0] % bn[1];
                return true;
            case    3:
                /* %= operator */
                {
                    res = bn[0];

                    const ::Botan::word modulo = bn[1].word_at(0);

                    /* Ensure no truncation occurred */
                    if ( modulo != bn[1] ) {
                        return false;
                    }

                    res = bn[0] %= modulo;
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is 0 */
        if ( bn[1] == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return false;
}

bool ExpMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    /* Exponent and modulus must be positive, according to the documentation */
    if ( bn[1] < 0 || bn[2] <= 0 ) {
        return false;
    }

    res = ::Botan::power_mod(bn[0], bn[1], bn[2]);

    return true;
}

bool Sqr::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = ::Botan::square(bn[0]);

    return true;
}

bool GCD::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = ::Botan::gcd(bn[0], bn[1]);

    return true;
}

bool SqrMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    if ( bn[1].is_negative() ) {
        return false;
    } else {
        try {
            switch ( GET_UINT8_FOR_SWITCH() ) {
                case    0:
                    {
                        try {
                            ::Botan::Modular_Reducer mod(bn[1]);
                            res = mod.square(bn[0]);
                        } catch ( ::Botan::Invalid_State& e ) {
                            /* Modular reducer is expected to throw an exception when modulo is 0 */
                            if ( bn[1] == 0 ) {
                                return false;
                            }

                            /* Rethrow */
                            throw e;
                        }
                    }
                    break;
                case    1:
                    res = ::Botan::square(bn[0]) % bn[1];
                    break;
                default:
                    return false;
            }
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
            return false;
        } catch ( ::Botan::Invalid_Argument& e ) {
            /* Botan is expected to throw an exception when modulo is 0 */
            if ( bn[1] == 0 ) {
                return false;
            }

            /* Rethrow */
            throw e;
        }
    }

    return true;
}

bool InvMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    try {
        res = ::Botan::inverse_mod(bn[0], bn[1]);
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* inverse_mod() is expected to throw an exception when modulo is 0 */
        if ( bn[1] == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool Cmp::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    if ( bn[0] < bn[1] ) {
        res = ::Botan::BigInt("-1");
    } else if ( bn[0] > bn[1] ) {
        res = 1;
    } else {
        res = 0;
    }

    return true;
}

bool LCM::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = ::Botan::lcm(bn[0], bn[1]);

    return true;
}

bool Abs::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = ::Botan::abs(bn[0]);

    return true;
}

bool Jacobi::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;


    int resInt;

    try {
        resInt = ::Botan::jacobi(bn[0], bn[1]);
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* jacobi() is expected to throw in these cases */
        if ( (bn[1] % 2) == 0 || bn[1] <= 1 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    if ( resInt == -1 ) {
        res = ::Botan::BigInt("-1");
    } else {
        res = resInt;
    }

    return true;
}

bool Neg::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = -bn[0];

    return true;
}

bool IsPrime::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */
    return false;
}

bool RShift::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    uint32_t count;
    try {
        count = bn[1].to_u32bit();
    } catch ( ::Botan::Encoding_Error ) {
        /* to_u32bit will throw if value doesn't fit in u32 */
        return false;
    }

    res = bn[0] >> count;

    return true;
}

bool LShift1::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] << 1;

    return true;
}

bool IsNeg::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] < 0 ? 1 : 0;

    return true;
}

bool IsEq::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] == bn[1] ? 1 : 0;

    return true;
}

bool IsGt::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] > bn[1] ? 1 : 0;

    return true;
}

bool IsGte::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] >= bn[1] ? 1 : 0;

    return true;
}

bool IsLt::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] < bn[1] ? 1 : 0;

    return true;
}

bool IsLte::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] <= bn[1] ? 1 : 0;

    return true;
}

bool IsEven::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = !(bn[0] % 2) ? 1 : 0;

    return true;
}

bool IsOdd::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = (bn[0] % 2) ? 1 : 0;

    return true;
}

bool IsZero::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] == 0 ? 1 : 0;

    return true;
}

bool IsOne::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] == 1 ? 1 : 0;

    return true;
}

bool MulMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                {
                    try {
                        ::Botan::Modular_Reducer mod(bn[2]);
                        res = mod.multiply(bn[0], bn[1]);
                    } catch ( ::Botan::Invalid_State& e ) {
                        /* Modular reducer is expected to throw an exception when modulo is 0 */
                        if ( bn[2] == 0 ) {
                            return false;
                        }

                        /* Rethrow */
                        throw e;
                    }
                }
                break;
            case    1:
                res = (bn[0] * bn[1]) % bn[2];
                break;
            default:
                return false;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is 0 */
        if ( bn[2] == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool Bit::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    uint32_t pos;
    try {
        pos  = bn[1].to_u32bit();
    } catch ( ::Botan::Encoding_Error ) {
        /* to_u32bit will throw if value doesn't fit in u32 */
        return false;
    }

    res = bn[0].get_bit(pos) ? 1 : 0;

    return true;
}

bool CmpAbs::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    std::vector<::Botan::BigInt> bnAbs = {bn[0].abs(), bn[1].abs()};
    auto cmp = std::make_unique<Cmp>();

    return cmp->Run(ds, res, bnAbs);
}

bool SetBit::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0];

    uint32_t pos;
    try {
        pos  = bn[1].to_u32bit();
    } catch ( ::Botan::Encoding_Error ) {
        /* to_u32bit will throw if value doesn't fit in u32 */
        return false;
    }

    res.set_bit(pos);

    return true;
}

bool Mod_NIST_192::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    static const auto prime = ::Botan::prime_p192();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0] % ::Botan::BigInt("6277101735386680763835789423207666416083908700390324961279");
                return true;
            case    1:
                {
                    if( bn[0] >= limit ) {
                        return false;
                    }
                    res = bn[0];
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p192(res, ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0]);
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_224::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    static const auto prime = ::Botan::prime_p224();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0] % ::Botan::BigInt("26959946667150639794667015087019630673557916260026308143510066298881");
                return true;
            case    1:
                {
                    if( bn[0] >= limit ) {
                        return false;
                    }
                    res = bn[0];
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p224(res, ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0]);
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_256::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    static const auto prime = ::Botan::prime_p256();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0] % ::Botan::BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951");
                return true;
            case    1:
                {
                    if( bn[0] >= limit ) {
                        return false;
                    }
                    res = bn[0];
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p256(res, ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0]);
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_384::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    static const auto prime = ::Botan::prime_p384();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0] % ::Botan::BigInt("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319");
                return true;
            case    1:
                {
                    if( bn[0] >= limit ) {
                        return false;
                    }
                    res = bn[0];
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p384(res, ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0]);
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_521::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    static const auto prime = ::Botan::prime_p521();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0] % ::Botan::BigInt("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");
                return true;
            case    1:
                {
                    if( bn[0] >= limit ) {
                        return false;
                    }
                    res = bn[0];
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p521(res, ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0]);
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool ClearBit::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0];

    uint32_t pos;
    try {
        pos  = bn[1].to_u32bit();
    } catch ( ::Botan::Encoding_Error ) {
        /* to_u32bit will throw if value doesn't fit in u32 */
        return false;
    }

    res.clear_bit(pos);

    return true;
}

bool MulAdd::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = (bn[0]*bn[1]) + bn[2];

    return true;
}

bool Exp2::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    if ( bn[0] < 1 ) {
        return false;
    }

    const size_t exponent = bn[0].word_at(0) - 1;

    res = ::Botan::BigInt(2) << exponent;

    return true;
}

bool NumLSZeroBits::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = ::Botan::low_zero_bits(bn[0]);

    return true;
}

bool Sqrt::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    try {
        const auto res2 = ::Botan::is_perfect_square(bn[0]);
        if ( res2 == 0 ) {
            return false;
        }

        res = res2;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* is_perfect_square() is expected to throw in this case */
        if ( bn[0] < 1 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }


    return true;
}

bool AddMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = (bn[0] + bn[1]) % bn[2];
                break;
            case    1:
                {
                    if ( bn[0] >= bn[2] ) {
                        return false;
                    }
                    if ( bn[1] >= bn[2] ) {
                        return false;
                    }

                    ::Botan::secure_vector<::Botan::word> ws;
                    res = bn[0].mod_add(bn[1], bn[2], ws);
                }
                break;
            default:
                return false;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is 0 */
        if ( bn[2] == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool SubMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = (bn[0] - bn[1]) % bn[2];
                break;
            case    1:
                {
                    if ( bn[0] >= bn[2] ) {
                        return false;
                    }
                    if ( bn[1] >= bn[2] ) {
                        return false;
                    }

                    ::Botan::secure_vector<::Botan::word> ws;
                    res = bn[0].mod_sub(bn[1], bn[2], ws);
                }
                break;
            default:
                return false;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is 0 */
        if ( bn[2] == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool NumBits::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0].bits();

    return true;
}

bool Set::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0];

    return true;
}

bool CondSet::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res.ct_cond_assign(bn[1] != 0, bn[0]);

    return true;
}

bool Ressol::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    return false;
#if 0
    res = ::Botan::ressol(bn[0], bn[1]);

    return true;
#endif
}

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
