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

namespace detail {
    std::optional<size_t> To_size_t(const Bignum& bn) {
        /* TODO use #if */

        if ( sizeof(size_t) == 4 ) {
            try {
                return bn.ConstRef().to_u32bit();
            } catch ( ::Botan::Encoding_Error ) {
                return std::nullopt;
            }
        } else if ( sizeof(size_t) == 8 ) {
            if( bn.ConstRef().is_negative() ) {
                return std::nullopt;
            }

            if( bn.ConstRef().bits() > 64 ) {
                return std::nullopt;
            }

            uint64_t out = 0;

            for (size_t i = 0; i != 8; ++i) {
                out = (out << 8) | bn.ConstRef().byte_at(7-i);
            }

            return out;
        } else {
            CF_UNREACHABLE();
        }
    }
}

#if !defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
 #define GET_UINT8_FOR_SWITCH() ds.Get<uint8_t>()
#else
 #define GET_UINT8_FOR_SWITCH() 0
#endif /* CRYPTOFUZZ_BOTAN_IS_ORACLE */

#define APPLY_MODULO if (modulo != std::nullopt) res = (res.ConstRef() % modulo->ConstRef())

bool Add::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    res = bn[0].Ref() + bn[1].Ref();

    APPLY_MODULO;

    return true;
}

bool Sub::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    res = bn[0].Ref() - bn[1].Ref();

    APPLY_MODULO;

    return true;
}

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    res = bn[0].Ref() * bn[1].Ref();

    APPLY_MODULO;

    return true;
}

bool Div::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                CF_CHECK_TRUE(bn[1].Ref() != 0);
                res = ::Botan::ct_divide(bn[0].Ref(), bn[1].Ref());
                return true;
            case    1:
                {
                    CF_CHECK_TRUE(bn[1].Ref() != 0);
                    Bignum dummy;
                    /* noret */ ::Botan::vartime_divide(bn[0].Ref(), bn[1].Ref(), res.Ref(), dummy.Ref());
                }
                return true;
                /* TODO */
            case    2:
                {
                    CF_CHECK_TRUE(bn[1].Ref() != 0);
                    CF_CHECK_TRUE(bn[1].Ref() < 256);
                    ::Botan::word dummy;
                    CF_NORET(::Botan::ct_divide_word(bn[0].Ref(), bn[1].Ref().word_at(0), res.Ref(), dummy));
                }
                return true;
            case    3:
                /* / operator */
                res = bn[0].Ref() / bn[1].Ref();
                return true;
            case    4:
                /* /= operator */
                res = bn[0].Ref();
                res.Ref() /= bn[1].Ref();
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when divisor is 0 */
        if ( bn[1].Ref() == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

end:
    return false;
}

bool Mod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                {
                    try {
                        const Botan::Modular_Reducer reducer(bn[1].Ref());
                        res = reducer.reduce(bn[0].Ref());
                    } catch ( ::Botan::Invalid_State& e ) {
                        /* Modular reducer is expected to throw an exception when modulo is 0 */
                        if ( bn[1].Ref() == 0 ) {
                            return false;
                        }

                        /* Rethrow */
                        throw e;
                    }
                }
                return true;
            case    1:
                res = ct_modulo(bn[0].Ref(), bn[1].Ref());
                return true;
            case    2:
                /* % operator */
                res = bn[0].Ref() % bn[1].Ref();
                return true;
            case    3:
                /* %= operator */
                {
                    res = bn[0].Ref();

                    const ::Botan::word modulo = bn[1].Ref().word_at(0);

                    /* Ensure no truncation occurred */
                    if ( modulo != bn[1].Ref() ) {
                        return false;
                    }

                    res = bn[0].Ref() %= modulo;
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is <= 0 */
        if ( bn[1].Ref() <= 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return false;
}

bool Exp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    if ( modulo == std::nullopt ) {
        return false;
    }

    res = ::Botan::power_mod(bn[0].Ref(), bn[1].Ref(), modulo->ConstRef());

    return true;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    /* Exponent and modulus must be positive, according to the documentation */
    if ( bn[1].Ref() < 0 || bn[2].Ref() <= 0 ) {
        return false;
    }

    res = ::Botan::power_mod(bn[0].Ref(), bn[1].Ref(), bn[2].Ref());

    return true;
}

bool Sqr::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    res = ::Botan::square(bn[0].Ref());

    APPLY_MODULO;

    return true;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = ::Botan::gcd(bn[0].Ref(), bn[1].Ref());

    return true;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    if ( bn[1].Ref().is_negative() ) {
        return false;
    } else {
        try {
            switch ( GET_UINT8_FOR_SWITCH() ) {
                case    0:
                    {
                        try {
                            ::Botan::Modular_Reducer mod(bn[1].Ref());
                            res = mod.square(bn[0].Ref());
                        } catch ( ::Botan::Invalid_State& e ) {
                            /* Modular reducer is expected to throw an exception when modulo is 0 */
                            if ( bn[1].Ref() == 0 ) {
                                return false;
                            }

                            /* Rethrow */
                            throw e;
                        }
                    }
                    break;
                case    1:
                    res = ::Botan::square(bn[0].Ref()) % bn[1].Ref();
                    break;
                default:
                    return false;
            }
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
            return false;
        } catch ( ::Botan::Invalid_Argument& e ) {
            /* Botan is expected to throw an exception when modulo is 0 */
            if ( bn[1].Ref() == 0 ) {
                return false;
            }

            /* Rethrow */
            throw e;
        }
    }

    return true;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    const auto mod = modulo == std::nullopt ? bn[1].ConstRef() : modulo->ConstRef();

    try {
        res = ::Botan::inverse_mod(bn[0].Ref(), mod);
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* inverse_mod() is expected to throw an exception when modulo is 0 */
        if ( mod == 0 ) {
            return false;
        }

        /* inverse_mod() is expected to throw an exception when either argument is negative */
        if ( bn[0].Ref() < 0 || mod < 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    if ( bn[0].Ref() < bn[1].Ref() ) {
        res = Bignum("-1");
    } else if ( bn[0].Ref() > bn[1].Ref() ) {
        res = 1;
    } else {
        res = 0;
    }

    return true;
}

bool LCM::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    try {
        res = ::Botan::lcm(bn[0].Ref(), bn[1].Ref());
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* lcm() is expected to throw in these cases */
        if ( bn[0].Ref() == 0 || bn[1].Ref() == 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }


    return true;
}

bool Abs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = ::Botan::abs(bn[0].Ref());

    return true;
}

bool Jacobi::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;


    int resInt;

    try {
        resInt = ::Botan::jacobi(bn[0].Ref(), bn[1].Ref());
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* jacobi() is expected to throw in these cases */
        if ( (bn[1].Ref() % 2) == 0 || bn[1].Ref() <= 1 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    if ( resInt == -1 ) {
        res = Bignum("-1");
    } else {
        res = resInt;
    }

    return true;
}

bool Neg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = -bn[0].Ref();

    return true;
}

bool IsPrime::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */
    return false;
}

bool RShift::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    const auto count = detail::To_size_t(bn[1].Ref());

    if ( count == std::nullopt ) {
        return false;
    }

    Bignum toShift = bn[0];
    if ( modulo && bn[0].Ref() % 2 ) {
        toShift = toShift.Ref() + modulo->ConstRef();
    }

    res = toShift.Ref() >> *count;

    APPLY_MODULO;

    return true;
}

bool LShift1::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    res = bn[0].Ref() << 1;

    APPLY_MODULO;

    return true;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() < 0 ? 1 : 0;

    return true;
}

bool IsEq::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    auto A = modulo == std::nullopt ? bn[0] : bn[0].Ref() % modulo->ConstRef();
    auto B = modulo == std::nullopt ? bn[1] : bn[1].Ref() % modulo->ConstRef();

    res = A.Ref() == B.Ref() ? 1 : 0;

    return true;
}

bool IsGt::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() > bn[1].Ref() ? 1 : 0;

    return true;
}

bool IsGte::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() >= bn[1].Ref() ? 1 : 0;

    return true;
}

bool IsLt::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() < bn[1].Ref() ? 1 : 0;

    return true;
}

bool IsLte::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() <= bn[1].Ref() ? 1 : 0;

    return true;
}

bool IsEven::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = !(bn[0].Ref() % 2) ? 1 : 0;

    return true;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = (bn[0].Ref() % 2) ? 1 : 0;

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() == 0 ? 1 : 0;

    return true;
}

bool IsNotZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() == 0 ? 0 : 1;

    return true;
}

bool IsOne::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref() == 1 ? 1 : 0;

    return true;
}

bool MulMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                {
                    try {
                        ::Botan::Modular_Reducer mod(bn[2].Ref());
                        res = mod.multiply(bn[0].Ref(), bn[1].Ref());
                    } catch ( ::Botan::Invalid_State& e ) {
                        /* Modular reducer is expected to throw an exception when modulo is 0 */
                        if ( bn[2].Ref() == 0 ) {
                            return false;
                        }

                        /* Rethrow */
                        throw e;
                    }
                }
                break;
            case    1:
                res = (bn[0].Ref() * bn[1].Ref()) % bn[2].Ref();
                break;
            default:
                return false;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is <= 0 */
        if ( bn[2].Ref() <= 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool Bit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    const auto pos = detail::To_size_t(bn[1].Ref());

    if ( pos == std::nullopt ) {
        return false;
    }

    res = bn[0].Ref().get_bit(*pos) ? 1 : 0;

    return true;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    std::vector<Bignum> bnAbs = {bn[0].Ref().abs(), bn[1].Ref().abs()};
    auto cmp = std::make_unique<Cmp>();

    return cmp->Run(ds, res, bnAbs, modulo);
}

bool SetBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref();

    const auto pos = detail::To_size_t(bn[1].Ref());

    if ( pos == std::nullopt ) {
        return false;
    }

    res.Ref().set_bit(*pos);

    return true;
}

bool Mod_NIST_192::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    static const auto prime = ::Botan::prime_p192();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0].Ref() % Bignum("6277101735386680763835789423207666416083908700390324961279").Ref();
                return true;
            case    1:
                {
                    if ( bn[0].Ref() < 0 || bn[0].Ref() >= limit ) {
                        return false;
                    }
                    res = bn[0].Ref();
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p192(res.Ref(), ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0].Ref());
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_224::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    static const auto prime = ::Botan::prime_p224();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0].Ref() % Bignum("26959946667150639794667015087019630673557916260026308143510066298881").Ref();
                return true;
            case    1:
                {
                    if ( bn[0].Ref() < 0 || bn[0].Ref() >= limit ) {
                        return false;
                    }
                    res = bn[0].Ref();
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p224(res.Ref(), ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0].Ref());
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_256::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    static const auto prime = ::Botan::prime_p256();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0].Ref() % Bignum("115792089210356248762697446949407573530086143415290314195533631308867097853951").Ref();
                return true;
            case    1:
                {
                    if ( bn[0].Ref() < 0 || bn[0].Ref() >= limit ) {
                        return false;
                    }
                    res = bn[0].Ref();
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p256(res.Ref(), ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0].Ref());
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_384::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    static const auto prime = ::Botan::prime_p384();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0].Ref() % Bignum("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319").Ref();
                return true;
            case    1:
                {
                    if ( bn[0].Ref() < 0 || bn[0].Ref() >= limit ) {
                        return false;
                    }
                    res = bn[0].Ref();
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p384(res.Ref(), ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0].Ref());
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool Mod_NIST_521::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    static const auto prime = ::Botan::prime_p521();
    static const auto limit = prime * prime;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = bn[0].Ref() % Bignum("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151").Ref();
                return true;
            case    1:
                {
                    if ( bn[0].Ref() < 0 || bn[0].Ref() >= limit ) {
                        return false;
                    }
                    res = bn[0].Ref();
                    ::Botan::secure_vector<::Botan::word> ws;
                    CF_NORET(redc_p521(res.Ref(), ws));
                }
                return true;
            case    2:
                {
                    ::Botan::Modular_Reducer prime_redc(prime);
                    res = prime_redc.reduce(bn[0].Ref());
                }
                return true;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    }

    return false;
}

bool ClearBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref();

    const auto pos = detail::To_size_t(bn[1].Ref());

    if ( pos == std::nullopt ) {
        return false;
    }

    res.Ref().clear_bit(*pos);

    return true;
}

bool MulAdd::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = (bn[0].Ref()*bn[1].Ref()) + bn[2].Ref();

    return true;
}

bool Exp2::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    if ( bn[0].Ref() < 1 ) {
        return false;
    }

    const size_t exponent = bn[0].Ref().word_at(0) - 1;

    res = Bignum(2).Ref() << exponent;

    return true;
}

bool NumLSZeroBits::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = ::Botan::low_zero_bits(bn[0].Ref());

    return true;
}

bool Sqrt::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    try {
        const auto res2 = ::Botan::is_perfect_square(bn[0].Ref());
        if ( res2 == 0 ) {
            return false;
        }

        res = res2;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* is_perfect_square() is expected to throw in this case */
        if ( bn[0].Ref() < 1 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    APPLY_MODULO;

    return true;
}

bool AddMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = (bn[0].Ref() + bn[1].Ref()) % bn[2].Ref();
                break;
            case    1:
                {
                    if ( bn[0].Ref() >= bn[2].Ref() ) {
                        return false;
                    }
                    if ( bn[1].Ref() >= bn[2].Ref() ) {
                        return false;
                    }

                    ::Botan::secure_vector<::Botan::word> ws;
                    try {
                        res = bn[0].Ref().mod_add(bn[1].Ref(), bn[2].Ref(), ws);
                    } catch ( ::Botan::Invalid_Argument& e ) {
                        /* mod_add is expected to throw an exception when any argument is negative */
                        if ( bn[0].Ref() < 0 || bn[1].Ref() < 0 || bn[2].Ref() < 0) {
                            return false;
                        }

                        /* Rethrow */
                        throw e;
                    }
                }
                break;
            default:
                return false;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is <= 0 */
        if ( bn[2].Ref() <= 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool SubMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    try {
        switch ( GET_UINT8_FOR_SWITCH() ) {
            case    0:
                res = (bn[0].Ref() - bn[1].Ref()) % bn[2].Ref();
                break;
            case    1:
                {
                    if ( bn[0].Ref() >= bn[2].Ref() ) {
                        return false;
                    }
                    if ( bn[1].Ref() >= bn[2].Ref() ) {
                        return false;
                    }

                    ::Botan::secure_vector<::Botan::word> ws;
                    try {
                        res = bn[0].Ref().mod_sub(bn[1].Ref(), bn[2].Ref(), ws);
                    } catch ( ::Botan::Invalid_Argument& e ) {
                        /* mod_sub is expected to throw an exception when any argument is negative */
                        if ( bn[0].Ref() < 0 || bn[1].Ref() < 0 || bn[2].Ref() < 0) {
                            return false;
                        }

                        /* Rethrow */
                        throw e;
                    }
                }
                break;
            default:
                return false;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        return false;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Botan is expected to throw an exception when modulo is <= 0 */
        if ( bn[2].Ref() <= 0 ) {
            return false;
        }

        /* Rethrow */
        throw e;
    }

    return true;
}

bool NumBits::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    if ( modulo ) {
        res = (bn[0].Ref() % modulo->ConstRef()).bits();
    } else {
        res = bn[0].Ref().bits();
    }

    return true;
}

bool Set::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res = bn[0].Ref();

    APPLY_MODULO;

    return true;
}

bool CondSet::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)modulo;
    (void)ds;

    res.Ref().ct_cond_assign(bn[1].Ref() != 0, bn[0].Ref());

    return true;
}

bool Ressol::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    try {
        auto mod = modulo == std::nullopt ? bn[1] : *modulo;

        const auto r = ::Botan::ressol(bn[0].Ref(), mod.Ref());

        if ( r < 1 ) {
            if ( modulo != std::nullopt ) {
                res = 0;
                return true;
            } else {
                return false;
            }
        }

        if ( modulo != std::nullopt ) {
            res = ::Botan::square(r) % mod.Ref();
        }

        return true;
    } catch ( ::Botan::Invalid_Argument& e ) {
        /* Expected to throw if called with non-prime argument */

        return false;
    }
}

bool Not::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const {
    (void)ds;

    Bignum max;

    if ( modulo ) {
        max = *modulo;
    } else {
        const size_t numBits = bn[0].Ref().bits();

        if ( numBits == 0 ) {
            return false;
        }

        max = (::Botan::BigInt(1) << numBits) - 1;
    }

    res = max.Ref() - bn[0].Ref();

    APPLY_MODULO;

    return true;
}

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
