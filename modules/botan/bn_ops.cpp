#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <botan/numthry.h>
#include <botan/reducer.h>

#include "bn_ops.h"

namespace cryptofuzz {
namespace module {
namespace Botan_bignum {

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

    res = bn[0] / bn[1];

    return true;
}

bool Mod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;
    res = bn[0] % bn[1];
    return true;
}

bool ExpMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

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

    if ( bn[0] == 0 || bn[1] == 0 ) {
        return false;
    }

    res = ::Botan::gcd(bn[0], bn[1]);

    return true;
}

bool SqrMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    if ( bn[0] == 0 ) {
        res = ::Botan::square(bn[0]);
    } else if ( bn[1].is_negative() ) {
        res = 0;
    } else {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                {
                    ::Botan::Modular_Reducer mod(bn[1]);
                    res = mod.square(bn[0]);
                }
                break;
            case    1:
                res = ::Botan::square(bn[0]) % bn[1];
                break;
            default:
                return false;
        }
    }

    return true;
}

bool InvMod::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = ::Botan::inverse_mod(bn[0], bn[1]);

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

    const int resInt = ::Botan::jacobi(bn[0], bn[1]);
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

    res = bn[0] >> bn[1].to_u32bit();

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
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            {
                ::Botan::Modular_Reducer mod(bn[2]);
                res = mod.multiply(bn[0], bn[1]);
            }
            break;
        case    1:
            res = (bn[0] * bn[1]) % bn[2];
            break;
        default:
            return false;
    }

    return true;
}

bool Bit::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0].get_bit(bn[1].to_u32bit()) ? 1 : 0;

    return true;
}

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
