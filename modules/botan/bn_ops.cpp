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

    /* Exponent and modulus must be positive, according to the documentation */
    if ( bn[1] <= 0 || bn[2] <= 0 ) {
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

bool CmpAbs::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    std::vector<::Botan::BigInt> bnAbs = {bn[0].abs(), bn[1].abs()};
    auto cmp = std::make_unique<Cmp>();

    return cmp->Run(ds, res, bnAbs);
}

bool SetBit::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0];
    res.set_bit(bn[1].to_u32bit());

    return true;
}

bool Mod_NIST_192::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] % ::Botan::BigInt("6277101735386680763835789423207666416083908700390324961279");

    return true;
}

bool Mod_NIST_224::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] % ::Botan::BigInt("26959946667150639794667015087019630673557916260026308143510066298881");

    return true;
}

bool Mod_NIST_256::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] % ::Botan::BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951");

    return true;
}

bool Mod_NIST_384::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] % ::Botan::BigInt("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319");

    return true;
}

bool Mod_NIST_521::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0] % ::Botan::BigInt("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");

    return true;
}

bool ClearBit::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = bn[0];
    res.clear_bit(bn[1].to_u32bit());

    return true;
}

bool MulAdd::Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const {
    (void)ds;

    res = ::Botan::mul_add(bn[0], bn[1], bn[2]);

    return true;
}

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
