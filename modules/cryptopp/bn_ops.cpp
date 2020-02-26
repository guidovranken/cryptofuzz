#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

namespace cryptofuzz {
namespace module {
namespace CryptoPP_bignum {

bool Add::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0] + bn[1];

    return true;
}

bool Sub::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0] - bn[1];

    return true;
}

bool Div::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0] / bn[1];

    return true;
}

bool Mul::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0] * bn[1];

    return true;
}

bool ExpMod::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    if ( bn[0] == 0 ) {
        return false;
    }
    if ( bn[1] == 0 ) {
        return false;
    }
    if ( bn[2] <= 1 ) {
        return false;
    }

    res = a_exp_b_mod_c(bn[0], bn[1], bn[2]);

    return true;
}

bool MulMod::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(bn[2], 0);
    res = a_times_b_mod_c(bn[0], bn[1], bn[2]);

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = (bn[0] % bn[1]).InverseMod(bn[1]);

    return true;
}

bool Cmp::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].Compare(bn[1]);

    return true;
}

bool Sqr::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].Squared();

    return true;
}

bool GCD::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = ::CryptoPP::GCD(bn[0], bn[1]);

    return true;
}

bool LCM::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = ::CryptoPP::LCM(bn[0], bn[1]);

    return true;
}

bool Jacobi::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(bn[1].IsNegative(), false);
    CF_CHECK_EQ(bn[1].IsOdd(), true);
    res = ::CryptoPP::Jacobi(bn[0], bn[1]);

    ret = true;
end:
    return ret;
}

bool Neg::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = -bn[0];

    return true;
}

bool IsNeg::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].IsNegative() ? 1 : 0;

    return true;
}

bool Abs::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].AbsoluteValue();

    return true;
}

bool IsEq::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0] == bn[1] ? 1 : 0;

    return true;
}

bool IsZero::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].IsZero() ? 1 : 0;

    return true;
}

bool And::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].And(bn[1]);

    return true;
}

bool Or::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].Or(bn[1]);

    return true;
}

bool Xor::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].Xor(bn[1]);

    return true;
}

bool IsEven::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].IsEven() ? 1 : 0;

    return true;
}

bool IsOdd::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].IsOdd() ? 1 : 0;

    return true;
}

bool SqrMod::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    res = bn[0].Squared() % bn[1];

    return true;
}

bool Bit::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;
    bool ret = false;

    signed long places;
    CF_CHECK_EQ(bn[1].IsConvertableToLong(), true);
    places = bn[1].ConvertToLong();

    res = bn[0].GetBit(places) ? 1 : 0;

    ret = true;
end:
    return ret;
}

bool CmpAbs::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    std::vector<::CryptoPP::Integer> bnAbs = {bn[0].AbsoluteValue(), bn[1].AbsoluteValue()};
    auto cmp = std::make_unique<Cmp>();

    return cmp->Run(ds, res, bnAbs);
}

namespace detail {
    bool SetBit(::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn, const bool value) {
        bool ret = false;

        signed long places;
        CF_CHECK_EQ(bn[1].IsConvertableToLong(), true);
        places = bn[1].ConvertToLong();

        res = bn[0];
        res.SetBit(places, value);

        ret = true;
end:
        return ret;
    }
}

bool SetBit::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    return detail::SetBit(res, bn, true);
}

bool ClearBit::Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const {
    (void)ds;

    return detail::SetBit(res, bn, false);
}

} /* namespace CryptoPP_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
