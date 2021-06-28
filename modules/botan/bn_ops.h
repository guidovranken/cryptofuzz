#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <botan/bigint.h>

#include "bn_helper.h"

namespace cryptofuzz {
namespace module {
namespace Botan_bignum {

class Operation {
    public:
        virtual bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Exp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class LCM : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Neg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsPrime : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class RShift : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class LShift1 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsEq : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsGt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsGte : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsLt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsLte : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsEven: public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsOdd: public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsNotZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class IsOne : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class MulMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Bit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class CmpAbs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class SetBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Mod_NIST_192 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Mod_NIST_224 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Mod_NIST_256 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Mod_NIST_384 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Mod_NIST_521 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class ClearBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class MulAdd : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Exp2 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class NumLSZeroBits : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Sqrt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class AddMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class SubMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class NumBits : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Set : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class CondSet : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Ressol : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

class Not : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, const std::optional<Bignum>& modulo) const override;
};

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
