#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <integer.h>
#include <nbtheory.h>

namespace cryptofuzz {
namespace module {
namespace CryptoPP_bignum {

class Operation {
    public:
        virtual bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class MulMod : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class LCM : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Neg : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class IsEq : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class And : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Or : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Xor : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class IsEven : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class IsOdd : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class Bit : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class CmpAbs : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class SetBit : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

class ClearBit : public Operation {
    public:
        bool Run(Datasource& ds, ::CryptoPP::Integer& res, std::vector<::CryptoPP::Integer>& bn) const override;
};

} /* namespace CryptoPP_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
