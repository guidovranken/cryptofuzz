#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <botan/bigint.h>

namespace cryptofuzz {
namespace module {
namespace Botan_bignum {

class Operation {
    public:
        virtual bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class LCM : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class Neg : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class IsPrime : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class RShift : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class LShift1 : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

class IsEq : public Operation {
    public:
        bool Run(Datasource& ds, ::Botan::BigInt& res, std::vector<::Botan::BigInt>& bn) const override;
};

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
