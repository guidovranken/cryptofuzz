#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <gmp.h>

namespace cryptofuzz {
namespace module {
namespace libgmp_bignum {

class Bignum {
    private:
        mpz_t mp;
    public:

        Bignum(void) {
            /* noret */ mpz_init(mp);
        }

        ~Bignum() {
            /* noret */ mpz_clear(mp);
        }

        bool Set(const std::string s) {
            bool ret = false;

            CF_CHECK_EQ(mpz_set_str(mp, s.c_str(), 10), 0);

            ret = true;
end:
            return ret;
        }

        mpz_ptr GetPtr(void) {
            return mp;
        }

        std::optional<signed long> GetSignedLong(void) {
            std::optional<signed long> ret = std::nullopt;

            CF_CHECK_EQ(mpz_fits_slong_p(GetPtr()), 1);

            ret = mpz_get_si(GetPtr());
end:
            return ret;
        }

        std::optional<unsigned long int> GetUnsignedLong(void) {
            std::optional<unsigned long int> ret = std::nullopt;

            CF_CHECK_EQ(mpz_fits_ulong_p(GetPtr()), 1);

            ret = mpz_get_ui(GetPtr());
end:
            return ret;
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;

            char* str = mpz_get_str(nullptr, 10, mp);
            ret = { std::string(str) };
            free(str);

            return ret;
        }

        inline bool operator==(const Bignum& rhs) {
            return mpz_cmp(mp, rhs.mp) == 0;
        }
};

class BignumCluster {
    private:
        Datasource& ds;
        std::array<Bignum, 4> bn;
    public:
        BignumCluster(Datasource& ds, Bignum bn0, Bignum bn1, Bignum bn2, Bignum bn3) :
            ds(ds),
            bn({bn0, bn1, bn2, bn3})
        { }

        Bignum& operator[](const size_t index) {
            if ( index >= bn.size() ) {
                abort();
            }

            try {
                /* Rewire? */
                if ( ds.Get<bool>() == true ) {
                    /* Pick a random bignum */
                    const size_t newIndex = ds.Get<uint8_t>() % 4;

                    /* Same value? */
                    if ( bn[newIndex] == bn[index] ) {
                        /* Then return reference to other bignum */
                        return bn[newIndex];
                    }

                    /* Fall through */
                }
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

            return bn[index];
        }

        Bignum& Get(const size_t index) {
            if ( index >= bn.size() ) {
                abort();
            }

            return bn[index];
        }

        bool Set(const size_t index, const std::string s) {
            if ( index >= bn.size() ) {
                abort();
            }

            return bn[index].Set(s);
        }

        mpz_ptr GetDestPtr(const size_t index) {
            return bn[index].GetPtr();
        }
};

class Operation {
    public:
        virtual bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class ExtGCD_X : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class ExtGCD_Y : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class LCM : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Xor : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class And : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Neg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Sqrt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class CmpAbs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class AddMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class SubMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class MulMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Mod_NIST_192 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Mod_NIST_224: public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Mod_NIST_256 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Mod_NIST_384 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Mod_NIST_521 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class SetBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class ClearBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Bit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsOdd : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsEven : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsPow2 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class NumLSZeroBits : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Factorial : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Cbrt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class SqrtRem : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class CbrtRem : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Nthrt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class NthrtRem : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsSquare : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Exp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Or : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class AddMul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class SubMul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Primorial : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Lucas : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Fibonacci : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Set : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class BinCoeff : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class HamDist : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsPower : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

} /* namespace libgmp_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
