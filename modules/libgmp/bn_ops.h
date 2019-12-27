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

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;

            char* str = mpz_get_str(nullptr, 10, mp);
            ret = { std::string(str) };
            free(str);

            return ret;
        }
};

class Operation {
    public:
        virtual bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class LCM : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Xor : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class And : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Neg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

} /* namespace libgmp_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
