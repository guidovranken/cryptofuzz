#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
extern "C" {
#include <tommath.h>
}

namespace cryptofuzz {
namespace module {
namespace libtommath_bignum {

class Bignum {
    private:
        mp_int mpi;
    public:

        Bignum(void) {
            if ( mp_init(&mpi) != MP_OKAY ) {
                throw std::exception();
            }
        }

        ~Bignum() {
            /* noret */ mp_clear(&mpi);
        }


        Bignum(const Bignum& other) {
            if ( mp_init(&mpi) != MP_OKAY ) {
                throw std::exception();
            }
            if ( mp_copy(&other.mpi, &mpi) != MP_OKAY ) {
                throw std::exception();
            }
        }

        Bignum(const Bignum&& other) {
            if ( mp_init(&mpi) != MP_OKAY ) {
                throw std::exception();
            }
            if ( mp_copy(&other.mpi, &mpi) != MP_OKAY ) {
                throw std::exception();
            }
        }

        bool Set(const std::string s) {
            bool ret = false;

            CF_CHECK_EQ(mp_read_radix(&mpi, s.c_str(), 10), MP_OKAY);

            ret = true;
end:
            return ret;
        }

        mp_int * GetPtr(void) {
            return &mpi;
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;
            char* str = nullptr;
            size_t size;

            //CF_CHECK_EQ(mp_radix_size(&mpi, 10, &size), MP_OKAY);
            size = 8192;

            str = (char*)malloc(size);

            CF_CHECK_EQ(mp_to_radix(&mpi, str, size, nullptr, 10), MP_OKAY);

            ret = { std::string(str) };
end:
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

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class LCM : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsEven : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsOdd : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class AddMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class SubMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class MulMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Sqrt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Neg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class And : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Or : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Xor : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

} /* namespace libtommath_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
