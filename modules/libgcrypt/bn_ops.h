#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <gcrypt.h>
#include <array>

namespace cryptofuzz {
namespace module {
namespace libgcrypt_bignum {

class Bignum {
    private:
        gcry_mpi_t mpi = nullptr;
    public:

        Bignum(void) {
            mpi = gcry_mpi_new (1024 /* TODO dynamic */);
            /* TODO if mpi == nullptr */
            /* TODO secure memory */
        }

        ~Bignum() {
            /* noret */ gcry_mpi_release(mpi);
            mpi = nullptr;
        }

        Bignum(const Bignum& other) {
            mpi = gcry_mpi_copy(other.mpi);
        }

        Bignum(const Bignum&& other) {
            mpi = gcry_mpi_copy(other.mpi);
        }

        bool Set(const std::string s) {
            const auto sHex = util::DecToHex(s);
            bool ret = false;
            gcry_error_t err;
            gcry_mpi_t mpiNew;
            CF_CHECK_EQ(err = gcry_mpi_scan(&mpiNew, GCRYMPI_FMT_HEX, sHex.data(), 0, NULL), 0);
            /* noret */ gcry_mpi_release(mpi);
            mpi = mpiNew;

            ret = true;
end:
            return ret;
        }

        std::optional<std::string> ToString(void) {
            std::optional<std::string> ret = std::nullopt;
            gcry_error_t err;
            char *buf;

            CF_CHECK_EQ(err = gcry_mpi_aprint(GCRYMPI_FMT_HEX, (unsigned char**)&buf, NULL, mpi), 0);

            ret = util::HexToDec( std::string(buf) );

            gcry_free(buf);

end:
            return ret;
        }


        gcry_mpi_t GetPtr(void) const {
            return mpi;
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;
            const auto s = ToString();
            CF_CHECK_NE(s, std::nullopt);
            ret = { *s };
end:
            return ret;
        }

        inline bool operator==(const Bignum& rhs) const {
            return gcry_mpi_cmp(GetPtr(), rhs.GetPtr()) == 0;
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

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Cmp : public Operation {
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

class RShift : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class LShift1 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsEq : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class IsOne : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class MulMod : public Operation {
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

class Bit : public Operation {
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

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class NumBits : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Exp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

} /* namespace libgcrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
