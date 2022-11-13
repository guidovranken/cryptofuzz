#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <mbedtls/bignum.h>
#include <array>
#include <limits>

namespace cryptofuzz {
namespace module {
namespace mbedTLS_bignum {

class Bignum {
    private:
        Datasource& ds;
        mbedtls_mpi mpi;
        void convert(void) {
            bool write_bin = false;
            uint16_t size = 0;

            try {
                write_bin = ds.Get<bool>();
                if ( write_bin == true ) {
                    size = ds.Get<uint16_t>();
                }
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

            if ( write_bin == true ) {
                uint8_t* out = util::malloc(size);
                /* ignore ret */ mbedtls_mpi_write_binary(&mpi, out, size);
                util::free(out);
            }

        }
    public:

        Bignum(fuzzing::datasource::Datasource& ds) :
            ds(ds) {
            CF_NORET(mbedtls_mpi_init(&mpi));
        }

        ~Bignum() {
            CF_NORET(mbedtls_mpi_free(&mpi));
        }

        bool Set(const std::string s) {
            bool ret = false;

            CF_CHECK_EQ(mbedtls_mpi_read_string(&mpi, 10, s.c_str()), 0);

            ret = true;
end:
            return ret;
        }

        const mbedtls_mpi* GetPtrConst(void) const {
            return &mpi;
        }

        mbedtls_mpi* GetDestPtr(void) {
            return &mpi;
        }

        const mbedtls_mpi* GetPtr(void) {
            CF_NORET(convert());
            return &mpi;
        }

        std::optional<uint32_t> GetUint32(void) {
            std::optional<uint32_t> ret = std::nullopt;
            uint32_t out;

            /* Must not be negative */
            CF_CHECK_NE(mbedtls_mpi_cmp_int(GetPtr(), 0), -1);

            /* XXX use mbedtls_mpi_write_binary on big endian systems */
            CF_CHECK_EQ(mbedtls_mpi_write_binary_le(GetPtr(), (unsigned char*)&out, sizeof(out)), 0);

            ret = out;

end:
            return ret;
        }

        std::optional<mbedtls_mpi_sint> To_mbedtls_mpi_sint(void) {
            std::optional<mbedtls_mpi_sint> ret = std::nullopt;
            mbedtls_mpi_sint r;
            CF_CHECK_GTE(mbedtls_mpi_cmp_int(GetPtr(),
                        std::numeric_limits<mbedtls_mpi_sint>::min()
                        /* Prevent UB: https://github.com/Mbed-TLS/mbedtls/issues/6597 */
                        + 1
            ), 0);
            CF_CHECK_LTE(mbedtls_mpi_cmp_int(GetPtr(), std::numeric_limits<mbedtls_mpi_sint>::max()), 0);
            CF_CHECK_EQ(mbedtls_mpi_write_binary_le(GetPtr(), (unsigned char*)&r, sizeof(r)), 0);
            if ( mbedtls_mpi_cmp_int(GetPtr(), 0) < 0 ) {
                r = -r;
            }
            ret = r;
end:
            return ret;
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;
            char* str = nullptr;
            size_t olen;

            CF_CHECK_EQ(mbedtls_mpi_write_string(&mpi, 16, nullptr, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);

            str = (char*)malloc(olen);

            CF_CHECK_EQ(mbedtls_mpi_write_string(&mpi, 16, str, olen, &olen), 0);

            if ( strcmp(str, "-00") == 0 ) {
                ret = std::string("0");
            } else {
                ret = { util::HexToDec(str) };
            }
end:
            free(str);

            return ret;
        }

        inline bool operator==(const Bignum& rhs) const {
            return mbedtls_mpi_cmp_mpi(GetPtrConst(), rhs.GetPtrConst()) == 0;
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

class Sqr : public Operation {
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

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class Bit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class CmpAbs : public Operation {
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

class Set : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

class NumLSZeroBits : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn) const override;
};

} /* namespace mbedTLS_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
