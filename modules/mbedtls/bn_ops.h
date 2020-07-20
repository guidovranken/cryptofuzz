#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <mbedtls/bignum.h>

namespace cryptofuzz {
namespace module {
namespace mbedTLS_bignum {

class Bignum {
    private:
        mbedtls_mpi mpi;
    public:

        Bignum(void) {
            /* noret */ mbedtls_mpi_init(&mpi);
        }

        ~Bignum() {
            /* noret */ mbedtls_mpi_free(&mpi);
        }

        bool Set(const std::string s) {
            bool ret = false;

            CF_CHECK_EQ(mbedtls_mpi_read_string(&mpi, 10, s.c_str()), 0);

            ret = true;
end:
            return ret;
        }

        mbedtls_mpi* GetPtr(void) {
            return &mpi;
        }

        std::optional<uint32_t> GetUint32(void) {
            std::optional<uint32_t> ret = std::nullopt;
            uint32_t out;

            /* Must not be negative */
            CF_CHECK_NE(mbedtls_mpi_cmp_int(GetPtr(), -1), 0);

            /* XXX use mbedtls_mpi_write_binary on big endian systems */
            CF_CHECK_EQ(mbedtls_mpi_write_binary_le(GetPtr(), (unsigned char*)&out, sizeof(out)), 0);

            ret = out;

end:
            return ret;
        }

        std::optional<int32_t> GetInt32(void) {
            std::optional<int32_t> ret = std::nullopt;
            std::optional<uint32_t> u32 = GetUint32();
            CF_CHECK_NE(u32, std::nullopt);
            CF_CHECK_EQ(*u32 & 0x80000000, 0);
            ret = (int64_t)(*u32);

end:
            return ret;
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;
            char* str = nullptr;
            size_t olen;

            CF_CHECK_EQ(mbedtls_mpi_write_string(&mpi, 10, nullptr, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);

            str = (char*)malloc(olen);

            CF_CHECK_EQ(mbedtls_mpi_write_string(&mpi, 10, str, olen, &olen), 0);

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

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Cmp : public Operation {
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

class RShift : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class LShift1 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsEq : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsOne : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class MulMod : public Operation {
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

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Bit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class CmpAbs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class SetBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class ClearBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

} /* namespace mbedTLS_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
