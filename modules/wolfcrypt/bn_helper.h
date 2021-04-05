#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/util.h>
#include <array>

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/ecc.h>
#if defined(WOLFSSL_SP_MATH)
 #include <wolfssl/wolfcrypt/sp.h>
#endif
}

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_bignum {

class Bignum {
    private:
        mp_int* mp = nullptr;
        Datasource& ds;
        bool noFree = false;

        typedef enum {
            READ_RADIX_OK,
            READ_RADIX_FAIL_MEMORY,
            READ_RADIX_FAIL_OTHER,
        } read_radix_error_t;

        static read_radix_error_t read_radix(mp_int* dest, const std::string& str, const size_t base);
        static read_radix_error_t read_radix(mp_int* dest, const char* str, const size_t base);
        void baseConversion(void) const;
        void binaryConversion(void) const;
    public:

        Bignum(Datasource& ds);
        Bignum(mp_int* mp, Datasource& ds);
        Bignum(const Bignum& other);
        Bignum(const Bignum&& other);
        ~Bignum();

        void SetNoFree(void);
        bool Set(const std::string s);
        bool Set(const component::Bignum i);
        mp_int* GetPtr(void) const;
        mp_int* GetPtrDirect(void) const;
        std::optional<uint64_t> AsUint64(void) const;

        template <class T>
        std::optional<T> AsUnsigned(void) const {
            std::optional<T> ret = std::nullopt;
            T v2;

            auto v = AsUint64();
            CF_CHECK_NE(v, std::nullopt);

            v2 = *v;
            CF_CHECK_EQ(v2, *v);

            ret = v2;

end:
            return ret;
        }

        std::optional<std::string> ToDecString(void);
        std::optional<component::Bignum> ToComponentBignum(void);
        bool ToBin(uint8_t* dest, const size_t size);
        static std::optional<std::vector<uint8_t>> ToBin(Datasource& ds, const component::Bignum b, std::optional<size_t> size = std::nullopt);
        static bool ToBin(Datasource& ds, const component::Bignum b, uint8_t* dest, const size_t size);
        static bool ToBin(Datasource& ds, const component::BignumPair b, uint8_t* dest, const size_t size);
        static std::optional<component::Bignum> BinToBignum(Datasource& ds, const uint8_t* src, const size_t size);
        static std::optional<component::BignumPair> BinToBignumPair(Datasource& ds, const uint8_t* src, const size_t size);
        bool operator==(const Bignum& rhs) const;
};

class BignumCluster {
    private:
        Datasource& ds;
        std::array<Bignum, 4> bn;

        struct {
            bool invalid = false;
            std::array<mp_int*, 4> bn = {0};
        } cache;
    public:
        BignumCluster(Datasource& ds, Bignum bn0, Bignum bn1, Bignum bn2, Bignum bn3);
        ~BignumCluster();
        Bignum& operator[](const size_t index);

        bool Set(const size_t index, const std::string s);
        mp_int* GetDestPtr(const size_t index);

        void Save(void);
        void InvalidateCache(void);
        bool EqualsCache(void) const;
};

} /* namespace wolfCrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
