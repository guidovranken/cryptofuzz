#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#if defined(CRYPTOFUZZ_BORINGSSL)
#include <openssl/mem.h>
#endif
#include <array>

namespace cryptofuzz {
namespace module {
namespace OpenSSL_bignum {

class Bignum {
    private:
        BIGNUM* bn = nullptr;
        Datasource& ds;
        bool locked = false;
        bool noFree = false;
    public:
        Bignum(Datasource& ds) :
            ds(ds)
    { }

        ~Bignum() {
            if ( noFree == false ) {
                BN_free(bn);
            }
        }

        void Lock(void) {
            locked = true;
        }

        void DisableFree(void) {
            noFree = true;
        }

        void ReleaseOwnership(void) {
            Lock();
            DisableFree();
        }

        bool New(void) {
            CF_ASSERT(locked == false, "Cannot renew locked Bignum");

            BN_free(bn);
            bn = BN_new();

            return bn != nullptr;
        }

        bool Set(Bignum& other) {
            bool ret = false;

            CF_CHECK_NE(BN_copy(bn, other.GetPtr()), NULL);

            ret = true;
end:
            return ret;
        }

        bool Set(const std::string s) {
            CF_ASSERT(locked == false, "Cannot set locked Bignum");

            bool ret = false;

            CF_CHECK_NE(BN_dec2bn(&bn, s.c_str()), 0);

            ret = true;
end:
            return ret;
        }

        std::optional<uint64_t> AsUint64(void) const {
            std::optional<uint64_t> ret = std::nullopt;
            try {
                switch ( ds.Get<uint8_t>() ) {
                    case    0:
#if !defined(CRYPTOFUZZ_LIBRESSL)
                        {
                            /* BN_bn2binpad is not supported by LibreSSL */

                            uint64_t v;

                            CF_CHECK_LTE(BN_num_bytes(bn), (int)sizeof(uint64_t));
                            CF_CHECK_NE(BN_bn2binpad(bn, (unsigned char*)&v, sizeof(v)), -1);

                            /* Manual reversing is required because
                             * BN_bn2lebinpad is not supported by BoringSSL.
                             *
                             * TODO This must be omitted on big-endian platforms.
                             */
                            v =
                                ((v & 0xFF00000000000000) >> 56) |
                                ((v & 0x00FF000000000000) >> 40) |
                                ((v & 0x0000FF0000000000) >> 24) |
                                ((v & 0x000000FF00000000) >>  8) |
                                ((v & 0x00000000FF000000) <<  8) |
                                ((v & 0x0000000000FF0000) << 24) |
                                ((v & 0x000000000000FF00) << 40) |
                                ((v & 0x00000000000000FF) << 56);

                            ret = v;
                        }
#endif
                        break;
                    case    1:
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL)
                        {
                            ASN1_INTEGER* asn1 = nullptr;
                            uint64_t v;

                            CF_CHECK_NE( (asn1 = BN_to_ASN1_INTEGER(bn, nullptr)), nullptr);
                            const auto r = ASN1_INTEGER_get_uint64(&v, asn1);
                            ASN1_INTEGER_free(asn1);
                            CF_CHECK_EQ(r, 1);

                            ret = v;
                        }
#endif
                        break;
                    default:
                        break;

                }
            } catch ( ... ) { }

            /* Silence compiler */
            goto end;
end:
            return ret;
        }

        std::optional<int> AsInt(void) const {
            std::optional<int> ret = std::nullopt;
            const auto u64 = AsUint64();

            CF_CHECK_NE(u64, std::nullopt);
            CF_CHECK_LTE(*u64, 2147483647);

            ret = *u64;
end:
            return ret;
        }

        std::optional<BN_ULONG> AsBN_ULONG(void) const {
            std::optional<BN_ULONG> ret;
            std::optional<uint64_t> v64;

            /* Convert bn[1] to uint64_t if possible */
            CF_CHECK_NE(v64 = AsUint64(), std::nullopt);

            /* Try to convert the uint64_t to BN_ULONG */
            BN_ULONG vul;
            CF_CHECK_EQ(vul = *v64, *v64);

            ret = vul;
end:
            return ret;
        }

        void SetUint32(const uint32_t v) {
            /* Gnarly but it works for now */

            char s[1024];
            if ( sprintf(s, "%u", v) < 0 ) {
                abort();
            }

            if ( Set(s) == false ) {
                abort();
            }
        }

        BIGNUM* GetDestPtr(const bool allowDup = true) {
            if ( locked == false ) {
                try {
                    {
                        const bool changeConstness = ds.Get<bool>();
                        if ( changeConstness == true ) {
#if !defined(CRYPTOFUZZ_BORINGSSL)
                            const bool constness = ds.Get<bool>();

                            if ( constness == true ) {
                                /* noret */ BN_set_flags(bn, BN_FLG_CONSTTIME);
                            } else {
                                /* noret */ BN_set_flags(bn, 0);
                            }
#endif
                        }
                    }

                    {
                        if ( allowDup == true ) {
                            const bool dup = ds.Get<bool>();

                            if ( dup == true ) {
                                BIGNUM* tmp = BN_dup(bn);
                                if ( tmp != nullptr ) {
                                    BN_free(bn);
                                    bn = tmp;
                                }
                            }
                        }
                    }

                    {
                        if ( allowDup == true ) {
                            const bool asn1Convert = ds.Get<bool>();

                            if ( asn1Convert == true ) {
                                ASN1_INTEGER* asn1 = BN_to_ASN1_INTEGER(bn, nullptr);

                                if ( asn1 != nullptr ) {
                                    BIGNUM* tmp = ASN1_INTEGER_to_BN(asn1, nullptr);

                                    if ( tmp != nullptr ) {
                                        BN_free(bn);
                                        bn = tmp;
                                    }

                                    ASN1_INTEGER_free(asn1);
                                }
                            }
                        }
                    }

                    {
                        if ( allowDup == true ) {
                            const bool asn1Convert = ds.Get<bool>();

                            if ( asn1Convert == true ) {
                                ASN1_ENUMERATED* asn1 = BN_to_ASN1_ENUMERATED(bn, nullptr);

                                if ( asn1 != nullptr ) {
                                    BIGNUM* tmp = ASN1_ENUMERATED_to_BN(asn1, nullptr);

                                    if ( tmp != nullptr ) {
                                        BN_free(bn);
                                        bn = tmp;
                                    }

                                    ASN1_ENUMERATED_free(asn1);
                                }
                            }
                        }
                    }
                } catch ( ... ) { }
            }

            return bn;
        }

        BIGNUM* GetPtrConst(void) const {
            return bn;
        }

        const BIGNUM* GetPtr(const bool allowDup = true) {
            return GetDestPtr(allowDup);
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;

            char* str = nullptr;

            bool hex = true;
            try { hex = ds.Get<bool>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

            if ( hex == true ) {
                CF_CHECK_NE(str = BN_bn2hex(GetPtr()), nullptr);
                ret = { util::HexToDec(str) };
            } else {
                CF_CHECK_NE(str = BN_bn2dec(GetPtr()), nullptr);
                ret = { std::string(str) };
            }
end:
            OPENSSL_free(str);

            return ret;
        }

        std::optional<std::string> ToString(void) {
            std::optional<std::string> ret = std::nullopt;

            char* str = nullptr;

            CF_CHECK_NE(str = BN_bn2dec(GetPtr()), nullptr);
            ret = { std::string(str) };
end:
            OPENSSL_free(str);

            return ret;
        }

        inline bool operator==(const Bignum& rhs) const {
            return BN_cmp(GetPtrConst(), rhs.GetPtrConst()) == 0;
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
            CF_ASSERT(index < bn.size(), "Accessing bignum with illegal index");

            try {
                /* Rewire? */
                if ( ds.Get<bool>() == true ) {
                    /* Pick a random bignum */
                    const size_t newIndex = ds.Get<uint8_t>() % 4;

                    /* Same value? */
                    if ( bn[newIndex] == bn[index] ) {
                        /* Then return reference to other bignum */

                        if ( newIndex != index ) {
                            bn[newIndex].Lock();
                        }

                        return bn[newIndex];
                    }

                    /* Fall through */
                }
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

            return bn[index];
        }

        Bignum& Get(const size_t index) {
            CF_ASSERT(index < bn.size(), "Accessing bignum with illegal index");

            return bn[index];
        }

        BIGNUM* GetDestPtr(const size_t index) {
            return Get(index).GetDestPtr();
        }

        bool New(const size_t index) {
            CF_ASSERT(index < bn.size(), "Accessing bignum with illegal index");

            return bn[index].New();
        }

        bool Set(const size_t index, const std::string s) {
            CF_ASSERT(index < bn.size(), "Accessing bignum with illegal index");

            return bn[index].Set(s);
        }
};

class BN_CTX {
    private:
        ::BN_CTX* ctx = nullptr;
    public:
        BN_CTX(Datasource& ds) :
            ctx(BN_CTX_new())
        {
            (void)ds;

            CF_ASSERT(ctx != nullptr, "BN_CTX_new() returned NULL");
        }

        ::BN_CTX* GetPtr() {
            return ctx;
        }

        ~BN_CTX() {
            BN_CTX_free(ctx);
        }
};
class BN_MONT_CTX {
    private:
        ::BN_MONT_CTX* ctx = nullptr;
    public:
        BN_MONT_CTX(Datasource& ds) :
            ctx(BN_MONT_CTX_new())
        {
            (void)ds;

            CF_ASSERT(ctx != nullptr, "BN_MONT_CTX_new() returned NULL");
        }

        ::BN_MONT_CTX* GetPtr() {
            return ctx;
        }

        ~BN_MONT_CTX() {
            BN_MONT_CTX_free(ctx);
        }
};

class Operation {
    public:
        virtual bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class AddMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class SubMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class MulMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsPrime : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Sqrt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsEq : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsEven : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsOdd : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsOne : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

#if !defined(CRYPTOFUZZ_BORINGSSL)
class Mod_NIST_192 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Mod_NIST_224 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Mod_NIST_256 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Mod_NIST_384 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Mod_NIST_521 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};
#endif

class SqrtMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

#if defined(CRYPTOFUZZ_BORINGSSL)
class LCM : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};
#endif

class Exp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class RShift : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class LShift1 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class SetBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class ClearBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Bit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class CmpAbs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class ModLShift : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsPow2 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Mask : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class IsCoprime : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

class Rand : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, BignumCluster& bn, BN_CTX& ctx) const override;
};

} /* namespace OpenSSL_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
