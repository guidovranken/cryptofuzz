#pragma once

#include "bn_ops.h"
#include <iostream>

namespace cryptofuzz {
namespace module {

template <class T>
class CTX_Copier {
    private:
        T* ctx = nullptr;
        Datasource& ds;

        T* newCTX(void) const;
        int copyCTX(T* dest, T* src) const;
        void freeCTX(T* ctx) const;

        T* copy(void) {
            bool doCopyCTX = true;
            try {
                doCopyCTX = ds.Get<bool>();
            } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

            if ( doCopyCTX == true ) {
                T* tmpCtx = newCTX();
                if ( tmpCtx != nullptr ) {
                    if ( copyCTX(tmpCtx, ctx) == 1 ) {
                        /* Copy succeeded, free the old ctx */
                        freeCTX(ctx);

                        /* Use the copied ctx */
                        ctx = tmpCtx;
                    } else {
                        freeCTX(tmpCtx);
                    }
                }
            }

            return ctx;
        }

    public:
        CTX_Copier(Datasource& ds) :
            ds(ds) {
            ctx = newCTX();

            CF_ASSERT(ctx != nullptr, "Cannot create ctx");
        }

        T* GetPtr(void) {
            return copy();
        }

        ~CTX_Copier() {
            freeCTX(ctx);
        }
};

class EC_GROUP_Copier {
    private:
        bool locked = false;
        const int curveNID;
        EC_GROUP* group = nullptr;
        Datasource& ds;

        EC_GROUP* newGroup(void) {
            return EC_GROUP_new_by_curve_name(curveNID);
        }

#if !defined(CRYPTOFUZZ_BORINGSSL)
        int copyGroup(EC_GROUP* dest, EC_GROUP* src) {
            return EC_GROUP_copy(dest, src);
        }
#endif
        void freeGroup(EC_GROUP* group) {
            /* noret */ EC_GROUP_free(group);
        }

        EC_GROUP* copy(void) {
            bool doCopyGroup = true;
            try {
                doCopyGroup = ds.Get<bool>();
            } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

            if ( doCopyGroup == true ) {
#if !defined(CRYPTOFUZZ_BORINGSSL)
                EC_GROUP* tmpGroup = newGroup();
                if ( tmpGroup != nullptr ) {
                    if ( copyGroup(tmpGroup, group) == 1 ) {
                        /* Copy succeeded, free the old group */
                        freeGroup(group);

                        /* Use the copied group */
                        group = tmpGroup;
                    } else {
                        freeGroup(tmpGroup);
                    }
                }
#endif
            }

            return group;
        }

    public:
        EC_GROUP_Copier(Datasource& ds, const int curveNID) :
            curveNID(curveNID), ds(ds) {
            group = newGroup();
        }

        void Lock(void) {
            locked = true;
        }

        EC_GROUP* GetPtr(void) {
            if ( locked == true ) {
                return group;
            } else {
                return copy();
            }
        }

        ~EC_GROUP_Copier() {
            freeGroup(group);
        }
};

class EC_POINT_Copier {
    private:
        std::shared_ptr<EC_GROUP_Copier> group;
        EC_POINT* point = nullptr;
        Datasource& ds;
        const uint64_t curveType;
        bool projective = false;

        EC_POINT* newPoint(void) {
            return EC_POINT_new(group->GetPtr());
        }

        int copyPoint(EC_POINT* dest, EC_POINT* src) {
            return EC_POINT_copy(dest, src);
        }
        void freePoint(EC_POINT* point) {
            /* noret */ EC_POINT_free(point);
        }


        point_conversion_form_t GetForm(void) {
            uint8_t form = 0;
            try {
                form = ds.Get<uint8_t>() % 3;
            } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

            if ( form == 0 ) {
                return POINT_CONVERSION_COMPRESSED;
            } else if ( form == 1 ) {
                return POINT_CONVERSION_UNCOMPRESSED;
            } else if ( form == 2 ) {
                return POINT_CONVERSION_HYBRID;
            } else {
                CF_UNREACHABLE();
            }
        }


        EC_POINT* copy(void) {
            {
                bool doCopyPoint = true;
                try {
                    doCopyPoint = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

                if ( doCopyPoint == true ) {
                    EC_POINT* tmpPoint = newPoint();
                    if ( tmpPoint != nullptr ) {
                        if ( copyPoint(tmpPoint, point) == 1 ) {
                            /* Copy succeeded, free the old point */
                            freePoint(point);

                            /* Use the copied point */
                            point = tmpPoint;
                        } else {
                            freePoint(tmpPoint);
                        }
                    }
                }
            }

            return point;
        }

        bool set(OpenSSL_bignum::Bignum& pub_x, OpenSSL_bignum::Bignum& pub_y, const bool allowProjective = true) {
            bool ret = false;

            char* x_str = nullptr;
            char* y_str = nullptr;

#if defined(CRYPTOFUZZ_BORINGSSL)
            (void)allowProjective;
            const bool projective = false;
#else
            bool projective = false;
            if ( allowProjective == true ) {
                try {
                    projective = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }
            }

            if ( projective ) {
                if ( (x_str = BN_bn2dec(pub_x.GetPtr())) == nullptr ) {
                    projective = false;
                }
                if ( projective && (y_str = BN_bn2dec(pub_y.GetPtr())) == nullptr ) {
                    projective = false;
                }
            }
#endif
            if ( projective == false ) {
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
                CF_CHECK_NE(EC_POINT_set_affine_coordinates(group->GetPtr(), GetPtr(), pub_x.GetPtr(), pub_y.GetPtr(), nullptr), 0);
#else
                CF_CHECK_NE(EC_POINT_set_affine_coordinates_GFp(group->GetPtr(), GetPtr(), pub_x.GetPtr(), pub_y.GetPtr(), nullptr), 0);
#endif
            } else {
#if defined(CRYPTOFUZZ_BORINGSSL)
                CF_UNREACHABLE();
#else
                OpenSSL_bignum::Bignum x(ds);
                CF_CHECK_TRUE(x.New());
                OpenSSL_bignum::Bignum y(ds);
                CF_CHECK_TRUE(y.New());
                OpenSSL_bignum::Bignum z(ds);
                CF_CHECK_TRUE(z.New());

                const auto proj = util::ToRandomProjective(
                        ds,
                        std::string(x_str),
                        std::string(y_str),
                        curveType);
                CF_CHECK_TRUE(x.Set(proj[0]));
                CF_CHECK_TRUE(y.Set(proj[1]));
                CF_CHECK_TRUE(z.Set(proj[2]));
                CF_CHECK_NE(EC_POINT_set_Jprojective_coordinates_GFp(group->GetPtr(), GetPtr(), x.GetPtr(), y.GetPtr(), z.GetPtr(), nullptr), 0);
                this->projective = true;
#endif
            }

            ret = true;
end:
            OPENSSL_free(x_str);
            OPENSSL_free(y_str);
            return ret;
        }

        bool set_compressed(OpenSSL_bignum::Bignum& pub_x, OpenSSL_bignum::Bignum& pub_y) {
            bool ret = false;

            const bool is_prime_curve =
#if defined(CRYPTOFUZZ_LIBRESSL) || defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_OPENSSL_102) || defined(CRYPTOFUZZ_OPENSSL_098)
                EC_METHOD_get_field_type(EC_GROUP_method_of(group->GetPtr()))
#else
                EC_GROUP_get_field_type(group->GetPtr())
#endif
                == NID_X9_62_prime_field;

#if defined(CRYPTOFUZZ_BORINGSSL)
            if ( is_prime_curve ) {
                return set(pub_x, pub_y);
            }
#endif

#if defined(CRYPTOFUZZ_LIBRESSL)
            if ( !is_prime_curve ) {
                /* LibreSSL doesn't have BN_GF2m_mod_div */
                return set(pub_x, pub_y);
            }
#endif

            OpenSSL_bignum::Bignum field(ds);
            CF_CHECK_TRUE(field.New());
            int y_bit;

            /* Reduction of Y is necessary in order to correctly determine y_bit */
            {
                OpenSSL_bignum::BN_CTX ctx(ds);
                BIGNUM* y = pub_y.GetDestPtr();

#if defined(CRYPTOFUZZ_LIBRESSL) || defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_OPENSSL_102) || defined(CRYPTOFUZZ_OPENSSL_098)
                /* LibreSSL and BoringSSL don't have EC_GROUP_get0_field(),
                 * so try to retrieve the prime from the repository
                 */
                const auto prime = cryptofuzz::repository::ECC_CurveToPrime(curveType);
                CF_CHECK_NE(prime, std::nullopt);
                CF_CHECK_EQ(field.Set(*prime), true);
#else
                (void)curveType;

                const BIGNUM* _field;
                CF_ASSERT(
                        (_field = EC_GROUP_get0_field(group->GetPtr())) != nullptr,
                        "EC_GROUP_get0_field returned NULL");
                CF_CHECK_NE(BN_copy(field.GetDestPtr(), _field), nullptr);
#endif

                CF_CHECK_EQ(BN_mod(y, y, field.GetPtr(), ctx.GetPtr()), 1);
            }

            if ( is_prime_curve == true ) {
                y_bit = BN_is_bit_set(pub_y.GetPtr(), 0);
            } else {
                /* Binary curve */
#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
                CF_UNREACHABLE();
#else
                if ( BN_is_zero(pub_x.GetPtr()) ) {
                    y_bit = 0;
                } else {
                    OpenSSL_bignum::BN_CTX ctx(ds);
                    OpenSSL_bignum::Bignum div(ds);

                    CF_CHECK_TRUE(div.New());
                    CF_CHECK_EQ(BN_GF2m_mod_div(div.GetDestPtr(), pub_y.GetPtr(), pub_x.GetPtr(), field.GetPtr(), ctx.GetPtr()), 1);

                    y_bit = BN_is_bit_set(div.GetPtr(), 0);
                }
#endif
            }

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
            CF_CHECK_NE(EC_POINT_set_compressed_coordinates(group->GetPtr(), GetPtr(), pub_x.GetPtr(), y_bit, nullptr), 0);
#else
            CF_CHECK_NE(EC_POINT_set_compressed_coordinates_GFp(group->GetPtr(), GetPtr(), pub_x.GetPtr(), y_bit, nullptr), 0);
#endif

            CF_ASSERT(
                    EC_POINT_is_on_curve(group->GetPtr(), GetPtr(), nullptr) == 1,
                    "Decompressed point not on curve")

            ret = true;
end:
            return ret;
        }

    public:
        EC_POINT_Copier(Datasource& ds, std::shared_ptr<EC_GROUP_Copier> group, const uint64_t curveType) :
            group(group), ds(ds), curveType(curveType) {
            point = newPoint();

            CF_ASSERT(point != nullptr, "Cannot create EC_POINT");
        }

        EC_POINT* GetPtr(void) {
            return copy();
        }

        ~EC_POINT_Copier() {
            freePoint(point);
        }

        bool Set(
                OpenSSL_bignum::Bignum& pub_x,
                OpenSSL_bignum::Bignum& pub_y,
                const bool allowCompressed = true,
                const bool allowProjective = true) {
            bool compressed = false;
            try {
                compressed = ds.Get<bool>();
            } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

            if ( allowCompressed == false ) {
                compressed = false;
            }

            /* Currently disabled because it leads to spurious discrepancies */
            compressed = false;

            return compressed ?
                set_compressed(pub_x, pub_y) :
                set(pub_x, pub_y, allowProjective);
        }

        bool Set(
                const component::Bignum& pub_x,
                const component::Bignum& pub_y,
                const bool allowCompressed = true,
                const bool allowProjective = true) {
            bool ret = false;

            OpenSSL_bignum::Bignum _pub_x(ds), _pub_y(ds);

            CF_CHECK_EQ(_pub_x.Set(pub_x.ToString(ds)), true);
            CF_CHECK_EQ(_pub_y.Set(pub_y.ToString(ds)), true);

            CF_CHECK_TRUE(Set(_pub_x, _pub_y, allowCompressed, allowProjective));

            ret = true;
end:
            return ret;
        }

        bool Get(OpenSSL_bignum::Bignum& pub_x, OpenSSL_bignum::Bignum& pub_y) {
            bool ret = false;

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
            CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);
#else
            CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group->GetPtr(), GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);
#endif

            ret = true;
end:
            return ret;
        }

        std::optional<component::ECC_Point> Get(void) {
            std::optional<component::ECC_Point> ret = std::nullopt;

            char* x_str = nullptr;
            char* y_str = nullptr;

            OpenSSL_bignum::Bignum x(ds);
            OpenSSL_bignum::Bignum y(ds);

            CF_CHECK_EQ(x.New(), true);
            CF_CHECK_EQ(y.New(), true);

            CF_CHECK_TRUE(Get(x, y));

            CF_CHECK_NE(x_str = BN_bn2dec(x.GetPtr()), nullptr);
            CF_CHECK_NE(y_str = BN_bn2dec(y.GetPtr()), nullptr);

            ret = { std::string(x_str), std::string(y_str) };

end:
            OPENSSL_free(x_str);
            OPENSSL_free(y_str);

            return ret;
        }

        bool IsProjective(void) const {
            return projective;
        }
};

#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
template<> EVP_MD_CTX* CTX_Copier<EVP_MD_CTX>::newCTX(void) const { return EVP_MD_CTX_new(); }
#else
template<> EVP_MD_CTX* CTX_Copier<EVP_MD_CTX>::newCTX(void) const {
    EVP_MD_CTX* ret = (EVP_MD_CTX*)malloc(sizeof(*ret));
    EVP_MD_CTX_init(ret);
    return ret;
}
#endif

template<> int CTX_Copier<EVP_MD_CTX>::copyCTX(EVP_MD_CTX* dest, EVP_MD_CTX* src) const { return EVP_MD_CTX_copy(dest, src); }

#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
template<> void CTX_Copier<EVP_MD_CTX>::freeCTX(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
#else
template<> void CTX_Copier<EVP_MD_CTX>::freeCTX(EVP_MD_CTX* ctx) const { EVP_MD_CTX_cleanup(ctx); free(ctx); }
#endif

template<> EVP_CIPHER_CTX* CTX_Copier<EVP_CIPHER_CTX>::newCTX(void) const { return EVP_CIPHER_CTX_new(); }
#if !defined(CRYPTOFUZZ_OPENSSL_098)
template<> int CTX_Copier<EVP_CIPHER_CTX>::copyCTX(EVP_CIPHER_CTX* dest, EVP_CIPHER_CTX* src) const { return EVP_CIPHER_CTX_copy(dest, src); }
#else
template<> int CTX_Copier<EVP_CIPHER_CTX>::copyCTX(EVP_CIPHER_CTX* dest, EVP_CIPHER_CTX* src) const { (void)dest; (void)src; return 0; }
#endif
template<> void CTX_Copier<EVP_CIPHER_CTX>::freeCTX(EVP_CIPHER_CTX* ctx) const { return EVP_CIPHER_CTX_free(ctx); }

#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
template<> HMAC_CTX* CTX_Copier<HMAC_CTX>::newCTX(void) const { return HMAC_CTX_new(); }
template<> int CTX_Copier<HMAC_CTX>::copyCTX(HMAC_CTX* dest, HMAC_CTX* src) const { return HMAC_CTX_copy(dest, src); }
template<> void CTX_Copier<HMAC_CTX>::freeCTX(HMAC_CTX* ctx) const { return HMAC_CTX_free(ctx); }
#endif

#if !defined(CRYPTOFUZZ_OPENSSL_098)
template<> CMAC_CTX* CTX_Copier<CMAC_CTX>::newCTX(void) const { return CMAC_CTX_new(); }
template<> int CTX_Copier<CMAC_CTX>::copyCTX(CMAC_CTX* dest, CMAC_CTX* src) const { return CMAC_CTX_copy(dest, src); }
template<> void CTX_Copier<CMAC_CTX>::freeCTX(CMAC_CTX* ctx) const { return CMAC_CTX_free(ctx); }
#endif

template<> EC_KEY* CTX_Copier<EC_KEY>::newCTX(void) const { return EC_KEY_new(); }
template<> int CTX_Copier<EC_KEY>::copyCTX(EC_KEY* dest, EC_KEY* src) const {
#if !defined(CRYPTOFUZZ_BORINGSSL)
    return EC_KEY_copy(dest, src) == nullptr ? 0 : 1;
#else
    (void)dest;
    (void)src;
    return 0;
#endif
}
template<> void CTX_Copier<EC_KEY>::freeCTX(EC_KEY* ctx) const { return EC_KEY_free(ctx); }

using CF_EVP_MD_CTX = CTX_Copier<EVP_MD_CTX>;
using CF_EVP_CIPHER_CTX = CTX_Copier<EVP_CIPHER_CTX>;
using CF_HMAC_CTX = CTX_Copier<HMAC_CTX>;
using CF_CMAC_CTX = CTX_Copier<CMAC_CTX>;
using CF_EC_KEY = CTX_Copier<EC_KEY>;
using CF_EC_POINT = EC_POINT_Copier;
using CF_EC_GROUP = EC_GROUP_Copier;
} /* namespace module */
} /* namespace cryptofuzz */
