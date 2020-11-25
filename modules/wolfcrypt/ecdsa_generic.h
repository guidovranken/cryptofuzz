#pragma once

#include <cryptofuzz/operations.h>
#include <optional>

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
}

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {

class ECCPoint {
    private:
        ecc_point* point = nullptr;
        Datasource& ds;
        const int curveID;
        bool locked = false;
        bool initialized = false;
    public:
        ECCPoint(const ECCPoint& other);
        ECCPoint(Datasource& ds, const int curveID);
        ~ECCPoint();
        ecc_point* GetPtr(void);
        void Lock(void);
        void SetInitialized(void);
        std::optional<component::BignumPair> ToBignumPair(void);
};

class ECCKey {
    private:
        ecc_key* key = nullptr;
        Datasource& ds;
        std::optional<int> curveID = std::nullopt;
    public:
        ECCKey(Datasource& ds);
        ~ECCKey();
        ecc_key* GetPtr(void);
        bool SetCurve(const Type& curveType);
        bool LoadPrivateKey(const component::Bignum& priv);
        std::optional<ECCPoint> MakePub(void);
        bool SetRNG(void);
};

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Generic(operation::ECC_PrivateToPublic& op);
std::optional<bool> OpECDSA_Verify_Generic(operation::ECDSA_Verify& op);
std::optional<component::ECDSA_Signature> OpECDSA_Sign_Generic(operation::ECDSA_Sign& op);
std::optional<component::Ciphertext> OpECIES_Encrypt_Generic(operation::ECIES_Encrypt& op);

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
