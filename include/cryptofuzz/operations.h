#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/datasource.hpp>
#include "../../third_party/json/json.hpp"

namespace cryptofuzz {
namespace operation {

using fuzzing::datasource::Datasource;

class Operation {
    public:
        component::Modifier modifier;

        Operation(component::Modifier modifier) :
            modifier(std::move(modifier))
        { }

        Operation(nlohmann::json modifier) :
            modifier(modifier)
        { }

        virtual std::string Name(void) const = 0;
        virtual std::string ToString(void) const = 0;
        virtual nlohmann::json ToJSON(void) const = 0;
        virtual std::string GetAlgorithmString(void) const {
            return "(no algorithm)";
        }
};

class Digest : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;

        Digest(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(ds)
        { }

        Digest(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            digestType(json["digestType"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::DigestToString(digestType.Get());
        }
        inline bool operator==(const Digest& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
};

class HMAC : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;
        const component::SymmetricCipher cipher;

        HMAC(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(ds),
            cipher(ds)
        { }
        HMAC(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            digestType(json["digestType"]),
            cipher(json["cipher"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::DigestToString(digestType.Get());
        }
        inline bool operator==(const HMAC& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (digestType == rhs.digestType) &&
                (cipher == rhs.cipher) &&
                (modifier == rhs.modifier);
        }
};

class SymmetricEncrypt : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::SymmetricCipher cipher;
        const std::optional<component::AAD> aad;

        const uint64_t ciphertextSize;
        const std::optional<uint64_t> tagSize;

        SymmetricEncrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            cipher(ds),
            aad(ds.Get<bool>() ? std::nullopt : std::make_optional<component::AAD>(ds)),
            ciphertextSize(ds.Get<uint64_t>() % (10*1024*1024)),
            tagSize( ds.Get<bool>() ?
                    std::nullopt :
                    std::make_optional<uint64_t>(ds.Get<uint64_t>() % (10*1024*1024)) )
        { }
        SymmetricEncrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            cipher(json["cipher"]),
            aad(
                    json["aad_enabled"].get<bool>() ?
                        std::optional<component::AAD>(json["aad"].get<uint64_t>()) :
                        std::optional<component::AAD>(std::nullopt)
            ),
            ciphertextSize(json["ciphertextSize"].get<uint64_t>()),
            tagSize(
                    json["tagSize_enabled"].get<bool>() ?
                        std::optional<uint64_t>(json["tagSize"].get<uint64_t>()) :
                        std::optional<uint64_t>(std::nullopt)
            )
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::CipherToString(cipher.cipherType.Get());
        }
        inline bool operator==(const SymmetricEncrypt& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (cipher == rhs.cipher) &&
                (aad == rhs.aad) &&
                (ciphertextSize == rhs.ciphertextSize) &&
                (tagSize == rhs.tagSize) &&
                (modifier == rhs.modifier);
        }
};

class SymmetricDecrypt : public Operation {
    public:
        const Buffer ciphertext;
        const component::SymmetricCipher cipher;
        const std::optional<component::Tag> tag;
        const std::optional<component::AAD> aad;

        const uint64_t cleartextSize;

        SymmetricDecrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            ciphertext(ds),
            cipher(ds),
            tag(ds.Get<bool>() ? std::nullopt : std::make_optional<component::Tag>(ds)),
            aad(ds.Get<bool>() ? std::nullopt : std::make_optional<component::AAD>(ds)),
            cleartextSize(ds.Get<uint64_t>() % (10*1024*1024))
        { }
        SymmetricDecrypt(const SymmetricEncrypt& opSymmetricEncrypt, const component::Ciphertext ciphertext, const uint64_t cleartextSize, std::optional<component::AAD> aad, component::Modifier modifier);
        SymmetricDecrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            ciphertext(json["ciphertext"]),
            cipher(json["cipher"]),
            tag(
                    json["tag_enabled"].get<bool>() ?
                        std::optional<component::Tag>(json["tag"].get<uint64_t>()) :
                        std::optional<component::Tag>(std::nullopt)
            ),
            aad(
                    json["aad_enabled"].get<bool>() ?
                        std::optional<component::AAD>(json["aad"].get<uint64_t>()) :
                        std::optional<component::AAD>(std::nullopt)
            ),
            cleartextSize(json["cleartextSize"].get<uint64_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        std::string GetAlgorithmString(void) const override {
            return repository::CipherToString(cipher.cipherType.Get());
        }
        inline bool operator==(const SymmetricDecrypt& rhs) const {
            return
                (ciphertext == rhs.ciphertext) &&
                (cipher == rhs.cipher) &&
                (tag == rhs.tag) &&
                (aad == rhs.aad) &&
                (cleartextSize == rhs.cleartextSize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_SCRYPT : public Operation {
    public:
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t N;
        const uint64_t r;
        const uint64_t p;

        const uint64_t keySize;

        KDF_SCRYPT(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            password(ds),
            salt(ds),
            N(ds.Get<uint64_t>() % 5),
            r(ds.Get<uint64_t>() % 9),
            p(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_SCRYPT(nlohmann::json json) :
            Operation(json["modifier"]),
            password(json["password"]),
            salt(json["salt"]),
            N(json["N"].get<uint64_t>()),
            r(json["r"].get<uint64_t>()),
            p(json["p"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_SCRYPT& rhs) const {
            return
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (N == rhs.N) &&
                (r == rhs.r) &&
                (p == rhs.p) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_HKDF : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const component::Cleartext info;

        const uint64_t keySize;

        KDF_HKDF(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            password(ds),
            salt(ds),
            info(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_HKDF(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            info(json["info"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_HKDF& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (info == rhs.info) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_TLS1_PRF : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext secret;
        const component::Cleartext seed;

        const uint64_t keySize;

        KDF_TLS1_PRF(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            secret(ds),
            seed(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_TLS1_PRF(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            secret(json["secret"]),
            seed(json["seed"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_TLS1_PRF& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (secret == rhs.secret) &&
                (seed == rhs.seed) &&
                (modifier == rhs.modifier);
        }
};

class KDF_PBKDF1 : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t iterations;

        const uint64_t keySize;

        KDF_PBKDF1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            password(ds),
            salt(ds),
            iterations(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_PBKDF1(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_PBKDF1& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_PBKDF2 : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t iterations;

        const uint64_t keySize;

        KDF_PBKDF2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            password(ds),
            salt(ds),
            iterations(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_PBKDF2(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_PBKDF2& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_ARGON2 : public Operation {
    public:
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint8_t type;
        const uint8_t threads;
        const uint32_t memory;
        const uint32_t iterations;
        const uint32_t keySize;

        KDF_ARGON2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            password(ds),
            salt(ds),
            type(ds.Get<uint8_t>()),
            threads(ds.Get<uint8_t>()),
            memory(ds.Get<uint32_t>() % (64*1024)),
            iterations(ds.Get<uint32_t>() % 3),
            keySize(ds.Get<uint32_t>() % 1024)
        { }
        KDF_ARGON2(nlohmann::json json) :
            Operation(json["modifier"]),
            password(json["password"]),
            salt(json["salt"]),
            type(json["type"].get<uint8_t>()),
            threads(json["threads"].get<uint8_t>()),
            memory(json["memory"].get<uint32_t>()),
            iterations(json["iterations"].get<uint32_t>()),
            keySize(json["keySize"].get<uint32_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_ARGON2& rhs) const {
            return
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (type == rhs.type) &&
                (threads == rhs.threads) &&
                (memory == rhs.memory) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_SSH : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext key;
        const component::Cleartext xcghash;
        const component::Cleartext session_id;
        const component::Cleartext type;
        const uint64_t keySize;

        KDF_SSH(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            key(ds),
            xcghash(ds),
            session_id(ds),
            type(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_SSH(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            key(json["key"]),
            xcghash(json["xcghash"]),
            session_id(json["session_id"]),
            type(json["type"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_SSH& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (key == rhs.key) &&
                (xcghash == rhs.xcghash) &&
                (session_id == rhs.session_id) &&
                (type == rhs.type) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class CMAC : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::SymmetricCipher cipher;

        CMAC(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            cipher(ds)
        { }
        CMAC(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            cipher(json["cipher"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const CMAC& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (cipher == rhs.cipher) &&
                (modifier == rhs.modifier);
        }
};

class Sign : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;
        const component::PrivateKeyPEM pkeyPEM;

        const uint64_t signatureSize;

        Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(ds),
            pkeyPEM(ds),
            signatureSize(ds.Get<uint64_t>() % (10*1024*1024))
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const Sign& rhs) const {
            (void)rhs;
            /* TODO */
            return false;
        }
};

class Verify : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::DigestType digestType;
        const component::PrivateKeyPEM pkeyPEM;
        const component::Signature signature;

        Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            digestType(ds),
            pkeyPEM(ds),
            signature(ds)
        { }
        Verify(const Sign& opSign, const component::Signature signature, component::Modifier modifier);

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const Verify& rhs) const {
            (void)rhs;
            /* TODO */
            return false;
        }
};

class ECC_PrivateToPublic : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;

        ECC_PrivateToPublic(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds)
        { }
        ECC_PrivateToPublic(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_PrivateToPublic& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
};

class ECDSA_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Cleartext cleartext;

        ECDSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            cleartext(ds)
        { }
        ECDSA_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            cleartext(json["cleartext"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (cleartext == rhs.cleartext) &&
                (modifier == rhs.modifier);
        }
};

class ECDSA_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PublicKey pub;
        const component::Cleartext cleartext;
        const component::ECDSA_Signature signature;

        ECDSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            pub(ds),
            cleartext(ds),
            signature(ds)
        { }
        ECDSA_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            pub(json["pub_x"], json["pub_y"]),
            cleartext(json["cleartext"]),
            signature(json["sig_r"], json["sig_y"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (pub == rhs.pub) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (modifier == rhs.modifier);
        }
};

class BLS_PrivateToPublic : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PrivateKey priv;

        BLS_PrivateToPublic(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds)
        { }
        BLS_PrivateToPublic(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_PrivateToPublic& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
};

class BLS_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PrivateKey priv;
        const component::Cleartext cleartext;

        BLS_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            cleartext(ds)
        { }
        BLS_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            cleartext(json["cleartext"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (cleartext == rhs.cleartext) &&
                (modifier == rhs.modifier);
        }
};

class BLS_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PublicKey pub;
        const component::Cleartext cleartext;
        const component::BLS_Signature signature;

        BLS_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            pub(ds),
            cleartext(ds),
            signature(ds)
        { }
        BLS_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            pub(json["pub_x"], json["pub_z"]),
            cleartext(json["cleartext"]),
            signature(json["sig_r"], json["sig_y"])
        { }

        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (pub == rhs.pub) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (modifier == rhs.modifier);
        }
};

} /* namespace operation */
} /* namespace cryptofuzz */
