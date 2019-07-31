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
};

} /* namespace operation */
} /* namespace cryptofuzz */
