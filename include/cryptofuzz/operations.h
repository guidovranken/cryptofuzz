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


        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            digestType.Serialize(ds);
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

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            digestType.Serialize(ds);
            cipher.Serialize(ds);
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
                        std::optional<component::AAD>(json["aad"]) :
                        std::optional<component::AAD>(std::nullopt)
            ),
            ciphertextSize(json["ciphertextSize"].get<uint64_t>()),
            tagSize(
                    json["tagSize_enabled"].get<bool>() ?
                        std::optional<uint64_t>(json["tagSize"].get<uint64_t>()) :
                        std::optional<uint64_t>(std::nullopt)
            )
        { }

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            cipher.Serialize(ds);
            if ( aad == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                aad->Serialize(ds);
            }
            ds.Put<>(ciphertextSize);
            if ( tagSize == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                ds.Put<>(*tagSize);
            }
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
                        std::optional<component::Tag>(json["tag"]) :
                        std::optional<component::Tag>(std::nullopt)
            ),
            aad(
                    json["aad_enabled"].get<bool>() ?
                        std::optional<component::AAD>(json["aad"]) :
                        std::optional<component::AAD>(std::nullopt)
            ),
            cleartextSize(json["cleartextSize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            ciphertext.Serialize(ds);
            cipher.Serialize(ds);
            if ( tag == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                tag->Serialize(ds);
            }
            if ( aad == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                aad->Serialize(ds);
            }
            ds.Put<>(cleartextSize);
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

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(N);
            ds.Put<>(r);
            ds.Put<>(p);
            ds.Put<>(keySize);
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
            keySize(ds.Get<uint64_t>() % 17000)
        { }
        KDF_HKDF(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            info(json["info"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            info.Serialize(ds);
            ds.Put<>(keySize);
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

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            secret.Serialize(ds);
            seed.Serialize(ds);
            ds.Put<>(keySize);
        }
};

class KDF_PBKDF : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext password;
        const component::Cleartext salt;
        const uint64_t iterations;

        const uint64_t keySize;

        KDF_PBKDF(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            password(ds),
            salt(ds),
            iterations(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_PBKDF(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            password(json["password"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint64_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_PBKDF& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (password == rhs.password) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
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

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
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

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
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

        static size_t MaxOperations(void) { return 3; }
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
        void Serialize(Datasource& ds) const {
            password.Serialize(ds);
            salt.Serialize(ds);
            ds.Put<>(type);
            ds.Put<>(threads);
            ds.Put<>(memory);
            ds.Put<>(iterations);
            ds.Put<>(keySize);
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

        static size_t MaxOperations(void) { return 20; }
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
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            key.Serialize(ds);
            xcghash.Serialize(ds);
            session_id.Serialize(ds);
            type.Serialize(ds);
            ds.Put<>(keySize);
        }
};

class KDF_X963 : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext secret;
        const component::Cleartext info;
        const uint64_t keySize;

        KDF_X963(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            secret(ds),
            info(ds),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_X963(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            secret(json["secret"]),
            info(json["info"]),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_X963& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (secret == rhs.secret) &&
                (info == rhs.info) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            digestType.Serialize(ds);
            secret.Serialize(ds);
            info.Serialize(ds);
            ds.Put<>(keySize);
        }
};

class KDF_BCRYPT : public Operation {
    public:
        const component::DigestType digestType;
        const component::Cleartext secret;
        const component::Cleartext salt;
        const uint32_t iterations;
        const uint64_t keySize;

        KDF_BCRYPT(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            digestType(ds),
            secret(ds),
            salt(ds),
            iterations(ds.Get<uint32_t>() % 3),
            keySize(ds.Get<uint64_t>() % 1024)
        { }
        KDF_BCRYPT(nlohmann::json json) :
            Operation(json["modifier"]),
            digestType(json["digestType"]),
            secret(json["secret"]),
            salt(json["salt"]),
            iterations(json["iterations"].get<uint32_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 2; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_BCRYPT& rhs) const {
            return
                (digestType == rhs.digestType) &&
                (secret == rhs.secret) &&
                (salt == rhs.salt) &&
                (iterations == rhs.iterations) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
};

class KDF_SP_800_108 : public Operation {
    public:
        const component::MACType mech;
        const component::Cleartext secret;
        const component::Cleartext salt;
        const component::Cleartext label;
        const uint8_t mode;
        const uint64_t keySize;

        KDF_SP_800_108(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            mech(ds),
            secret(ds),
            salt(ds),
            label(ds),
            mode(ds.Get<uint8_t>()),
            keySize(ds.Get<uint64_t>() % 17000)
        { }
        KDF_SP_800_108(nlohmann::json json) :
            Operation(json["modifier"]),
            mech(json["mech"]),
            secret(json["secret"]),
            salt(json["salt"]),
            label(json["label"]),
            mode(json["mode"].get<uint8_t>()),
            keySize(json["keySize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const KDF_SP_800_108& rhs) const {
            return
                (mech == rhs.mech) &&
                (secret == rhs.secret) &&
                (salt == rhs.salt) &&
                (label == rhs.label) &&
                (mode == rhs.mode) &&
                (keySize == rhs.keySize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            mech.Serialize(ds);
            secret.Serialize(ds);
            salt.Serialize(ds);
            label.Serialize(ds);
            ds.Put<>(mode);
            ds.Put<>(keySize);
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

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const CMAC& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (cipher == rhs.cipher) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            cipher.Serialize(ds);
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

        static size_t MaxOperations(void) { return 20; }
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

        static size_t MaxOperations(void) { return 20; }
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

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_PrivateToPublic& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
        }
};

class ECC_ValidatePubkey : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PublicKey pub;

        ECC_ValidatePubkey(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            pub(ds)
        { }
        ECC_ValidatePubkey(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            pub(json["pub_x"], json["pub_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_ValidatePubkey& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (pub == rhs.pub) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            pub.Serialize(ds);
        }
};

class ECC_GenerateKeyPair : public Operation {
    public:
        const component::CurveType curveType;

        ECC_GenerateKeyPair(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds)
        { }

        ECC_GenerateKeyPair(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_GenerateKeyPair& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
        }
};

class ECDSA_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        ECDSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(ds)
        { }
        ECDSA_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            nonce(json["nonce"]),
            cleartext(json["cleartext"]),
            nonceSource(json["nonceSource"].get<uint8_t>()),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (nonce == rhs.nonce) &&
                (cleartext == rhs.cleartext) &&
                (nonceSource == rhs.nonceSource ) &&
                (digestType == rhs.digestType ) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            nonce.Serialize(ds);
            cleartext.Serialize(ds);
            ds.Put<>(nonceSource);
            digestType.Serialize(ds);
        }
        bool UseRandomNonce(void) const {
            return nonceSource == 0;
        }
        bool UseRFC6979Nonce(void) const {
            return nonceSource == 1;
        }
        bool UseSpecifiedNonce(void) const {
            return nonceSource == 2;
        }
};

class ECDSA_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECDSA_Signature signature;
        const component::DigestType digestType;

        ECDSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            signature(ds),
            digestType(ds)
        { }
        ECDSA_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            signature(json["signature"]),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
        }
};

class ECDH_Derive : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PublicKey pub1;
        const component::ECC_PublicKey pub2;

        ECDH_Derive(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            pub1(ds),
            pub2(ds)
        { }
        ECDH_Derive(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            pub1(json["pub1_x"], json["pub1_y"]),
            pub2(json["pub2_x"], json["pub2_y"])
        { }
        ECDH_Derive(
                component::Modifier modifier,
                component::CurveType curveType,
                component::ECC_PublicKey pub1,
                component::ECC_PublicKey pub2) :
            Operation(std::move(modifier)),
            curveType(curveType),
            pub1(pub1),
            pub2(pub2)
        { }


        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDH_Derive& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (pub1 == rhs.pub2) &&
                (pub2 == rhs.pub2) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            pub1.Serialize(ds);
            pub2.Serialize(ds);
        }
};

class ECIES_Encrypt : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::ECC_PublicKey pub;
        const component::SymmetricCipherType cipherType;
        const std::optional<component::SymmetricIV> iv;
        /* TODO kdf type */
        /* TODO mac type */

        ECIES_Encrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            curveType(ds),
            priv(ds),
            pub(ds),
            cipherType(ds),
            iv(ds.Get<bool>() ? std::nullopt : std::make_optional<component::SymmetricIV>(ds))
        { }
        ECIES_Encrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            pub(json["pub_x"], json["pub_y"]),
            cipherType(json["cipherType"]),
            iv(
                    json["iv_enabled"].get<bool>() ?
                        std::optional<component::SymmetricIV>(json["iv"]) :
                        std::optional<component::SymmetricIV>(std::nullopt)
            )
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECIES_Encrypt& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (pub == rhs.pub) &&
                (cipherType == rhs.cipherType) &&
                (iv == rhs.iv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            curveType.Serialize(ds);
            priv.Serialize(ds);
            pub.Serialize(ds);
            cipherType.Serialize(ds);
            if ( iv == std::nullopt ) {
                ds.Put<bool>(true);
            } else {
                ds.Put<bool>(false);
                iv->Serialize(ds);
            }
        }
};

class DH_GenerateKeyPair : public Operation {
    public:
        const component::Bignum prime;
        const component::Bignum base;

        DH_GenerateKeyPair(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            prime(ds),
            base(ds)
        { }
        DH_GenerateKeyPair(nlohmann::json json) :
            Operation(json["modifier"]),
            prime(json["prime"]),
            base(json["base"])
        { }
        DH_GenerateKeyPair(
                component::Modifier modifier,
                component::Bignum prime,
                component::Bignum base) :
            Operation(std::move(modifier)),
            prime(prime),
            base(base)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DH_GenerateKeyPair& rhs) const {
            return
                (prime == rhs.prime) &&
                (base  == rhs.base) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            prime.Serialize(ds);
            base.Serialize(ds);
        }
};

class DH_Derive : public Operation {
    public:
        const component::Bignum prime;
        const component::Bignum base;
        const component::Bignum pub;
        const component::Bignum priv;

        DH_Derive(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            prime(ds),
            base(ds),
            pub(ds),
            priv(ds)
        { }
        DH_Derive(nlohmann::json json) :
            Operation(json["modifier"]),
            prime(json["prime"]),
            base(json["base"]),
            pub(json["pub"]),
            priv(json["priv"])
        { }
        DH_Derive(
                component::Modifier modifier,
                component::Bignum prime,
                component::Bignum base,
                component::Bignum pub,
                component::Bignum priv) :
            Operation(std::move(modifier)),
            prime(prime),
            base(base),
            pub(pub),
            priv(priv)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DH_Derive& rhs) const {
            return
                (prime == rhs.prime) &&
                (base  == rhs.base) &&
                (pub == rhs.pub) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            prime.Serialize(ds);
            base.Serialize(ds);
            pub.Serialize(ds);
            priv.Serialize(ds);
        }
};

class BignumCalc : public Operation {
    public:
        const component::CalcOp calcOp;
        const component::Bignum bn0;
        const component::Bignum bn1;
        const component::Bignum bn2;
        const component::Bignum bn3;

        BignumCalc(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            calcOp(ds),
            bn0(ds),
            bn1(ds),
            bn2(ds),
            bn3(ds)
        { }
        BignumCalc(nlohmann::json json) :
            Operation(json["modifier"]),
            calcOp(json["calcOp"]),
            bn0(json["bn1"]),
            bn1(json["bn2"]),
            bn2(json["bn3"]),
            bn3(json["bn4"])
        { }
        BignumCalc(
                component::Modifier modifier,
                component::CurveType calcOp,
                component::Bignum bn0,
                component::Bignum bn1,
                component::Bignum bn2,
                component::Bignum bn3) :
            Operation(std::move(modifier)),
            calcOp(calcOp),
            bn0(bn0),
            bn1(bn1),
            bn2(bn2),
            bn3(bn3)
        { }


        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BignumCalc& rhs) const {
            return
                (calcOp == rhs.calcOp) &&
                (bn0 == rhs.bn0) &&
                (bn1 == rhs.bn1) &&
                (bn2 == rhs.bn2) &&
                (bn3 == rhs.bn3) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            calcOp.Serialize(ds);
            bn0.Serialize(ds);
            bn1.Serialize(ds);
            bn2.Serialize(ds);
            bn3.Serialize(ds);
        }
};

} /* namespace operation */
} /* namespace cryptofuzz */
