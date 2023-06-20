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

class UMAC : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::Cleartext key;
        const component::Cleartext iv;
        uint8_t type;
        const uint64_t outSize;

        UMAC(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            key(ds),
            iv(ds),
            type(ds.Get<uint64_t>() % 4),
            outSize(ds.Get<uint64_t>() % 1024)
        { }
        UMAC(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            key(json["key"]),
            iv(json["iv"]),
            type(json["type"].get<uint64_t>()),
            outSize(json["outSize"].get<uint64_t>())
        { }

        static size_t MaxOperations(void) { return 20; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const UMAC& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (key == rhs.key) &&
                (iv == rhs.iv) &&
                (type == rhs.type) &&
                (outSize == rhs.outSize) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            key.Serialize(ds);
            iv.Serialize(ds);
            ds.Put<>(type);
            ds.Put<>(outSize);
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

class ECCSI_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Cleartext cleartext;
        const component::Cleartext id;
        const component::DigestType digestType;

        ECCSI_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            cleartext(ds),
            id(ds),
            digestType(ds)
        { }
        ECCSI_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            cleartext(json["cleartext"]),
            id(json["id"]),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECCSI_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (cleartext == rhs.cleartext) &&
                (id == rhs.id) &&
                (digestType == rhs.digestType ) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            cleartext.Serialize(ds);
            id.Serialize(ds);
            digestType.Serialize(ds);
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

class ECGDSA_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        ECGDSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(ds)
        { }
        ECGDSA_Sign(nlohmann::json json) :
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
        inline bool operator==(const ECGDSA_Sign& rhs) const {
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

class ECRDSA_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        ECRDSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(ds)
        { }
        ECRDSA_Sign(nlohmann::json json) :
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
        inline bool operator==(const ECRDSA_Sign& rhs) const {
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

class Schnorr_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::Bignum nonce;
        const component::Cleartext cleartext;
        const uint8_t nonceSource;
        const component::DigestType digestType;

        Schnorr_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            nonce(ds),
            cleartext(ds),
            nonceSource(ds.Get<uint8_t>()),
            digestType(ds)
        { }
        Schnorr_Sign(nlohmann::json json) :
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
        inline bool operator==(const Schnorr_Sign& rhs) const {
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
        bool UseBIP340Nonce(void) const {
            return nonceSource == 1;
        }
        bool UseSpecifiedNonce(void) const {
            return nonceSource == 2;
        }
};

class ECCSI_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::Cleartext id;
        const component::ECCSI_Signature signature;
        const component::DigestType digestType;

        ECCSI_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            id(ds),
            signature(ds),
            digestType(ds)
        { }
        ECCSI_Verify(const ECCSI_Sign& opECCSI_Sign, const component::ECCSI_Signature signature, component::Modifier modifier);
        ECCSI_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            id(json["id"]),
            signature(json["signature"]),
            digestType(json["digestType"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECCSI_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (id == rhs.id) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            id.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
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
        ECDSA_Verify(const ECDSA_Sign& opECDSA_Sign, const component::ECDSA_Signature signature, component::Modifier modifier);
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

class ECGDSA_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECGDSA_Signature signature;
        const component::DigestType digestType;

        ECGDSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            signature(ds),
            digestType(ds)
        { }
        ECGDSA_Verify(nlohmann::json json) :
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
        inline bool operator==(const ECGDSA_Verify& rhs) const {
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

class ECRDSA_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECRDSA_Signature signature;
        const component::DigestType digestType;

        ECRDSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            signature(ds),
            digestType(ds)
        { }
        ECRDSA_Verify(nlohmann::json json) :
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
        inline bool operator==(const ECRDSA_Verify& rhs) const {
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

class ECDSA_Recover : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::BignumPair signature;
        const component::DigestType digestType;
        const uint8_t id;

        ECDSA_Recover(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            signature(ds),
            digestType(ds),
            id(ds.Get<uint8_t>())
        { }
        ECDSA_Recover(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            signature(json["signature"]),
            digestType(json["digestType"]),
            id(json["id"].get<uint8_t>())
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDSA_Recover& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (digestType == rhs.digestType) &&
                (id == rhs.id) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            signature.Serialize(ds);
            digestType.Serialize(ds);
            ds.Put<>(id);
        }
};

class DSA_GenerateParameters : public Operation {
    public:
        DSA_GenerateParameters(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier))
        { (void)ds; }
        DSA_GenerateParameters(nlohmann::json json) :
            Operation(json["modifier"])
        { }
        DSA_GenerateParameters(component::Modifier modifier) :
            Operation(std::move(modifier))
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DSA_GenerateParameters& rhs) const {
            return
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            (void)ds;
        }
};

class DSA_PrivateToPublic : public Operation {
    public:
        const component::Bignum g;
        const component::Bignum p;
        const component::Bignum priv;

        DSA_PrivateToPublic(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            g(ds),
            p(ds),
            priv(ds)
        { }
        DSA_PrivateToPublic(nlohmann::json json) :
            Operation(json["modifier"]),
            g(json["g"]),
            p(json["p"]),
            priv(json["priv"])
        { }
        DSA_PrivateToPublic(
                component::Modifier modifier,
                component::Bignum g,
                component::Bignum p,
                component::Bignum priv) :
            Operation(std::move(modifier)),
            g(g),
            p(p),
            priv(priv)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DSA_PrivateToPublic& rhs) const {
            return
                (g == rhs.g) &&
                (p == rhs.p) &&
                (priv == rhs.priv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            priv.Serialize(ds);
        }
};

class DSA_GenerateKeyPair : public Operation {
    public:
        const component::Bignum p;
        const component::Bignum q;
        const component::Bignum g;

        DSA_GenerateKeyPair(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            p(ds),
            q(ds),
            g(ds)
        { }
        DSA_GenerateKeyPair(nlohmann::json json) :
            Operation(json["modifier"]),
            p(json["p"]),
            q(json["q"]),
            g(json["g"])
        { }
        DSA_GenerateKeyPair(
                component::Modifier modifier,
                component::Bignum p,
                component::Bignum q,
                component::Bignum g) :
            Operation(std::move(modifier)),
            p(p),
            q(q),
            g(g)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DSA_GenerateKeyPair& rhs) const {
            return
                (p == rhs.p) &&
                (q == rhs.q) &&
                (g == rhs.g) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            p.Serialize(ds);
            q.Serialize(ds);
            g.Serialize(ds);
        }
};

class DSA_Sign : public Operation {
    public:
        const component::DSA_Parameters parameters;
        const component::Bignum priv;
        const component::Cleartext cleartext;

        DSA_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            parameters(ds),
            priv(ds),
            cleartext(ds)
        { }
        DSA_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            parameters(json["parameters"]),
            priv(json["priv"]),
            cleartext(json["cleartext"])
        { }
        DSA_Sign(
                component::Modifier modifier,
                component::DSA_Parameters parameters,
                component::Bignum priv,
                component::Cleartext cleartext) :
            Operation(std::move(modifier)),
            parameters(parameters),
            priv(priv),
            cleartext(cleartext)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DSA_Sign& rhs) const {
            return
                (parameters == rhs.parameters) &&
                (priv == rhs.priv) &&
                (cleartext == rhs.cleartext) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            parameters.Serialize(ds);
            priv.Serialize(ds);
            cleartext.Serialize(ds);
        }
};

class DSA_Verify : public Operation {
    public:
        const component::DSA_Parameters parameters;
        const component::Bignum pub;
        const component::BignumPair signature;
        const component::Cleartext cleartext;

        DSA_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            parameters(ds),
            pub(ds),
            signature(ds),
            cleartext(ds)
        { }
        DSA_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            parameters(json["parameters"]),
            pub(json["pub"]),
            signature(json["signature"]),
            cleartext(json["cleartext"])
        { }
        DSA_Verify(
                component::Modifier modifier,
                component::DSA_Parameters parameters,
                component::Bignum pub,
                component::BignumPair signature,
                component::Cleartext cleartext) :
            Operation(std::move(modifier)),
            parameters(parameters),
            pub(pub),
            signature(signature),
            cleartext(cleartext)
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const DSA_Verify& rhs) const {
            return
                (parameters == rhs.parameters) &&
                (pub == rhs.pub) &&
                (signature == rhs.signature) &&
                (cleartext == rhs.cleartext) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            parameters.Serialize(ds);
            pub.Serialize(ds);
            signature.Serialize(ds);
            cleartext.Serialize(ds);
        }
};

class Schnorr_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::ECDSA_Signature signature;
        const component::DigestType digestType;

        Schnorr_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            signature(ds),
            digestType(ds)
        { }
        Schnorr_Verify(nlohmann::json json) :
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
        inline bool operator==(const Schnorr_Verify& rhs) const {
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
        const component::ECC_PrivateKey priv;
        const component::ECC_PublicKey pub;

        ECDH_Derive(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            pub(ds)
        { }
        ECDH_Derive(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            pub(json["pub_x"], json["pub_y"])
        { }
        ECDH_Derive(
                component::Modifier modifier,
                component::CurveType curveType,
                component::ECC_PrivateKey priv,
                component::ECC_PublicKey pub) :
            Operation(std::move(modifier)),
            curveType(curveType),
            priv(priv),
            pub(pub)
        { }


        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECDH_Derive& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (pub == rhs.pub) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            pub.Serialize(ds);
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

class ECIES_Decrypt : public Operation {
    public:
        const Buffer ciphertext;
        const component::CurveType curveType;
        const component::ECC_PrivateKey priv;
        const component::ECC_PublicKey pub;
        const component::SymmetricCipherType cipherType;
        const std::optional<component::SymmetricIV> iv;
        /* TODO kdf type */
        /* TODO mac type */

        ECIES_Decrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            ciphertext(ds),
            curveType(ds),
            priv(ds),
            pub(ds),
            cipherType(ds),
            iv(ds.Get<bool>() ? std::nullopt : std::make_optional<component::SymmetricIV>(ds))
        { }
        ECIES_Decrypt(nlohmann::json json) :
            Operation(json["modifier"]),
            ciphertext(json["ciphertext"]),
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
        inline bool operator==(const ECIES_Decrypt& rhs) const {
            return
                (ciphertext == rhs.ciphertext) &&
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (pub == rhs.pub) &&
                (cipherType == rhs.cipherType) &&
                (iv == rhs.iv) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            ciphertext.Serialize(ds);
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

class ECC_Point_Add : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a, b;

        ECC_Point_Add(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        ECC_Point_Add(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Add& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class ECC_Point_Sub : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a, b;

        ECC_Point_Sub(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        ECC_Point_Sub(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Sub& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class ECC_Point_Mul : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a;
        const component::Bignum b;

        ECC_Point_Mul(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        ECC_Point_Mul(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Mul& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class ECC_Point_Neg : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a;

        ECC_Point_Neg(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds)
        { }
        ECC_Point_Neg(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Neg& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
        }
};

class ECC_Point_Dbl : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a;

        ECC_Point_Dbl(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds)
        { }
        ECC_Point_Dbl(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Dbl& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
        }
};

class ECC_Point_Cmp : public Operation {
    public:
        const component::CurveType curveType;
        const component::ECC_Point a, b;

        ECC_Point_Cmp(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        ECC_Point_Cmp(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const ECC_Point_Cmp& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
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
        std::optional<component::Bignum> modulo;

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
        void SetModulo(component::Bignum& modulo);
};

class BignumCalc_Fp2 : public Operation {
    public:
        const component::CalcOp calcOp;
        const component::Fp2 bn0;
        const component::Fp2 bn1;
        const component::Fp2 bn2;
        const component::Fp2 bn3;
        std::optional<component::Fp2> modulo;

        BignumCalc_Fp2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            calcOp(ds),
            bn0(ds),
            bn1(ds),
            bn2(ds),
            bn3(ds)
        { }
        BignumCalc_Fp2(nlohmann::json json) :
            Operation(json["modifier"]),
            calcOp(json["calcOp"]),
            bn0(json["bn1"]),
            bn1(json["bn2"]),
            bn2(json["bn3"]),
            bn3(json["bn4"])
        { }
        BignumCalc_Fp2(
                component::Modifier modifier,
                component::CurveType calcOp,
                component::Fp2 bn0,
                component::Fp2 bn1,
                component::Fp2 bn2,
                component::Fp2 bn3) :
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
        inline bool operator==(const BignumCalc_Fp2& rhs) const {
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
        void SetModulo(component::Fp2& modulo);
};

class BignumCalc_Fp12 : public Operation {
    public:
        const component::CalcOp calcOp;
        const component::Fp12 bn0;
        const component::Fp12 bn1;
        const component::Fp12 bn2;
        const component::Fp12 bn3;
        std::optional<component::Fp12> modulo;

        BignumCalc_Fp12(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            calcOp(ds),
            bn0(ds),
            bn1(ds),
            bn2(ds),
            bn3(ds)
        { }
        BignumCalc_Fp12(nlohmann::json json) :
            Operation(json["modifier"]),
            calcOp(json["calcOp"]),
            bn0(json["bn1"]),
            bn1(json["bn2"]),
            bn2(json["bn3"]),
            bn3(json["bn4"])
        { }
        BignumCalc_Fp12(
                component::Modifier modifier,
                component::CurveType calcOp,
                component::Fp12 bn0,
                component::Fp12 bn1,
                component::Fp12 bn2,
                component::Fp12 bn3) :
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
        inline bool operator==(const BignumCalc_Fp12& rhs) const {
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
        void SetModulo(component::Fp12& modulo);
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

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_PrivateToPublic& rhs) const {
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

class BLS_PrivateToPublic_G2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PrivateKey priv;

        BLS_PrivateToPublic_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds)
        { }
        BLS_PrivateToPublic_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_PrivateToPublic_G2& rhs) const {
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

class BLS_Sign : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PrivateKey priv;
        const bool hashOrPoint;
        const component::G2 point;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::Cleartext aug;

        BLS_Sign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            priv(ds),
            hashOrPoint(ds.Get<bool>()),
            point(ds),
            cleartext(ds),
            dest(ds),
            aug(ds)
        { }
        BLS_Sign(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            priv(json["priv"]),
            hashOrPoint(json["hashOrPoint"]),
            point(json["point_v"], json["point_w"], json["point_x"], json["point_y"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            aug(json["aug"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Sign& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (priv == rhs.priv) &&
                (hashOrPoint == rhs.hashOrPoint) &&
                (point == rhs.point) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (aug == rhs.aug) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            priv.Serialize(ds);
            ds.Put<bool>(hashOrPoint);
            point.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            aug.Serialize(ds);
        }
};

class BLS_Verify : public Operation {
    public:
        const component::CurveType curveType;
        const component::BLS_PublicKey pub;
        const bool hashOrPoint;
        const component::G2 point;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::G2 signature;

        BLS_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            pub(ds),
            hashOrPoint(ds.Get<bool>()),
            point(ds),
            cleartext(ds),
            dest(ds),
            signature(ds)
        { }
        BLS_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            pub(json["pub_x"], json["pub_y"]),
            hashOrPoint(json["hashOrPoint"]),
            point(json["point_v"], json["point_w"], json["point_x"], json["point_y"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            signature(json["sig_v"], json["sig_w"], json["sig_x"], json["sig_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Verify& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (pub == rhs.pub) &&
                (hashOrPoint == rhs.hashOrPoint) &&
                (point == rhs.point) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (signature == rhs.signature) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            pub.Serialize(ds);
            ds.Put<bool>(hashOrPoint);
            point.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            signature.Serialize(ds);
        }
};

class BLS_BatchSign : public Operation {
    public:
        component::BLS_BatchSign_Vector bf;

        BLS_BatchSign(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            bf(ds)
        { }
        BLS_BatchSign(nlohmann::json json) :
            Operation(json["modifier"]),
            bf(json["bf"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_BatchSign& rhs) const {
            return
                (bf == rhs.bf) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            bf.Serialize(ds);
        }
};

class BLS_BatchVerify : public Operation {
    public:
        component::BLS_BatchVerify_Vector bf;

        BLS_BatchVerify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            bf(ds)
        { }
        BLS_BatchVerify(nlohmann::json json) :
            Operation(json["modifier"]),
            bf(json["bf"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_BatchVerify& rhs) const {
            return
                (bf == rhs.bf) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            bf.Serialize(ds);
        }
};

class BLS_Aggregate_G1 : public Operation {
    public:
        const component::CurveType curveType;
        component::BLS_G1_Vector points;

        BLS_Aggregate_G1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            points(ds)
        { }
        BLS_Aggregate_G1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            points(json["points"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Aggregate_G1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (points == rhs.points) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            points.Serialize(ds);
        }
};

class BLS_Aggregate_G2 : public Operation {
    public:
        const component::CurveType curveType;
        component::BLS_G2_Vector points;

        BLS_Aggregate_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            points(ds)
        { }
        BLS_Aggregate_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            points(json["points"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Aggregate_G2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (points == rhs.points) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            points.Serialize(ds);
        }
};

class BLS_Pairing : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 g1;
        const component::G2 g2;

        BLS_Pairing(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            g1(ds),
            g2(ds)
        { }
        BLS_Pairing(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            g1(json["g1_x"], json["g1_y"]),
            g2(json["g2_v"], json["g2_w"], json["g2_x"], json["g2_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Pairing& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (g1 == rhs.g1) &&
                (g2 == rhs.g2) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            g1.Serialize(ds);
            g2.Serialize(ds);
        }
};

class BLS_MillerLoop : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 g1;
        const component::G2 g2;

        BLS_MillerLoop(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            g1(ds),
            g2(ds)
        { }
        BLS_MillerLoop(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            g1(json["g1_x"], json["g1_y"]),
            g2(json["g2_v"], json["g2_w"], json["g2_x"], json["g2_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_MillerLoop& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (g1 == rhs.g1) &&
                (g2 == rhs.g2) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            g1.Serialize(ds);
            g2.Serialize(ds);
        }
};

class BLS_FinalExp : public Operation {
    public:
        const component::CurveType curveType;
        const component::Fp12 fp12;

        BLS_FinalExp(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            fp12(ds)
        { }
        BLS_FinalExp(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            fp12(json["fp12"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_FinalExp& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (fp12 == rhs.fp12) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            fp12.Serialize(ds);
        }
};

class BLS_HashToG1 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::Cleartext aug;

        BLS_HashToG1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            dest(ds),
            aug(ds)
        { }
        BLS_HashToG1(const component::CurveType curveType, const component::Cleartext cleartext, const component::Cleartext dest, const component::Cleartext aug, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(curveType),
            cleartext(cleartext),
            dest(dest),
            aug(aug)
        { }
        BLS_HashToG1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            aug(json["aug"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_HashToG1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (aug == rhs.aug) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            aug.Serialize(ds);
        }
};

class BLS_HashToG2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext cleartext;
        const component::Cleartext dest;
        const component::Cleartext aug;

        BLS_HashToG2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            cleartext(ds),
            dest(ds),
            aug(ds)
        { }
        BLS_HashToG2(const component::CurveType curveType, const component::Cleartext cleartext, const component::Cleartext dest, const component::Cleartext aug, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(curveType),
            cleartext(cleartext),
            dest(dest),
            aug(aug)
        { }
        BLS_HashToG2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            cleartext(json["cleartext"]),
            dest(json["dest"]),
            aug(json["aug"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_HashToG2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (cleartext == rhs.cleartext) &&
                (dest == rhs.dest) &&
                (aug == rhs.aug) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            cleartext.Serialize(ds);
            dest.Serialize(ds);
            aug.Serialize(ds);
        }
};

class BLS_MapToG1 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Bignum u;
        const component::Bignum v;

        BLS_MapToG1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            u(ds),
            v(ds)
        { }
        BLS_MapToG1(const component::CurveType curveType, const component::Bignum u, const component::Bignum v, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(curveType),
            u(u),
            v(v)
        { }
        BLS_MapToG1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            u(json["u"]),
            v(json["v"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_MapToG1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (u == rhs.u) &&
                (v == rhs.v) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            u.Serialize(ds);
            v.Serialize(ds);
        }
};

class BLS_MapToG2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Fp2 u;
        const component::Fp2 v;

        BLS_MapToG2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            u(ds),
            v(ds)
        { }
        BLS_MapToG2(const component::CurveType curveType, const component::Fp2 u, const component::Fp2 v, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(curveType),
            u(u),
            v(v)
        { }
        BLS_MapToG2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            u(json["u"]),
            v(json["v"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_MapToG2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (u == rhs.u) &&
                (v == rhs.v) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            u.Serialize(ds);
            v.Serialize(ds);
        }
};

class BLS_IsG1OnCurve : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 g1;

        BLS_IsG1OnCurve(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            g1(ds)
        { }
        BLS_IsG1OnCurve(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            g1(json["g1_x"], json["g1_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_IsG1OnCurve& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (g1 == rhs.g1) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            g1.Serialize(ds);
        }
};

class BLS_IsG2OnCurve : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 g2;

        BLS_IsG2OnCurve(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            g2(ds)
        { }
        BLS_IsG2OnCurve(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            g2(json["g2_v"], json["g2_w"], json["g2_x"], json["g2_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_IsG2OnCurve& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (g2 == rhs.g2) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            g2.Serialize(ds);
        }
};

class BLS_GenerateKeyPair : public Operation {
    public:
        const component::CurveType curveType;
        const component::Cleartext ikm;
        const component::Cleartext info;

        BLS_GenerateKeyPair(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            ikm(ds),
            info(ds)
        { }

        BLS_GenerateKeyPair(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            ikm(json["ikm"]),
            info(json["info"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_GenerateKeyPair& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (ikm == rhs.ikm) &&
                (info == rhs.info) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            ikm.Serialize(ds);
            info.Serialize(ds);
        }
};

class BLS_Decompress_G1 : public Operation {
    public:
        const component::CurveType curveType;
        const component::Bignum compressed;

        BLS_Decompress_G1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            compressed(ds)
        { }
        BLS_Decompress_G1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            compressed(json["compressed"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Decompress_G1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (compressed == rhs.compressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            compressed.Serialize(ds);
        }
};

class BLS_Compress_G1 : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 uncompressed;

        BLS_Compress_G1(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            uncompressed(ds)
        { }
        BLS_Compress_G1(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            uncompressed(json["g1_x"], json["g1_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Compress_G1& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (uncompressed == rhs.uncompressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            uncompressed.Serialize(ds);
        }
};

class BLS_Decompress_G2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 compressed;

        BLS_Decompress_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            compressed(ds)
        { }
        BLS_Decompress_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            compressed(json["g1_x"], json["g1_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Decompress_G2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (compressed == rhs.compressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            compressed.Serialize(ds);
        }
};

class BLS_Compress_G2 : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 uncompressed;

        BLS_Compress_G2(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            uncompressed(ds)
        { }
        BLS_Compress_G2(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            uncompressed(json["g2_v"], json["g2_w"], json["g2_x"], json["g2_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_Compress_G2& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (uncompressed == rhs.uncompressed) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            uncompressed.Serialize(ds);
        }
};

class BLS_G1_Add : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a, b;

        BLS_G1_Add(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        BLS_G1_Add(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_Add& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G1_IsEq : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a, b;

        BLS_G1_IsEq(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        BLS_G1_IsEq(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_IsEq& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G1_Mul : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a;
        const component::Bignum b;

        BLS_G1_Mul(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        BLS_G1_Mul(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"]),
            b(json["b"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_Mul& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G1_Neg : public Operation {
    public:
        const component::CurveType curveType;
        const component::G1 a;

        BLS_G1_Neg(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds)
        { }
        BLS_G1_Neg(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_x"], json["a_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_Neg& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
        }
};

class BLS_G2_Add : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a, b;

        BLS_G2_Add(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        BLS_G2_Add(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"]),
            b(json["b_v"], json["b_w"], json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_Add& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G2_IsEq : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a, b;

        BLS_G2_IsEq(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        BLS_G2_IsEq(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"]),
            b(json["b_v"], json["b_w"], json["b_x"], json["b_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_IsEq& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G2_Mul : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a;
        const component::Bignum b;

        BLS_G2_Mul(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds),
            b(ds)
        { }
        BLS_G2_Mul(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"]),
            b(json["b"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_Mul& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (b == rhs.b) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
            b.Serialize(ds);
        }
};

class BLS_G2_Neg : public Operation {
    public:
        const component::CurveType curveType;
        const component::G2 a;

        BLS_G2_Neg(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            a(ds)
        { }
        BLS_G2_Neg(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            a(json["a_v"], json["a_w"], json["a_x"], json["a_y"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G2_Neg& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (a == rhs.a) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            a.Serialize(ds);
        }
};

class BLS_G1_MultiExp : public Operation {
    public:
        const component::CurveType curveType;
        component::BLS_G1_Scalar_Vector points_scalars;

        BLS_G1_MultiExp(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            curveType(ds),
            points_scalars(ds)
        { }
        BLS_G1_MultiExp(nlohmann::json json) :
            Operation(json["modifier"]),
            curveType(json["curveType"]),
            points_scalars(json["points_scalars"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const BLS_G1_MultiExp& rhs) const {
            return
                (curveType == rhs.curveType) &&
                (points_scalars == rhs.points_scalars) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            curveType.Serialize(ds);
            points_scalars.Serialize(ds);
        }
};

class Misc : public Operation {
    public:
        const Type operation;

        Misc(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            operation(ds)
        { }

        Misc(nlohmann::json json) :
            Operation(json["modifier"]),
            operation(json["operation"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const Misc& rhs) const {
            return
                (operation == rhs.operation) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            operation.Serialize(ds);
        }
};

class SR25519_Verify : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::SR25519_Signature signature;

        SR25519_Verify(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            signature(ds)
        { }
        SR25519_Verify(nlohmann::json json) :
            Operation(json["modifier"]),
            cleartext(json["cleartext"]),
            signature(json["signature"])
        { }

        static size_t MaxOperations(void) { return 5; }
        std::string Name(void) const override;
        std::string ToString(void) const override;
        nlohmann::json ToJSON(void) const override;
        inline bool operator==(const SR25519_Verify& rhs) const {
            return
                (cleartext == rhs.cleartext) &&
                (signature == rhs.signature) &&
                (modifier == rhs.modifier);
        }
        void Serialize(Datasource& ds) const {
            cleartext.Serialize(ds);
            signature.Serialize(ds);
        }
};

} /* namespace operation */
} /* namespace cryptofuzz */
