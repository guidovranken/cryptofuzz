#pragma once

#include <cryptofuzz/components.h>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {
namespace operation {

using fuzzing::datasource::Datasource;

class Operation {
    public:
        component::Modifier modifier;

        Operation(component::Modifier modifier) :
            modifier(std::move(modifier))
        { }

        virtual std::string ToString(void) const = 0;
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

        std::string ToString(void) const override;
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

        std::string ToString(void) const override;
};

class SymmetricEncrypt : public Operation {
    public:
        const component::Cleartext cleartext;
        const component::SymmetricCipher cipher;

        const uint64_t ciphertextSize;

        SymmetricEncrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            cleartext(ds),
            cipher(ds),
            ciphertextSize(ds.Get<uint64_t>() % (10*1024*1024))
        { }

        std::string ToString(void) const override;
};

class SymmetricDecrypt : public Operation {
    public:
        const component::Ciphertext ciphertext;
        const component::SymmetricCipher cipher;

        const uint64_t cleartextSize;

        SymmetricDecrypt(Datasource& ds, component::Modifier modifier) :
            Operation(std::move(modifier)),
            ciphertext(ds),
            cipher(ds),
            cleartextSize(ds.Get<uint64_t>() % (10*1024*1024))
        { }
        SymmetricDecrypt(const SymmetricEncrypt& opSymmetricEncrypt, const component::Ciphertext ciphertext, const uint64_t cleartextSize, component::Modifier modifier);

        std::string ToString(void) const override;
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
            r(ds.Get<uint64_t>() % 5),
            p(ds.Get<uint64_t>() % 5),
            keySize(ds.Get<uint64_t>() % (10*1024*1024))
        { }

        std::string ToString(void) const override;
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
            keySize(ds.Get<uint64_t>() % (10*1024*1024))
        { }

        std::string ToString(void) const override;
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
            keySize(ds.Get<uint64_t>() % (10*1024*1024))
        { }

        std::string ToString(void) const override;
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
            keySize(ds.Get<uint64_t>() % (10*1024*1024))
        { }

        std::string ToString(void) const override;
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

        std::string ToString(void) const override;
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

        std::string ToString(void) const override;
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

        std::string ToString(void) const override;
};

} /* namespace operation */
} /* namespace cryptofuzz */
