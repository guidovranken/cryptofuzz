#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <memory>

#include "crypto/sha1.cpp"
#include "crypto/sha256.cpp"
#include "crypto/sha512.cpp"
#include "crypto/ripemd160.cpp"

#include "crypto/hmac_sha256.cpp"
#include "crypto/hmac_sha512.cpp"

#include "crypto/aes.cpp"

namespace cryptofuzz {
namespace module {

Bitcoin::Bitcoin(void) :
    Module("Bitcoin") { }

template <class Alg>
std::optional<component::Digest> Bitcoin::digest(operation::Digest& op, Datasource& ds) {
    std::optional<component::Digest> ret = std::nullopt;

    util::Multipart parts;
    std::unique_ptr<Alg> alg = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        alg = std::make_unique<Alg>();
    }

    /* Process */
    for (const auto& part : parts) {
        alg->Write(part.first, part.second);
    }

    /* Finalize */
    {
        uint8_t out[Alg::OUTPUT_SIZE];
        alg->Finalize(out);
        ret = component::Digest(out, Alg::OUTPUT_SIZE);
    }

    return ret;
}

std::optional<component::Digest> Bitcoin::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            return digest<CSHA1>(op, ds);
        case CF_DIGEST("SHA256"):
            return digest<CSHA256>(op, ds);
        case CF_DIGEST("SHA512"):
            return digest<CSHA512>(op, ds);
        case CF_DIGEST("RIPEMD160"):
            return digest<CRIPEMD160>(op, ds);
    }

    return ret;
}

template <class Alg>
std::optional<component::MAC> Bitcoin::hmac(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;
    std::unique_ptr<Alg> alg = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        alg = std::make_unique<Alg>(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
    }

    /* Process */
    for (const auto& part : parts) {
        alg->Write(part.first, part.second);
    }

    /* Finalize */
    {
        uint8_t out[Alg::OUTPUT_SIZE];
        alg->Finalize(out);
        ret = component::MAC(out, Alg::OUTPUT_SIZE);
    }

    return ret;
}

std::optional<component::MAC> Bitcoin::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA256"):
            return hmac<CHMAC_SHA256>(op, ds);
        case CF_DIGEST("SHA512"):
            return hmac<CHMAC_SHA512>(op, ds);
    }

    return ret;
}

std::optional<component::Ciphertext> Bitcoin::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    if ( op.tagSize != std::nullopt || op.aad != std::nullopt ) {
        return ret;
    }

    std::unique_ptr<AES256CBCEncrypt> aes = nullptr;
    uint8_t* out = util::malloc(op.cleartext.GetSize() + AES_BLOCKSIZE);
    int numWritten;

    /* Initialize */
    {
        CF_CHECK_EQ(op.cipher.cipherType.Get(), CF_CIPHER("AES_256_CBC"));
        CF_CHECK_EQ(op.cipher.key.GetSize(), AES256_KEYSIZE);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), AES_BLOCKSIZE);
        aes = std::make_unique<AES256CBCEncrypt>(op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), true);
    }

    /* Process */
    {
        CF_CHECK_GT(numWritten = aes->Encrypt(op.cleartext.GetPtr(), op.cleartext.GetSize(), out), 0);
    }

    /* Finalize */
    {
        ret = component::Ciphertext(Buffer(out, numWritten));
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::Cleartext> Bitcoin::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;

    if ( op.aad != std::nullopt || op.tag != std::nullopt ) {
        return ret;
    }

    std::unique_ptr<AES256CBCDecrypt> aes = nullptr;
    uint8_t* out = util::malloc(op.ciphertext.GetSize());
    int numWritten;

    /* Initialize */
    {
        CF_CHECK_EQ(op.cipher.cipherType.Get(), CF_CIPHER("AES_256_CBC"));
        CF_CHECK_EQ(op.cipher.key.GetSize(), AES256_KEYSIZE);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), AES_BLOCKSIZE);
        aes = std::make_unique<AES256CBCDecrypt>(op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), true);
    }

    /* Process */
    {
        CF_CHECK_GT(numWritten = aes->Decrypt(op.ciphertext.GetPtr(), op.ciphertext.GetSize(), out), 0);
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, numWritten);
    }

end:
    util::free(out);

    return ret;
}


} /* namespace module */
} /* namespace cryptofuzz */
