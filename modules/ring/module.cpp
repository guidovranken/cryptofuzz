#include <cstdio>
#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <cryptofuzz/repository.h>

extern "C" {
    struct RustBuffer {
        uint8_t* bytes;
        size_t len;
    };
    struct RustBuffers {
        RustBuffer* bufs;
        size_t len;
    };

    void free_buf(RustBuffer* buf);
    void free_bufs(RustBuffers* bufs);
    RustBuffer *hmac(const char* op);
    RustBuffer *digest(const char* op);
    RustBuffer *kdf_hkdf(const char* op);
    RustBuffer *kdf_pbkdf2(const char* op);
    RustBuffers *symmetric_encrypt(const char* op);
    RustBuffer *symmetric_decrypt(const char* op);
    RustBuffers *ecdsa_sign(const char* op);
    int8_t ecdsa_verify(const char* op);
}

template <class T> std::optional<T> getResultAs(RustBuffer *res) {
    std::optional<T> ret = std::nullopt;

    if(res == NULL) {
        return ret;
    }

    ret = T(res->bytes, res->len);
    free_buf(res);

    return ret;
}

namespace cryptofuzz {
namespace module {

Ring::Ring(void) :
    Module("Ring") { }

std::optional<component::Digest> Ring::OpDigest(operation::Digest& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = digest(jsonStr.c_str());
    return ::getResultAs<component::Digest>(res);
}

std::optional<component::MAC> Ring::OpHMAC(operation::HMAC& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = hmac(jsonStr.c_str());
    return ::getResultAs<component::MAC>(res);
}

std::optional<component::Key> Ring::OpKDF_HKDF(operation::KDF_HKDF& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = kdf_hkdf(jsonStr.c_str());
    return ::getResultAs<component::Key>(res);
}

std::optional<component::Key> Ring::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = kdf_pbkdf2(jsonStr.c_str());
    return ::getResultAs<component::Key>(res);
}

std::optional<component::Ciphertext> Ring::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = symmetric_encrypt(jsonStr.c_str());

    std::optional<component::Ciphertext> ret = std::nullopt;
    if(res == NULL) {
        return ret;
    }
    auto buffer = Buffer(res->bufs[0].bytes, res->bufs[0].len);
    auto tag = Buffer(res->bufs[1].bytes, res->bufs[1].len);
    ret = component::Ciphertext(buffer, tag);
    assert(op.tagSize.value_or(0) == res->bufs[1].len);
    free_bufs(res);

    return ret;
}

std::optional<component::Cleartext> Ring::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = symmetric_decrypt(jsonStr.c_str());
    return ::getResultAs<component::Cleartext>(res);
}

std::optional<bool> Ring::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = ecdsa_verify(jsonStr.c_str());
    if(res == -1) {
        return std::nullopt;
    }
    return res == 1;
}

std::optional<component::ECDSA_Signature> Ring::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    auto jsonStr = op.ToJSON().dump();
    auto res = ecdsa_sign(jsonStr.c_str());

    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    if(res == NULL) {
        return ret;
    }

    // only supports p256 right now
    assert(res->bufs[0].len == 64);
    assert(res->bufs[1].len == 65);

    ret = component::ECDSA_Signature(
        {util::BinToDec(res->bufs[0].bytes, 32), util::BinToDec(res->bufs[0].bytes + 32, 32)},
        {util::BinToDec(res->bufs[1].bytes + 1, 32), util::BinToDec(res->bufs[1].bytes + 1 + 32, 32)}
    );
    free_bufs(res);
    return ret;
}

}
}
