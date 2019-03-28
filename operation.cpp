#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <sstream>

namespace cryptofuzz {
namespace operation {

std::string Digest::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Digest" << std::endl;
    ss << "digest: " << util::DigestIDToString(digestType) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

std::string HMAC::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: HMAC" << std::endl;
    ss << "digest: " << util::DigestIDToString(digestType) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

std::string SymmetricEncrypt::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SymmetricEncrypt" << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "cipher iv: " << util::HexDump(cipher.iv.Get()) << std::endl;
    ss << "cipher key: " << util::HexDump(cipher.key.Get()) << std::endl;
    ss << "cipher: " << util::SymmetricCipherIDToString(cipher.cipherType) << std::endl;
    ss << "ciphertextSize: " << std::to_string(ciphertextSize) << std::endl;

    return ss.str();
}

std::string SymmetricDecrypt::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SymmetricDecrypt" << std::endl;
    ss << "ciphertext: " << util::HexDump(ciphertext.Get()) << std::endl;
    ss << "cipher iv: " << util::HexDump(cipher.iv.Get()) << std::endl;
    ss << "cipher key: " << util::HexDump(cipher.key.Get()) << std::endl;
    ss << "cipher: " << util::SymmetricCipherIDToString(cipher.cipherType) << std::endl;
    ss << "cleartextSize: " << std::to_string(cleartextSize) << std::endl;

    return ss.str();
}

/* Construct SymmetricDecrypt from SymmetricEncrypt */
SymmetricDecrypt::SymmetricDecrypt(const SymmetricEncrypt& opSymmetricEncrypt, const component::Ciphertext ciphertext, const uint64_t cleartextSize, component::Modifier modifier) :
    Operation(std::move(modifier)),
    ciphertext(ciphertext),
    cipher(opSymmetricEncrypt.cipher),
    cleartextSize(cleartextSize)
{ }

std::string KDF_SCRYPT::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_SCRYPT" << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "N: " << std::to_string(N) << std::endl;
    ss << "r: " << std::to_string(r) << std::endl;
    ss << "p: " << std::to_string(p) << std::endl;

    return ss.str();
}

std::string KDF_HKDF::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_HKDF" << std::endl;
    ss << "digest: " << util::DigestIDToString(digestType) << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "info: " << util::HexDump(info.Get()) << std::endl;

    return ss.str();
}

std::string KDF_TLS1_PRF::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_TLS1_PRF" << std::endl;
    ss << "digest: " << util::DigestIDToString(digestType) << std::endl;
    ss << "secret: " << util::HexDump(secret.Get()) << std::endl;
    ss << "seed: " << util::HexDump(seed.Get()) << std::endl;

    return ss.str();
}

std::string KDF_PBKDF2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_PBKDF2" << std::endl;
    ss << "digest: " << util::DigestIDToString(digestType) << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "iterations: " << std::to_string(iterations) << std::endl;

    return ss.str();
}

std::string CMAC::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: CMAC" << std::endl;
    ss << "cipher iv: " << util::HexDump(cipher.iv.Get()) << std::endl;
    ss << "cipher key: " << util::HexDump(cipher.key.Get()) << std::endl;
    ss << "cipher: " << util::SymmetricCipherIDToString(cipher.cipherType) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "key: " << util::HexDump(cipher.key.Get()) << std::endl;

    return ss.str();
}

std::string Sign::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Sign" << std::endl;
    ss << "digest: " << util::DigestIDToString(digestType) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

std::string Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Verify" << std::endl;
    ss << "digest: " << util::DigestIDToString(digestType) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

/* Construct Verify from Sign */
Verify::Verify(const Sign& opSign, const component::Signature signature, component::Modifier modifier) :
    Operation(std::move(modifier)),
    cleartext(opSign.cleartext),
    digestType(opSign.digestType),
    pkeyPEM(opSign.pkeyPEM),
    signature(signature)
{ }

} /* namespace operation */
} /* namespace cryptofuzz */
