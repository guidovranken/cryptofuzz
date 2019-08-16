#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <sstream>

namespace cryptofuzz {
namespace operation {

std::string Digest::Name(void) const { return "Digest"; }
std::string Digest::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Digest" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json Digest::ToJSON(void) const {
    nlohmann::json j;
    j["cleartext"] = cleartext.ToJSON();
    j["digestType"] = digestType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string HMAC::Name(void) const { return "HMAC"; }
std::string HMAC::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: HMAC" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json HMAC::ToJSON(void) const {
    nlohmann::json j;
    j["cleartext"] = cleartext.ToJSON();
    j["digestType"] = digestType.ToJSON();
    j["cipher"] = cipher.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string SymmetricEncrypt::Name(void) const { return "SymmetricEncrypt"; }
std::string SymmetricEncrypt::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SymmetricEncrypt" << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "aad: " << (aad ? util::HexDump(aad->Get()) : "nullopt") << std::endl;
    ss << "cipher iv: " << util::HexDump(cipher.iv.Get()) << std::endl;
    ss << "cipher key: " << util::HexDump(cipher.key.Get()) << std::endl;
    ss << "cipher: " << repository::CipherToString(cipher.cipherType.Get()) << std::endl;
    ss << "ciphertextSize: " << std::to_string(ciphertextSize) << std::endl;
    ss << "tagSize: " << (tagSize ? std::to_string(*tagSize) : "nullopt") << std::endl;

    return ss.str();
}

nlohmann::json SymmetricEncrypt::ToJSON(void) const {
    nlohmann::json j;
    j["cleartext"] = cleartext.ToJSON();
    j["cipher"] = cipher.ToJSON();
    j["aad_enabled"] = (bool)(aad != std::nullopt);
    j["aad"] = aad != std::nullopt ? aad->ToJSON() : "";
    j["ciphertextSize"] = ciphertextSize;
    j["tagSize_enabled"] = (bool)(tagSize != std::nullopt);
    j["tagSize"] = tagSize != std::nullopt ? *tagSize : 0;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string SymmetricDecrypt::Name(void) const { return "SymmetricDecrypt"; }
std::string SymmetricDecrypt::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SymmetricDecrypt" << std::endl;
    ss << "ciphertext: " << util::HexDump(ciphertext.Get()) << std::endl;
    ss << "tag: " << (tag ? util::HexDump(tag->Get()) : "nullopt") << std::endl;
    ss << "aad: " << (aad ? util::HexDump(aad->Get()) : "nullopt") << std::endl;
    ss << "cipher iv: " << util::HexDump(cipher.iv.Get()) << std::endl;
    ss << "cipher key: " << util::HexDump(cipher.key.Get()) << std::endl;
    ss << "cipher: " << repository::CipherToString(cipher.cipherType.Get()) << std::endl;
    ss << "cleartextSize: " << std::to_string(cleartextSize) << std::endl;

    return ss.str();
}

nlohmann::json SymmetricDecrypt::ToJSON(void) const {
    nlohmann::json j;
    j["ciphertext"] = ciphertext.ToJSON();
    j["cipher"] = cipher.ToJSON();
    j["aad_enabled"] = (bool)(aad != std::nullopt);
    j["aad"] = aad != std::nullopt ? aad->ToJSON() : "";
    j["tag_enabled"] = (bool)(tag != std::nullopt);
    j["tag"] = tag != std::nullopt ? tag->ToJSON() : "";
    j["cleartextSize"] = cleartextSize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

/* Construct SymmetricDecrypt from SymmetricEncrypt */
SymmetricDecrypt::SymmetricDecrypt(const SymmetricEncrypt& opSymmetricEncrypt, const component::Ciphertext ciphertext, const uint64_t cleartextSize, std::optional<component::AAD> aad, component::Modifier modifier) :
    Operation(std::move(modifier)),
    ciphertext(ciphertext.ciphertext),
    cipher(opSymmetricEncrypt.cipher),
    tag(ciphertext.tag),
    aad(aad),
    cleartextSize(cleartextSize)
{ }

std::string KDF_SCRYPT::Name(void) const { return "KDF_SCRYPT"; }
std::string KDF_SCRYPT::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_SCRYPT" << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "N: " << std::to_string(N) << std::endl;
    ss << "r: " << std::to_string(r) << std::endl;
    ss << "p: " << std::to_string(p) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_SCRYPT::ToJSON(void) const {
    nlohmann::json j;
    j["password"] = password.ToJSON();
    j["salt"] = salt.ToJSON();
    j["N"] = N;
    j["r"] = r;
    j["p"] = p;
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_HKDF::Name(void) const { return "KDF_HKDF"; }
std::string KDF_HKDF::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_HKDF" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "info: " << util::HexDump(info.Get()) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_HKDF::ToJSON(void) const {
    nlohmann::json j;
    j["digestType"] = digestType.ToJSON();
    j["password"] = password.ToJSON();
    j["salt"] = salt.ToJSON();
    j["info"] = info.ToJSON();
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_TLS1_PRF::Name(void) const { return "KDF_TLS1_PRF"; }
std::string KDF_TLS1_PRF::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_TLS1_PRF" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "secret: " << util::HexDump(secret.Get()) << std::endl;
    ss << "seed: " << util::HexDump(seed.Get()) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_TLS1_PRF::ToJSON(void) const {
    nlohmann::json j;
    j["digestType"] = digestType.ToJSON();
    j["secret"] = secret.ToJSON();
    j["seed"] = seed.ToJSON();
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_PBKDF1::Name(void) const { return "KDF_PBKDF1"; }
std::string KDF_PBKDF1::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_PBKDF1" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "iterations: " << std::to_string(iterations) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_PBKDF1::ToJSON(void) const {
    nlohmann::json j;
    j["digestType"] = digestType.ToJSON();
    j["password"] = password.ToJSON();
    j["salt"] = salt.ToJSON();
    j["iterations"] = iterations;
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_PBKDF2::Name(void) const { return "KDF_PBKDF2"; }
std::string KDF_PBKDF2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_PBKDF2" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "iterations: " << std::to_string(iterations) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_PBKDF2::ToJSON(void) const {
    nlohmann::json j;
    j["digestType"] = digestType.ToJSON();
    j["password"] = password.ToJSON();
    j["salt"] = salt.ToJSON();
    j["iterations"] = iterations;
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_ARGON2::Name(void) const { return "KDF_ARGON2"; }
std::string KDF_ARGON2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_ARGON2" << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "type: " << std::to_string(type) << std::endl;
    ss << "threads: " << std::to_string(threads) << std::endl;
    ss << "memory: " << std::to_string(memory) << std::endl;
    ss << "iterations: " << std::to_string(iterations) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_ARGON2::ToJSON(void) const {
    nlohmann::json j;
    j["password"] = password.ToJSON();
    j["salt"] = salt.ToJSON();
    j["type"] = type;
    j["threads"] = threads;
    j["memory"] = memory;
    j["iterations"] = iterations;
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string CMAC::Name(void) const { return "CMAC"; }
std::string CMAC::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: CMAC" << std::endl;
    ss << "cipher iv: " << util::HexDump(cipher.iv.Get()) << std::endl;
    ss << "cipher key: " << util::HexDump(cipher.key.Get()) << std::endl;
    ss << "cipher: " << repository::CipherToString(cipher.cipherType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "key: " << util::HexDump(cipher.key.Get()) << std::endl;

    return ss.str();
}

nlohmann::json CMAC::ToJSON(void) const {
    nlohmann::json j;
    j["cleartext"] = cleartext.ToJSON();
    j["cipher"] = cipher.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string Sign::Name(void) const { return "Sign"; }
std::string Sign::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Sign" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json Sign::ToJSON(void) const {
    throw std::runtime_error("Not implemented");
}

std::string Verify::Name(void) const { return "Verify"; }
std::string Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Verify" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json Verify::ToJSON(void) const {
    throw std::runtime_error("Not implemented");
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
