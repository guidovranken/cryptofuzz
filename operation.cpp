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
    j["operation"] = "Digest";
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
    ss << "key: " << util::HexDump(cipher.key.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json HMAC::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "HMAC";
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
    j["operation"] = "SymmetricEncrypt";
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
    j["operation"] = "SymmetricDecrypt";
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
    j["operation"] = "KDF_SCRYPT";
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
    j["operation"] = "KDF_HKDF";
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
    j["operation"] = "KDF_TLS1_PRF";
    j["digestType"] = digestType.ToJSON();
    j["secret"] = secret.ToJSON();
    j["seed"] = seed.ToJSON();
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_PBKDF::Name(void) const { return "KDF_PBKDF"; }
std::string KDF_PBKDF::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_PBKDF" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "password: " << util::HexDump(password.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "iterations: " << std::to_string(iterations) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_PBKDF::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "KDF_PBKDF";
    j["digestType"] = digestType.ToJSON();
    j["password"] = password.ToJSON();
    j["salt"] = salt.ToJSON();
    j["iterations"] = iterations;
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
    j["operation"] = "KDF_PBKDF1";
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
    j["operation"] = "KDF_PBKDF2";
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
    j["operation"] = "KDF_ARGON2";
    j["password"] = password.ToJSON();
    j["salt"] = salt.ToJSON();
    j["type"] = type;
    j["threads"] = threads;
    j["memory"] = memory;
    j["iterations"] = iterations;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_SSH::Name(void) const { return "KDF_SSH"; }
std::string KDF_SSH::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_SSH" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "key: " << util::HexDump(key.Get()) << std::endl;
    ss << "xcghash: " << util::HexDump(xcghash.Get()) << std::endl;
    ss << "session_id: " << util::HexDump(session_id.Get()) << std::endl;
    ss << "type: " << util::HexDump(type.Get()) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_SSH::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "KDF_SSH";
    j["digestType"] = digestType.ToJSON();
    j["key"] = key.ToJSON();
    j["xcghash"] = xcghash.ToJSON();
    j["session_id"] = session_id.ToJSON();
    j["type"] = type.ToJSON();
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_X963::Name(void) const { return "KDF_X963"; }
std::string KDF_X963::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_X963" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "secret: " << util::HexDump(secret.Get()) << std::endl;
    ss << "info: " << util::HexDump(info.Get()) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_X963::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "KDF_X963";
    j["digestType"] = digestType.ToJSON();
    j["secret"] = secret.ToJSON();
    j["info"] = info.ToJSON();
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_BCRYPT::Name(void) const { return "KDF_BCRYPT"; }
std::string KDF_BCRYPT::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_BCRYPT" << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "secret: " << util::HexDump(secret.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "iterations: " << std::to_string(iterations) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_BCRYPT::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "KDF_BCRYPT";
    j["digestType"] = digestType.ToJSON();
    j["secret"] = secret.ToJSON();
    j["salt"] = salt.ToJSON();
    j["iterations"] = iterations;
    j["keySize"] = keySize;
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string KDF_SP_800_108::Name(void) const { return "KDF_SP_800_108"; }
std::string KDF_SP_800_108::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: KDF_SP_800_108" << std::endl;
    ss << "hmac/cmac: " << (mech.mode ? "HMAC" : "CMAC") << std::endl;
    if ( mech.mode == true ) {
        ss << "digest: " << repository::DigestToString(mech.type.Get()) << std::endl;
    } else {
        ss << "cipher: " << repository::CipherToString(mech.type.Get()) << std::endl;
    }
    ss << "secret: " << util::HexDump(secret.Get()) << std::endl;
    ss << "salt: " << util::HexDump(salt.Get()) << std::endl;
    ss << "label: " << util::HexDump(label.Get()) << std::endl;
    ss << "mode: " << std::to_string(mode) << std::endl;
    ss << "keySize: " << std::to_string(keySize) << std::endl;

    return ss.str();
}

nlohmann::json KDF_SP_800_108::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "KDF_SP_800_108";
    j["mech"] = mech.ToJSON();
    j["secret"] = secret.ToJSON();
    j["salt"] = salt.ToJSON();
    j["label"] = label.ToJSON();
    j["mode"] = mode;
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
    j["operation"] = "CMAC";
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

std::string ECC_PrivateToPublic::Name(void) const { return "ECC_PrivateToPublic"; }
std::string ECC_PrivateToPublic::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECC_PrivateToPublic" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;

    return ss.str();
}

nlohmann::json ECC_PrivateToPublic::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECC_PrivateToPublic";
    j["priv"] = priv.ToJSON();
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECC_ValidatePubkey::Name(void) const { return "ECC_ValidatePubkey"; }
std::string ECC_ValidatePubkey::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECC_ValidatePubkey" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "public key X: " << pub.first.ToString() << std::endl;
    ss << "public key Y: " << pub.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json ECC_ValidatePubkey::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECC_ValidatePubkey";
    j["pub_x"] = pub.first.ToJSON();
    j["pub_y"] = pub.second.ToJSON();
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECC_GenerateKeyPair::Name(void) const { return "ECC_GenerateKeyPair"; }
std::string ECC_GenerateKeyPair::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECC_GenerateKeyPair" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json ECC_GenerateKeyPair::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECC_GenerateKeyPair";
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECDSA_Sign::Name(void) const { return "ECDSA_Sign"; }
std::string ECDSA_Sign::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECDSA_Sign" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "nonce: " << nonce.ToString() << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "nonce source: ";
    if ( UseRandomNonce() ) {
        ss << "random";
    } else if ( UseRFC6979Nonce() ) {
        ss << "RFC 6979";
    } else if ( UseSpecifiedNonce() ) {
        ss << "specified";
    } else {
        ss << "(unknown)";
    }
    ss << std::endl;

    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json ECDSA_Sign::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECDSA_Sign";
    j["priv"] = priv.ToJSON();
    j["nonce"] = priv.ToJSON();
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["nonceSource"] = nonceSource;
    j["digestType"] = digestType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECDSA_Verify::Name(void) const { return "ECDSA_Verify"; }
std::string ECDSA_Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECDSA_Verify" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "public key X: " << signature.pub.first.ToString() << std::endl;
    ss << "public key Y: " << signature.pub.second.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "signature R: " << signature.signature.first.ToString() << std::endl;
    ss << "signature S: " << signature.signature.second.ToString() << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json ECDSA_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECDSA_Verify";
    j["curveType"] = curveType.ToJSON();
    j["pub_x"] = signature.pub.first.ToJSON();
    j["pub_y"] = signature.pub.second.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["sig_r"] = signature.signature.first.ToJSON();
    j["sig_s"] = signature.signature.second.ToJSON();
    j["digestType"] = digestType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECDH_Derive::Name(void) const { return "ECDH_Derive"; }
std::string ECDH_Derive::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECDH_Derive" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "public key 1 X: " << pub1.first.ToString() << std::endl;
    ss << "public key 1 Y: " << pub1.second.ToString() << std::endl;
    ss << "public key 2 X: " << pub2.first.ToString() << std::endl;
    ss << "public key 2 Y: " << pub2.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json ECDH_Derive::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECDH_Derive";
    j["curveType"] = curveType.ToJSON();
    j["pub1_x"] = pub1.first.ToJSON();
    j["pub1_y"] = pub1.second.ToJSON();
    j["pub2_x"] = pub2.first.ToJSON();
    j["pub2_y"] = pub2.second.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECIES_Encrypt::Name(void) const { return "ECIES_Encrypt"; }
std::string ECIES_Encrypt::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECIES_Encrypt" << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;
    ss << "public key X: " << pub.first.ToString() << std::endl;
    ss << "public key Y: " << pub.second.ToString() << std::endl;
    ss << "cipher: " << repository::CipherToString(cipherType.Get()) << std::endl;
    ss << "iv: " << (iv ? util::HexDump(iv->Get()) : "nullopt") << std::endl;

    return ss.str();
}

nlohmann::json ECIES_Encrypt::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECIES_Encrypt";
    j["cleartext"] = cleartext.ToJSON();
    j["curveType"] = curveType.ToJSON();
    j["priv"] = priv.ToJSON();
    j["pub_x"] = pub.first.ToJSON();
    j["pub_y"] = pub.second.ToJSON();
    j["cipherType"] = cipherType.ToJSON();
    j["iv_enabled"] = (bool)(iv != std::nullopt);
    j["iv"] = iv != std::nullopt ? iv->ToJSON() : "";
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string DH_GenerateKeyPair::Name(void) const { return "DH_GenerateKeyPair"; }
std::string DH_GenerateKeyPair::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: DH_GenerateKeyPair" << std::endl;
    ss << "prime: " << prime.ToString() << std::endl;
    ss << "base: " << base.ToString() << std::endl;

    return ss.str();
}

nlohmann::json DH_GenerateKeyPair::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "DH_GenerateKeyPair";
    j["prime"] = prime.ToJSON();
    j["base"] = base.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string DH_Derive::Name(void) const { return "DH_Derive"; }
std::string DH_Derive::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: DH_Derive" << std::endl;
    ss << "prime: " << prime.ToString() << std::endl;
    ss << "base: " << base.ToString() << std::endl;
    ss << "public key: " << pub.ToString() << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;

    return ss.str();
}

nlohmann::json DH_Derive::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "DH_Derive";
    j["prime"] = prime.ToJSON();
    j["base"] = base.ToJSON();
    j["pub"] = pub.ToJSON();
    j["priv"] = priv.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BignumCalc::Name(void) const { return "BignumCalc"; }
std::string BignumCalc::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BignumCalc" << std::endl;
    ss << "calc operation: " << repository::CalcOpToString(calcOp.Get()) << std::endl;
    ss << "bignum 1: " << bn0.ToString() << std::endl;
    ss << "bignum 2: " << bn1.ToString() << std::endl;
    ss << "bignum 3: " << bn2.ToString() << std::endl;
    ss << "bignum 4: " << bn3.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BignumCalc::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "BignumCalc";
    j["calcOp"] = calcOp.ToJSON();
    j["bn0"] = bn0.ToJSON();
    j["bn1"] = bn1.ToJSON();
    j["bn2"] = bn2.ToJSON();
    j["bn3"] = bn3.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_PrivateToPublic::Name(void) const { return "BLS_PrivateToPublic"; }
std::string BLS_PrivateToPublic::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_PrivateToPublic" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_PrivateToPublic::ToJSON(void) const {
    nlohmann::json j;
    j["priv"] = priv.ToJSON();
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_Sign::Name(void) const { return "BLS_Sign"; }
std::string BLS_Sign::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Sign" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_Sign::ToJSON(void) const {
    nlohmann::json j;

    /* TODO */

    return j;
}

std::string BLS_Verify::Name(void) const { return "BLS_Verify"; }
std::string BLS_Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Verify" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "public key X: " << pub.first.ToString() << std::endl;
    ss << "public key Y: " << pub.second.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "signature R: " << signature.first.ToString() << std::endl;
    ss << "signature S: " << signature.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_Pairing::Name(void) const { return "BLS_Pairing"; }
std::string BLS_Pairing::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Pairing" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    /* TODO q,p */

    return ss.str();
}

nlohmann::json BLS_Pairing::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    /* TODO q,p */
    return j;
}

std::string BLS_HashToG1::Name(void) const { return "BLS_HashToG1"; }
std::string BLS_HashToG1::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_HashToG1" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_HashToG1::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_HashToG2::Name(void) const { return "BLS_HashToG2"; }
std::string BLS_HashToG2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_HashToG2" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_HashToG2::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

} /* namespace operation */
} /* namespace cryptofuzz */
