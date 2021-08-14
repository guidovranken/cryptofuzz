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

std::string ECGDSA_Sign::Name(void) const { return "ECGDSA_Sign"; }
std::string ECGDSA_Sign::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECGDSA_Sign" << std::endl;
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

nlohmann::json ECGDSA_Sign::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECGDSA_Sign";
    j["priv"] = priv.ToJSON();
    j["nonce"] = priv.ToJSON();
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["nonceSource"] = nonceSource;
    j["digestType"] = digestType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECRDSA_Sign::Name(void) const { return "ECRDSA_Sign"; }
std::string ECRDSA_Sign::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECRDSA_Sign" << std::endl;
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

nlohmann::json ECRDSA_Sign::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECRDSA_Sign";
    j["priv"] = priv.ToJSON();
    j["nonce"] = priv.ToJSON();
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["nonceSource"] = nonceSource;
    j["digestType"] = digestType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string Schnorr_Sign::Name(void) const { return "Schnorr_Sign"; }
std::string Schnorr_Sign::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Schnorr_Sign" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "nonce: " << nonce.ToString() << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "nonce source: ";
    if ( UseRandomNonce() ) {
        ss << "random";
    } else if ( UseBIP340Nonce() ) {
        ss << "BIP 340";
    } else if ( UseSpecifiedNonce() ) {
        ss << "specified";
    } else {
        ss << "(unknown)";
    }
    ss << std::endl;

    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json Schnorr_Sign::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "Schnorr_Sign";
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

std::string ECGDSA_Verify::Name(void) const { return "ECGDSA_Verify"; }
std::string ECGDSA_Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECGDSA_Verify" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "public key X: " << signature.pub.first.ToString() << std::endl;
    ss << "public key Y: " << signature.pub.second.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "signature R: " << signature.signature.first.ToString() << std::endl;
    ss << "signature S: " << signature.signature.second.ToString() << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json ECGDSA_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECGDSA_Verify";
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

std::string ECRDSA_Verify::Name(void) const { return "ECRDSA_Verify"; }
std::string ECRDSA_Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECRDSA_Verify" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "public key X: " << signature.pub.first.ToString() << std::endl;
    ss << "public key Y: " << signature.pub.second.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "signature R: " << signature.signature.first.ToString() << std::endl;
    ss << "signature S: " << signature.signature.second.ToString() << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json ECRDSA_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECRDSA_Verify";
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

std::string Schnorr_Verify::Name(void) const { return "Schnorr_Verify"; }
std::string Schnorr_Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Schnorr_Verify" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "public key X: " << signature.pub.first.ToString() << std::endl;
    ss << "public key Y: " << signature.pub.second.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "signature R: " << signature.signature.first.ToString() << std::endl;
    ss << "signature S: " << signature.signature.second.ToString() << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;

    return ss.str();
}

nlohmann::json Schnorr_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "Schnorr_Verify";
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

std::string ECDSA_Recover::Name(void) const { return "ECDSA_Recover"; }
std::string ECDSA_Recover::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECDSA_Recover" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "signature R: " << signature.first.ToString() << std::endl;
    ss << "signature S: " << signature.second.ToString() << std::endl;
    ss << "digest: " << repository::DigestToString(digestType.Get()) << std::endl;
    ss << "recovery ID: " << std::to_string(id) << std::endl;

    return ss.str();
}

nlohmann::json ECDSA_Recover::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECDSA_Recover";
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["sig_r"] = signature.first.ToJSON();
    j["sig_s"] = signature.second.ToJSON();
    j["digestType"] = digestType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECDH_Derive::Name(void) const { return "ECDH_Derive"; }
std::string ECDH_Derive::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECDH_Derive" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;
    ss << "public key X: " << pub.first.ToString() << std::endl;
    ss << "public key Y: " << pub.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json ECDH_Derive::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECDH_Derive";
    j["curveType"] = curveType.ToJSON();
    j["priv"] = priv.ToJSON();
    j["pub_x"] = pub.first.ToJSON();
    j["pub_y"] = pub.second.ToJSON();
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

std::string ECIES_Decrypt::Name(void) const { return "ECIES_Decrypt"; }
std::string ECIES_Decrypt::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECIES_Decrypt" << std::endl;
    ss << "ciphertext: " << util::HexDump(ciphertext.Get()) << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;
    ss << "public key X: " << pub.first.ToString() << std::endl;
    ss << "public key Y: " << pub.second.ToString() << std::endl;
    ss << "cipher: " << repository::CipherToString(cipherType.Get()) << std::endl;
    ss << "iv: " << (iv ? util::HexDump(iv->Get()) : "nullopt") << std::endl;

    return ss.str();
}

nlohmann::json ECIES_Decrypt::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "ECIES_Decrypt";
    j["ciphertext"] = ciphertext.ToJSON();
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

std::string ECC_Point_Add::Name(void) const { return "ECC_Point_Add"; }
std::string ECC_Point_Add::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECC_Point_Add" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A X: " << a.first.ToString() << std::endl;
    ss << "A Y: " << a.second.ToString() << std::endl;
    ss << "B X: " << b.first.ToString() << std::endl;
    ss << "B Y: " << b.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json ECC_Point_Add::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_x"] = a.first.ToJSON();
    j["a_y"] = a.second.ToJSON();

    j["b_x"] = b.first.ToJSON();
    j["b_y"] = b.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string ECC_Point_Mul::Name(void) const { return "ECC_Point_Mul"; }
std::string ECC_Point_Mul::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: ECC_Point_Mul" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A X: " << a.first.ToString() << std::endl;
    ss << "A Y: " << a.second.ToString() << std::endl;
    ss << "B: " << b.ToString() << std::endl;

    return ss.str();
}

nlohmann::json ECC_Point_Mul::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_x"] = a.first.ToJSON();
    j["a_y"] = a.second.ToJSON();

    j["b"] = b.ToJSON();

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

std::string BLS_PrivateToPublic_G2::Name(void) const { return "BLS_PrivateToPublic_G2"; }
std::string BLS_PrivateToPublic_G2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_PrivateToPublic_G2" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "private key: " << priv.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_PrivateToPublic_G2::ToJSON(void) const {
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
    if ( hashOrPoint == true ) {
        ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    } else {
        ss << "point V: " << point.first.first.ToString() << std::endl;
        ss << "point W: " << point.first.second.ToString() << std::endl;
        ss << "point X: " << point.second.first.ToString() << std::endl;
        ss << "point Y: " << point.second.second.ToString() << std::endl;
    }
    ss << "dest: " << util::HexDump(dest.Get()) << std::endl;
    ss << "aug: " << util::HexDump(aug.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_Sign::ToJSON(void) const {
    nlohmann::json j;

    j["curveType"] = curveType.ToJSON();

    j["hashOrPoint"] = hashOrPoint;

    j["priv"] = priv.ToJSON();

    if ( hashOrPoint == true ) {
        j["cleartext"] = cleartext.ToJSON();
    } else {
        j["g2_v"] = point.first.first.ToJSON();
        j["g2_w"] = point.first.second.ToJSON();
        j["g2_x"] = point.second.first.ToJSON();
        j["g2_y"] = point.second.second.ToJSON();
    }
    j["dest"] = dest.ToJSON();
    j["aug"] = aug.ToJSON();

    j["modifier"] = modifier.ToJSON();

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
    ss << "signature V: " << signature.first.first.ToString() << std::endl;
    ss << "signature W: " << signature.first.second.ToString() << std::endl;
    ss << "signature X: " << signature.second.first.ToString() << std::endl;
    ss << "signature Y: " << signature.second.second.ToString() << std::endl;
    ss << "dest: " << util::HexDump(dest.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["cleartext"] = cleartext.ToJSON();

    j["g1_x"] = pub.first.ToJSON();
    j["g1_y"] = pub.second.ToJSON();

    j["g2_v"] = signature.first.first.ToJSON();
    j["g2_w"] = signature.first.second.ToJSON();
    j["g2_x"] = signature.second.first.ToJSON();
    j["g2_y"] = signature.second.second.ToJSON();

    j["dest"] = dest.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_Pairing::Name(void) const { return "BLS_Pairing"; }
std::string BLS_Pairing::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Pairing" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "G1 X: " << g1.first.ToString() << std::endl;
    ss << "G1 Y: " << g1.second.ToString() << std::endl;
    ss << "G2 V: " << g2.first.first.ToString() << std::endl;
    ss << "G2 W: " << g2.first.second.ToString() << std::endl;
    ss << "G2 X: " << g2.second.first.ToString() << std::endl;
    ss << "G2 Y: " << g2.second.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_Pairing::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    /* TODO q,p */
    return j;
}

std::string BLS_Aggregate_G1::Name(void) const { return "BLS_Aggregate_G1"; }
std::string BLS_Aggregate_G1::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Aggregate_G1" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;

    for (const auto& g1 : points.points) {
        ss << "    X: " << g1.first.ToString() << std::endl;
        ss << "    Y: " << g1.second.ToString() << std::endl;
        ss << std::endl;
    }

    return ss.str();
}

nlohmann::json BLS_Aggregate_G1::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();

    nlohmann::json points_json = nlohmann::json::array();

    for (const auto& g1 : points.points) {
        nlohmann::json point;

        point["x"] = g1.first.ToJSON();
        point["y"] = g1.second.ToJSON();

        points_json.push_back(point);
    }

    j["points"] = points_json;

    return j;
}

std::string BLS_Aggregate_G2::Name(void) const { return "BLS_Aggregate_G2"; }
std::string BLS_Aggregate_G2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Aggregate_G2" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;

    for (const auto& g2 : points.points) {
        ss << "    V:" << g2.first.first.ToString() << std::endl;
        ss << "    W:" << g2.first.second.ToString() << std::endl;
        ss << "    X:" << g2.second.first.ToString() << std::endl;
        ss << "    Y:" << g2.second.second.ToString() << std::endl;
        ss << std::endl;
    }

    return ss.str();
}

nlohmann::json BLS_Aggregate_G2::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();

    nlohmann::json points_json = nlohmann::json::array();

    for (const auto& g2 : points.points) {
        nlohmann::json point;

        point["v"] = g2.first.first.ToJSON();
        point["w"] = g2.first.second.ToJSON();
        point["x"] = g2.second.first.ToJSON();
        point["y"] = g2.second.second.ToJSON();

        points_json.push_back(point);
    }

    j["points"] = points_json;
    return j;
}

std::string BLS_HashToG1::Name(void) const { return "BLS_HashToG1"; }
std::string BLS_HashToG1::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_HashToG1" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "dest: " << util::HexDump(dest.Get()) << std::endl;
    ss << "aug: " << util::HexDump(aug.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_HashToG1::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["dest"] = dest.ToJSON();
    j["aug"] = aug.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_HashToG2::Name(void) const { return "BLS_HashToG2"; }
std::string BLS_HashToG2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_HashToG2" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "dest: " << util::HexDump(dest.Get()) << std::endl;
    ss << "aug: " << util::HexDump(aug.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_HashToG2::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["dest"] = dest.ToJSON();
    j["aug"] = aug.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_IsG1OnCurve::Name(void) const { return "BLS_IsG1OnCurve"; }
std::string BLS_IsG1OnCurve::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_IsG1OnCurve" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "G1 X: " << g1.first.ToString() << std::endl;
    ss << "G1 Y: " << g1.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_IsG1OnCurve::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["g1_x"] = g1.first.ToJSON();
    j["g1_y"] = g1.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_IsG2OnCurve::Name(void) const { return "BLS_IsG2OnCurve"; }
std::string BLS_IsG2OnCurve::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_IsG2OnCurve" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "G2 V: " << g2.first.first.ToString() << std::endl;
    ss << "G2 W: " << g2.first.second.ToString() << std::endl;
    ss << "G2 X: " << g2.second.first.ToString() << std::endl;
    ss << "G2 Y: " << g2.second.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_IsG2OnCurve::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["g2_v"] = g2.first.first.ToJSON();
    j["g2_w"] = g2.first.second.ToJSON();
    j["g2_x"] = g2.second.first.ToJSON();
    j["g2_y"] = g2.second.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_GenerateKeyPair::Name(void) const { return "BLS_GenerateKeyPair"; }
std::string BLS_GenerateKeyPair::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_GenerateKeyPair" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "ikm: " << util::HexDump(ikm.Get()) << std::endl;
    ss << "info: " << util::HexDump(info.Get()) << std::endl;

    return ss.str();
}

nlohmann::json BLS_GenerateKeyPair::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["modifier"] = modifier.ToJSON();
    j["ikm"] = ikm.ToJSON();
    j["info"] = info.ToJSON();
    return j;
}

std::string BLS_Decompress_G1::Name(void) const { return "BLS_Decompress_G1"; }
std::string BLS_Decompress_G1::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Decompress_G1" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "compressed: " << compressed.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_Decompress_G1::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["compressed"] = compressed.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_Compress_G1::Name(void) const { return "BLS_Compress_G1"; }
std::string BLS_Compress_G1::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Compress_G1" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "uncompressed X:" << uncompressed.first.ToString() << std::endl;
    ss << "uncompressed Y:" << uncompressed.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_Compress_G1::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["g1_x"] = uncompressed.first.ToJSON();
    j["g1_y"] = uncompressed.second.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_Decompress_G2::Name(void) const { return "BLS_Decompress_G2"; }
std::string BLS_Decompress_G2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Decompress_G2" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "compressed X: " << compressed.first.ToString() << std::endl;
    ss << "compressed Y: " << compressed.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_Decompress_G2::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["g1_x"] = compressed.first.ToJSON();
    j["g1_y"] = compressed.second.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_Compress_G2::Name(void) const { return "BLS_Compress_G2"; }
std::string BLS_Compress_G2::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_Compress_G2" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "uncompressed V:" << uncompressed.first.first.ToString() << std::endl;
    ss << "uncompressed W:" << uncompressed.first.second.ToString() << std::endl;
    ss << "uncompressed X:" << uncompressed.second.first.ToString() << std::endl;
    ss << "uncompressed Y:" << uncompressed.second.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_Compress_G2::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();
    j["g2_v"] = uncompressed.first.first.ToJSON();
    j["g2_w"] = uncompressed.first.second.ToJSON();
    j["g2_x"] = uncompressed.second.first.ToJSON();
    j["g2_y"] = uncompressed.second.second.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G1_Add::Name(void) const { return "BLS_G1_Add"; }
std::string BLS_G1_Add::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G1_Add" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A X: " << a.first.ToString() << std::endl;
    ss << "A Y: " << a.second.ToString() << std::endl;
    ss << "B X: " << b.first.ToString() << std::endl;
    ss << "B Y: " << b.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G1_Add::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_x"] = a.first.ToJSON();
    j["a_y"] = a.second.ToJSON();

    j["b_x"] = b.first.ToJSON();
    j["b_y"] = b.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G1_Mul::Name(void) const { return "BLS_G1_Mul"; }
std::string BLS_G1_Mul::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G1_Mul" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A X: " << a.first.ToString() << std::endl;
    ss << "A Y: " << a.second.ToString() << std::endl;
    ss << "B: " << b.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G1_Mul::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_x"] = a.first.ToJSON();
    j["a_y"] = a.second.ToJSON();

    j["b"] = b.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G1_IsEq::Name(void) const { return "BLS_G1_IsEq"; }
std::string BLS_G1_IsEq::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G1_IsEq" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A X: " << a.first.ToString() << std::endl;
    ss << "A Y: " << a.second.ToString() << std::endl;
    ss << "B X: " << b.first.ToString() << std::endl;
    ss << "B Y: " << b.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G1_IsEq::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_x"] = a.first.ToJSON();
    j["a_y"] = a.second.ToJSON();

    j["b_x"] = b.first.ToJSON();
    j["b_y"] = b.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G1_Neg::Name(void) const { return "BLS_G1_Neg"; }
std::string BLS_G1_Neg::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G1_Neg" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A X: " << a.first.ToString() << std::endl;
    ss << "A Y: " << a.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G1_Neg::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_x"] = a.first.ToJSON();
    j["a_y"] = a.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G2_Add::Name(void) const { return "BLS_G2_Add"; }
std::string BLS_G2_Add::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G2_Add" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A V:" << a.first.first.ToString() << std::endl;
    ss << "A W:" << a.first.second.ToString() << std::endl;
    ss << "A X:" << a.second.first.ToString() << std::endl;
    ss << "A Y:" << a.second.second.ToString() << std::endl;
    ss << "B V:" << b.first.first.ToString() << std::endl;
    ss << "B W:" << b.first.second.ToString() << std::endl;
    ss << "B X:" << b.second.first.ToString() << std::endl;
    ss << "B Y:" << b.second.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G2_Add::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_v"] = a.first.first.ToJSON();
    j["a_w"] = a.first.second.ToJSON();
    j["a_x"] = a.second.first.ToJSON();
    j["a_y"] = a.second.second.ToJSON();

    j["b_v"] = b.first.first.ToJSON();
    j["b_w"] = b.first.second.ToJSON();
    j["b_x"] = b.second.first.ToJSON();
    j["b_y"] = b.second.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G2_Mul::Name(void) const { return "BLS_G2_Mul"; }
std::string BLS_G2_Mul::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G2_Mul" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A V:" << a.first.first.ToString() << std::endl;
    ss << "A W:" << a.first.second.ToString() << std::endl;
    ss << "A X:" << a.second.first.ToString() << std::endl;
    ss << "A Y:" << a.second.second.ToString() << std::endl;
    ss << "B: " << b.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G2_Mul::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_v"] = a.first.first.ToJSON();
    j["a_w"] = a.first.second.ToJSON();
    j["a_x"] = a.second.first.ToJSON();
    j["a_y"] = a.second.second.ToJSON();

    j["b"] = b.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G2_IsEq::Name(void) const { return "BLS_G2_IsEq"; }
std::string BLS_G2_IsEq::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G2_IsEq" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A V:" << a.first.first.ToString() << std::endl;
    ss << "A W:" << a.first.second.ToString() << std::endl;
    ss << "A X:" << a.second.first.ToString() << std::endl;
    ss << "A Y:" << a.second.second.ToString() << std::endl;
    ss << "B V:" << b.first.first.ToString() << std::endl;
    ss << "B W:" << b.first.second.ToString() << std::endl;
    ss << "B X:" << b.second.first.ToString() << std::endl;
    ss << "B Y:" << b.second.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G2_IsEq::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_v"] = a.first.first.ToJSON();
    j["a_w"] = a.first.second.ToJSON();
    j["a_x"] = a.second.first.ToJSON();
    j["a_y"] = a.second.second.ToJSON();

    j["b_v"] = b.first.first.ToJSON();
    j["b_w"] = b.first.second.ToJSON();
    j["b_x"] = b.second.first.ToJSON();
    j["b_y"] = b.second.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string BLS_G2_Neg::Name(void) const { return "BLS_G2_Neg"; }
std::string BLS_G2_Neg::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: BLS_G2_Neg" << std::endl;
    ss << "ecc curve: " << repository::ECC_CurveToString(curveType.Get()) << std::endl;
    ss << "A V:" << a.first.first.ToString() << std::endl;
    ss << "A W:" << a.first.second.ToString() << std::endl;
    ss << "A X:" << a.second.first.ToString() << std::endl;
    ss << "A Y:" << a.second.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json BLS_G2_Neg::ToJSON(void) const {
    nlohmann::json j;
    j["curveType"] = curveType.ToJSON();

    j["a_v"] = a.first.first.ToJSON();
    j["a_w"] = a.first.second.ToJSON();
    j["a_x"] = a.second.first.ToJSON();
    j["a_y"] = a.second.second.ToJSON();

    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string Misc::Name(void) const { return "Misc"; }
std::string Misc::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: Misc" << std::endl;
    ss << "operation: " << std::to_string(operation.Get()) << std::endl;

    return ss.str();
}

nlohmann::json Misc::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = operation.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

std::string SR25519_Verify::Name(void) const { return "ECDSA_Verify"; }
std::string SR25519_Verify::ToString(void) const {
    std::stringstream ss;

    ss << "operation name: SR25519_Verify" << std::endl;
    ss << "public key: " << signature.pub.ToString() << std::endl;
    ss << "cleartext: " << util::HexDump(cleartext.Get()) << std::endl;
    ss << "signature R: " << signature.signature.first.ToString() << std::endl;
    ss << "signature S: " << signature.signature.second.ToString() << std::endl;

    return ss.str();
}

nlohmann::json SR25519_Verify::ToJSON(void) const {
    nlohmann::json j;
    j["operation"] = "SR25519_Verify";
    j["pub"] = signature.pub.ToJSON();
    j["cleartext"] = cleartext.ToJSON();
    j["sig_r"] = signature.signature.first.ToJSON();
    j["sig_s"] = signature.signature.second.ToJSON();
    j["modifier"] = modifier.ToJSON();
    return j;
}

} /* namespace operation */
} /* namespace cryptofuzz */
