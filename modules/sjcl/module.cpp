#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>
#include "sjcl.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

sjcl::sjcl(void) :
    Module("sjcl"),
    js(new JS()) {

    const std::vector<uint8_t> bc(sjcl_bytecode, sjcl_bytecode + sjcl_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

sjcl::~sjcl(void) {
    delete (JS*)js;
}

template <class T> std::optional<T> getResultAs(const std::string& s) {
    return T(nlohmann::json::parse(s));
}

template <class ReturnType, class OperationType, uint64_t OperationID>
std::optional<ReturnType> Run(JS* js, OperationType& op) {
    std::optional<ReturnType> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string( OperationID );

    const auto res = js->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = getResultAs<ReturnType>(*res);
    }

    return ret;
}

std::optional<component::Digest> sjcl::OpDigest(operation::Digest& op) {
    return Run<component::Digest, operation::Digest, CF_OPERATION("Digest")>((JS*)js, op);
}

std::optional<component::MAC> sjcl::OpHMAC(operation::HMAC& op) {
    return Run<component::MAC, operation::HMAC, CF_OPERATION("HMAC")>((JS*)js, op);
}

std::optional<component::Ciphertext> sjcl::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    return Run<component::Ciphertext, operation::SymmetricEncrypt, CF_OPERATION("SymmetricEncrypt")>((JS*)js, op);
}

std::optional<component::Cleartext> sjcl::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    return Run<component::Cleartext, operation::SymmetricDecrypt, CF_OPERATION("SymmetricDecrypt")>((JS*)js, op);
}

std::optional<component::Key> sjcl::OpKDF_HKDF(operation::KDF_HKDF& op) {
    return Run<component::Key, operation::KDF_HKDF, CF_OPERATION("KDF_HKDF")>((JS*)js, op);
}

std::optional<component::Key> sjcl::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    return Run<component::Key, operation::KDF_PBKDF2, CF_OPERATION("KDF_PBKDF2")>((JS*)js, op);
}

std::optional<component::Key> sjcl::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    return Run<component::Key, operation::KDF_SCRYPT, CF_OPERATION("KDF_SCRYPT")>((JS*)js, op);
}

int HexCharToDec(const char c) {
    if ( c >= '0' && c <= '9' ) {
        return c - '0';
    } else if ( c >= 'a' && c <= 'f' ) {
        return c - 'a' + 10;
    } else if ( c >= 'A' && c <= 'F' ) {
        return c - 'A' + 10;
    } else {
        abort();
    }
}

std::string HexToDec(std::string s) {
    std::string ret;
    bool negative = false;

    if ( s.empty() ) {
        return ret;
    }

    if ( s.size() >= 2 && s[0] == '0' && s[1] == 'x' ) {
        s = s.substr(2);
    }

    if ( s.size() >= 1 && s[0] == '-' ) {
        s = s.substr(1);
        negative = true;
    }

    boost::multiprecision::cpp_int total;

    for (long i = s.size() - 1; i >= 0; i--) {
        total += boost::multiprecision::cpp_int(HexCharToDec(s[i])) << ((s.size()-i-1)*4);
    }

    std::stringstream ss;
    if ( negative ) ss << "-";
    ss << total;

    return ss.str();
}

std::string DecToHex(const std::string s) {
    static const char* hexDigits = "0123456789ABCDEF";

    std::string ret;

    boost::multiprecision::cpp_int i(s);

    while ( i > 0 ) {
        const size_t mod16 = (i % 16).convert_to<size_t>();
        ret = hexDigits[mod16] + ret;
        i /= 16;
    }

    if ( ret.empty() ) {
        return "0";
    }

    return ret;
}

std::optional<component::Bignum> sjcl::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    nlohmann::json json;
    json["operation"] = std::to_string( CF_OPERATION("BignumCalc") );
    json["calcOp"] = std::to_string(op.calcOp.Get());
    json["bn0"] = DecToHex(op.bn0.ToTrimmedString());
    json["bn1"] = DecToHex(op.bn1.ToTrimmedString());
    json["bn2"] = DecToHex(op.bn2.ToTrimmedString());
    json["bn3"] = DecToHex(op.bn3.ToTrimmedString());

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = HexToDec(std::string(nlohmann::json::parse(*res)));
    }

    return ret;
}

std::optional<component::ECC_PublicKey> sjcl::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    nlohmann::json json;
    json["operation"] = std::to_string( CF_OPERATION("ECC_PrivateToPublic") );
    json["curveType"] = op.curveType.Get();
    json["priv"] = DecToHex(op.priv.ToTrimmedString());

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        const auto parsed = nlohmann::json::parse(*res);
        ret = {HexToDec(parsed[0]), HexToDec(parsed[1])};
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
