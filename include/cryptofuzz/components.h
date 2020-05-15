#pragma once

#include <cryptofuzz/generic.h>
#include <cryptofuzz/util_hexdump.h>
#include <fuzzing/datasource/datasource.hpp>
#include "../../third_party/json/json.hpp"

namespace cryptofuzz {
namespace component {

using SymmetricCipherType = Type;
using AsymmetricCipherType = Type;
using DigestType = Type;
using KDFType = Type;
using CurveType = Type;
using CalcOp = Type;

using Modifier = Buffer;
using Cleartext = Buffer;
using Digest = Buffer;
using MAC = Buffer;
using SymmetricIV = Buffer;
using SymmetricKey = Buffer;
using AsymmetricPrivKey = Buffer;
using Key = Buffer;
using Envelope = Buffer;
using Signature = Buffer;
using PrivateKeyPEM = Buffer;
using Tag = Buffer;
using AAD = Buffer;
using Secret = Buffer;

using ECC_PrivateKey = Bignum;
using Bignum = ::cryptofuzz::Bignum;

class SymmetricCipher {
    public:
        const SymmetricIV iv;
        const SymmetricKey key;
        const SymmetricCipherType cipherType;
        SymmetricCipher(Datasource& ds) :
            iv(ds),
            key(ds),
            cipherType(ds)
        { }
        SymmetricCipher(nlohmann::json json) :
            iv(json["iv"]),
            key(json["key"]),
            cipherType(json["cipherType"])
        { }
        nlohmann::json ToJSON(void) const {
            nlohmann::json j;
            j["iv"] = iv.ToJSON();
            j["key"] = key.ToJSON();
            j["cipherType"] = cipherType.ToJSON();
            return j;
        }
        inline bool operator==(const SymmetricCipher& rhs) const {
            return
                (iv == rhs.iv) &&
                (key == rhs.key) &&
                (cipherType == rhs.cipherType);
        }
};

class AsymmetricCipher {
    public:
        const AsymmetricPrivKey privKey;
        const AsymmetricCipherType cipherType;
        AsymmetricCipher(Datasource& ds) :
            privKey(ds),
            cipherType(ds)
        { }
};

class Ciphertext {
    public:
        Buffer ciphertext;
        std::optional<Tag> tag;

        Ciphertext(Datasource& ds) :
            ciphertext(ds),
            tag( ds.Get<bool>() ? std::nullopt : std::make_optional<Tag>(ds) )
        { }

        Ciphertext(Buffer ciphertext, std::optional<Tag> tag = std::nullopt) :
            ciphertext(ciphertext),
            tag(tag)
        { }

        inline bool operator==(const Ciphertext& rhs) const {
            return (ciphertext == rhs.ciphertext) && (tag == rhs.tag);
        }
};

class BignumPair {
    public:
        Bignum first, second;

        BignumPair(Datasource& ds) :
            first(ds),
            second(ds)
        { }

        BignumPair(const std::string first, const std::string second) :
            first(first),
            second(second)
        { }

        BignumPair(nlohmann::json json) :
            first(json[0].get<std::string>()),
            second(json[1].get<std::string>())
        { }


        inline bool operator==(const BignumPair& rhs) const {
            return
                (first == rhs.first) &&
                (second == rhs.second);
        }
};

using ECC_PublicKey = BignumPair;

class ECC_KeyPair {
    public:
        ECC_PrivateKey priv;
        ECC_PublicKey pub;

        ECC_KeyPair(Datasource& ds) :
            priv(ds),
            pub(ds)
        { }

        ECC_KeyPair(ECC_PrivateKey priv, BignumPair pub) :
            priv(priv),
            pub(pub)
        { }

        inline bool operator==(const ECC_KeyPair& rhs) const {
            return
                (priv == rhs.priv) &&
                (pub == rhs.pub);
        }
};

using ECDSA_Signature = BignumPair;

class MACType {
    public:
        bool mode;
        Type type;

        MACType(Datasource& ds) :
            mode(ds.Get<bool>()),
            type(ds)
        { }

        MACType(nlohmann::json json) :
            mode(json["mode"].get<bool>()),
            type(json["type"])
        { }

        nlohmann::json ToJSON(void) const {
            nlohmann::json j;
            j["mode"] = mode;
            j["type"] = type.ToJSON();
            return j;
        }

        inline bool operator==(const MACType& rhs) const {
            return
                (mode == rhs.mode) &&
                (type == rhs.type);
        }
};

} /* namespace component */
} /* namespace cryptofuzz */
