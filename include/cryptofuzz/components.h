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

} /* namespace component */
} /* namespace cryptofuzz */
