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
        SymmetricCipher(Datasource& ds);
        SymmetricCipher(nlohmann::json json);
        nlohmann::json ToJSON(void) const;

        bool operator==(const SymmetricCipher& rhs) const;
        void Serialize(Datasource& ds) const;
};

class Ciphertext {
    public:
        Buffer ciphertext;
        std::optional<Tag> tag;

        Ciphertext(Datasource& ds);
        Ciphertext(Buffer ciphertext, std::optional<Tag> tag = std::nullopt);

        bool operator==(const Ciphertext& rhs) const;
        void Serialize(Datasource& ds) const;
};

class BignumPair {
    public:
        Bignum first, second;

        BignumPair(Datasource& ds);
        BignumPair(const std::string first, const std::string second);
        BignumPair(nlohmann::json json);

        bool operator==(const BignumPair& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

using ECC_PublicKey = BignumPair;

class ECC_KeyPair {
    public:
        ECC_PrivateKey priv;
        ECC_PublicKey pub;

        ECC_KeyPair(Datasource& ds);
        ECC_KeyPair(ECC_PrivateKey priv, BignumPair pub);

        bool operator==(const ECC_KeyPair& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};


class ECDSA_Signature {
    public:
        BignumPair signature;
        ECC_PublicKey pub;

        ECDSA_Signature(Datasource& ds);
        ECDSA_Signature(BignumPair signature, ECC_PublicKey pub);
        ECDSA_Signature(nlohmann::json json);

        bool operator==(const ECDSA_Signature& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class MACType {
    public:
        bool mode;
        Type type;

        MACType(Datasource& ds);
        MACType(nlohmann::json json);
        nlohmann::json ToJSON(void) const;
        bool operator==(const MACType& rhs) const;
        void Serialize(Datasource& ds) const;
};

using DH_Key = BignumPair;
using DH_KeyPair = BignumPair;

} /* namespace component */
} /* namespace cryptofuzz */
