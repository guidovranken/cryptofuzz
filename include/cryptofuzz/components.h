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

using ECC_Point = BignumPair;

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

using ECGDSA_Signature = ECDSA_Signature;
using ECRDSA_Signature = ECDSA_Signature;
using Schnorr_Signature = ECDSA_Signature;

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

class G2 {
    public:
        BignumPair first, second;

        G2(Datasource& ds) :
            first(ds),
            second(ds)
        { }

        G2(const std::string a_first, const std::string a_second, const std::string b_first, const std::string b_second) :
            first(a_first, a_second),
            second(b_first, b_second)
        { }

        inline bool operator==(const G2& rhs) const {
            return
                (first == rhs.first) &&
                (second == rhs.second);
        }
        G2(nlohmann::json json);
        nlohmann::json ToJSON(void) const;
        void Serialize(Datasource& ds) const;
};

class BLS_Signature {
    public:
        G2 signature;
        ECC_PublicKey pub;

        BLS_Signature(Datasource& ds);
        BLS_Signature(G2 signature, ECC_PublicKey pub);
        BLS_Signature(nlohmann::json json);

        bool operator==(const BLS_Signature& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

using BLS_PrivateKey = Bignum;
using BLS_PublicKey = BignumPair;
using G1 = BignumPair;

class BLS_KeyPair {
    public:
        BLS_PrivateKey priv;
        BLS_PublicKey pub;

        BLS_KeyPair(Datasource& ds);
        BLS_KeyPair(BLS_PrivateKey priv, BignumPair pub);

        bool operator==(const BLS_KeyPair& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class BLS_PairingComponents {
    public:
        typedef struct {
            G2 sig;
            BLS_PublicKey pub;
            Cleartext msg;
            Cleartext aug;
        } Component;
        std::vector<Component> c;

        BLS_PairingComponents(Datasource& ds);
        BLS_PairingComponents(G2 sig, BLS_PublicKey pub, Cleartext msg, Cleartext aug);
        BLS_PairingComponents(nlohmann::json json);

        bool operator==(const BLS_PairingComponents& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class BLS_G1_Vector {
    public:
        std::vector<component::G1> points;

        BLS_G1_Vector(Datasource& ds);
        BLS_G1_Vector(nlohmann::json json);

        bool operator==(const BLS_G1_Vector& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class BLS_G2_Vector {
    public:
        std::vector<component::G2> points;

        BLS_G2_Vector(Datasource& ds);
        BLS_G2_Vector(nlohmann::json json);

        bool operator==(const BLS_G2_Vector& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class SR25519_Signature {
    public:
        BignumPair signature;
        Bignum pub;

        SR25519_Signature(Datasource& ds);
        SR25519_Signature(BignumPair signature, Bignum pub);
        SR25519_Signature(nlohmann::json json);

        bool operator==(const SR25519_Signature& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

} /* namespace component */
} /* namespace cryptofuzz */
