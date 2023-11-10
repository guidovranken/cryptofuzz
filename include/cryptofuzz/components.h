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
using Key3 = std::array<Key, 3>;
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
        ECC_KeyPair(nlohmann::json json);

        bool operator==(const ECC_KeyPair& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class ECCSI_Signature {
    public:
        BignumPair signature;
        ECC_PublicKey pub;
        BignumPair pvt;

        ECCSI_Signature(Datasource& ds);
        ECCSI_Signature(BignumPair signature, ECC_PublicKey pub, BignumPair pvt);
        ECCSI_Signature(nlohmann::json json);

        bool operator==(const ECCSI_Signature& rhs) const;
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

class DSA_Parameters {
    public:
        Bignum p, q, g;

        DSA_Parameters(Datasource& ds) :
            p(ds),
            q(ds),
            g(ds)
        { }

        DSA_Parameters(
        std::string p,
        std::string q,
        std::string g) :
            p(p),
            q(q),
            g(g)
        { }
        DSA_Parameters(nlohmann::json json);

        inline bool operator==(const DSA_Parameters& rhs) const {
            return
                (p == rhs.p) &&
                (q == rhs.q) &&
                (g == rhs.g);
        }
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class DSA_Signature {
    public:
        BignumPair signature;
        Bignum pub;

        DSA_Signature(Datasource& ds);
        DSA_Signature(BignumPair signature, Bignum pub);
        DSA_Signature(nlohmann::json json);

        bool operator==(const DSA_Signature& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

using DSA_KeyPair = BignumPair;

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

using Fp2 = BignumPair;

class Fp12 {
    public:
        Bignum bn1;
        Bignum bn2;
        Bignum bn3;
        Bignum bn4;
        Bignum bn5;
        Bignum bn6;
        Bignum bn7;
        Bignum bn8;
        Bignum bn9;
        Bignum bn10;
        Bignum bn11;
        Bignum bn12;

        Fp12(Datasource& ds) :
            bn1(ds),
            bn2(ds),
            bn3(ds),
            bn4(ds),
            bn5(ds),
            bn6(ds),
            bn7(ds),
            bn8(ds),
            bn9(ds),
            bn10(ds),
            bn11(ds),
            bn12(ds)
        { }

        Fp12(
        std::string bn1,
        std::string bn2,
        std::string bn3,
        std::string bn4,
        std::string bn5,
        std::string bn6,
        std::string bn7,
        std::string bn8,
        std::string bn9,
        std::string bn10,
        std::string bn11,
        std::string bn12) :
            bn1(bn1),
            bn2(bn2),
            bn3(bn3),
            bn4(bn4),
            bn5(bn5),
            bn6(bn6),
            bn7(bn7),
            bn8(bn8),
            bn9(bn9),
            bn10(bn10),
            bn11(bn11),
            bn12(bn12)
        { }
        Fp12(nlohmann::json json);

        inline bool operator==(const Fp12& rhs) const {
            return
                (bn1 == rhs.bn1) &&
                (bn2 == rhs.bn2) &&
                (bn3 == rhs.bn3) &&
                (bn4 == rhs.bn4) &&
                (bn5 == rhs.bn5) &&
                (bn6 == rhs.bn6) &&
                (bn7 == rhs.bn7) &&
                (bn8 == rhs.bn8) &&
                (bn9 == rhs.bn9) &&
                (bn10 == rhs.bn10) &&
                (bn11 == rhs.bn11) &&
                (bn12 == rhs.bn12);
        }
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
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

class BLS_BatchSignature {
    public:
        std::vector< std::pair<G1, G2> > msgpub;

        BLS_BatchSignature(std::vector< std::pair<G1, G2> > msgpub);

        bool operator==(const BLS_BatchSignature& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class BLS_BatchSign_Vector {
    public:
        typedef struct {
            Bignum priv;
            G1 g1;
        } BatchSign_single;
        std::vector<BatchSign_single> c;

        BLS_BatchSign_Vector(Datasource& ds);
        BLS_BatchSign_Vector(G1 g1, G2 g2);
        BLS_BatchSign_Vector(nlohmann::json json);

        bool operator==(const BLS_BatchSign_Vector& rhs) const;
        void Serialize(Datasource& ds) const;
        nlohmann::json ToJSON(void) const;
};

class BLS_BatchVerify_Vector {
    public:
        typedef struct {
            G1 g1;
            G2 g2;
        } BatchVerify_single;
        std::vector<BatchVerify_single> c;

        BLS_BatchVerify_Vector(Datasource& ds);
        BLS_BatchVerify_Vector(G1 g1, G2 g2);
        BLS_BatchVerify_Vector(nlohmann::json json);

        bool operator==(const BLS_BatchVerify_Vector& rhs) const;
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

class BLS_G1_Scalar_Vector {
    public:
        std::vector< std::pair<component::G1, component::Bignum> > points_scalars;

        BLS_G1_Scalar_Vector(Datasource& ds);
        BLS_G1_Scalar_Vector(nlohmann::json json);

        bool operator==(const BLS_G1_Scalar_Vector& rhs) const;
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
