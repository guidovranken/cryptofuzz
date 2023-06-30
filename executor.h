#pragma once

#include <cryptofuzz/module.h>
#include <cryptofuzz/options.h>
#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <map>
#include <memory>
#include <utility>
#include <vector>

namespace cryptofuzz {

template <class ResultType, class OperationType>
class ExecutorBase {
    private:
        const uint64_t operationID;
        const std::map<uint64_t, std::shared_ptr<Module> > modules;
    protected:
        const Options& options;
    private:
        using ResultPair = std::pair< std::shared_ptr<Module>, std::optional<ResultType> >;
        using ResultSet = std::vector<ResultPair>;

        ResultSet filter(const ResultSet& results) const;
        bool dontCompare(const OperationType& operation) const;
        void compare(const std::vector< std::pair<std::shared_ptr<Module>, OperationType> >& operations, const ResultSet& results, const uint8_t* data, const size_t size) const;
        OperationType getOp(Datasource* parentDs, const uint8_t* data, const size_t size) const;
        virtual OperationType getOpPostprocess(Datasource* parentDs, OperationType op) const;
        std::shared_ptr<Module> getModule(Datasource& ds) const;

        /* To be implemented by specializations of ExecutorBase */
        void updateExtraCounters(const uint64_t moduleID, OperationType& op) const;
        void postprocess(std::shared_ptr<Module> module, OperationType& op, const ResultPair& result) const;
        virtual std::optional<ResultType> callModule(std::shared_ptr<Module> module, OperationType& op) const {
            (void)module;
            (void)op;
            ::abort();
        }

        void abort(std::vector<std::string> moduleNames, const std::string operation, const std::string algorithm, const std::string reason) const;
    public:
        void Run(Datasource& parentDs, const uint8_t* data, const size_t size) const;
        ExecutorBase(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        virtual ~ExecutorBase();
};

class ExecutorBignumCalc : public ExecutorBase<component::Bignum, operation::BignumCalc> {
    private:
        std::optional<component::Bignum> callModule(std::shared_ptr<Module> module, operation::BignumCalc& op) const override;
    protected:
        std::optional<component::Bignum> modulo = std::nullopt;
    public:
        ExecutorBignumCalc(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        void SetModulo(const std::string& modulo);
};

class ExecutorBignumCalc_Mod_BLS12_381_R : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_BLS12_381_R(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_BLS12_381_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_BLS12_381_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_BLS12_377_R : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_BLS12_377_R(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_BLS12_377_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_BLS12_377_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_BN128_R : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_BN128_R(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_BN128_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_BN128_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_Vesta_R : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_Vesta_R(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_Vesta_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_Vesta_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_ED25519 : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_ED25519(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_Edwards_R : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_Edwards_R(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_Edwards_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_Edwards_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_Goldilocks : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_Goldilocks(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_MNT4_R : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_MNT4_R(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_MNT4_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_MNT4_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_MNT6_R : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_MNT6_R(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_MNT6_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_MNT6_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_2Exp64 : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_2Exp64(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_2Exp128 : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_2Exp128(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_2Exp256 : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_2Exp256(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_2Exp512 : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_2Exp512(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_SECP256K1 : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_SECP256K1(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Mod_SECP256K1_P : public ExecutorBignumCalc {
    public:
        ExecutorBignumCalc_Mod_SECP256K1_P(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        operation::BignumCalc getOpPostprocess(Datasource* parentDs, operation::BignumCalc op) const override;
};

class ExecutorBignumCalc_Fp2 : public ExecutorBase<component::Fp2, operation::BignumCalc_Fp2> {
    private:
        std::optional<component::Fp2> callModule(std::shared_ptr<Module> module, operation::BignumCalc_Fp2& op) const override;
    protected:
        std::optional<component::Bignum> modulo = std::nullopt;
    public:
        ExecutorBignumCalc_Fp2(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        void SetModulo(const std::string& modulo);
};

class ExecutorBignumCalc_Fp12 : public ExecutorBase<component::Fp12, operation::BignumCalc_Fp12> {
    private:
        std::optional<component::Fp12> callModule(std::shared_ptr<Module> module, operation::BignumCalc_Fp12& op) const override;
    protected:
        std::optional<component::Bignum> modulo = std::nullopt;
    public:
        ExecutorBignumCalc_Fp12(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        void SetModulo(const std::string& modulo);
};

/* Declare aliases */
using ExecutorDigest = ExecutorBase<component::Digest, operation::Digest>;
using ExecutorHMAC = ExecutorBase<component::MAC, operation::HMAC>;
using ExecutorUMAC = ExecutorBase<component::MAC, operation::UMAC>;
using ExecutorCMAC = ExecutorBase<component::MAC, operation::CMAC>;
using ExecutorSymmetricEncrypt = ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>;
using ExecutorSymmetricDecrypt = ExecutorBase<component::Cleartext, operation::SymmetricDecrypt>;
using ExecutorKDF_SCRYPT = ExecutorBase<component::Key, operation::KDF_SCRYPT>;
using ExecutorKDF_HKDF = ExecutorBase<component::Key, operation::KDF_HKDF>;
using ExecutorKDF_TLS1_PRF = ExecutorBase<component::Key, operation::KDF_TLS1_PRF>;
using ExecutorKDF_PBKDF = ExecutorBase<component::Key, operation::KDF_PBKDF>;
using ExecutorKDF_PBKDF1 = ExecutorBase<component::Key, operation::KDF_PBKDF1>;
using ExecutorKDF_PBKDF2 = ExecutorBase<component::Key, operation::KDF_PBKDF2>;
using ExecutorKDF_ARGON2 = ExecutorBase<component::Key, operation::KDF_ARGON2>;
using ExecutorKDF_SSH = ExecutorBase<component::Key, operation::KDF_SSH>;
using ExecutorKDF_X963 = ExecutorBase<component::Key, operation::KDF_X963>;
using ExecutorKDF_BCRYPT = ExecutorBase<component::Key, operation::KDF_BCRYPT>;
using ExecutorKDF_SP_800_108 = ExecutorBase<component::Key, operation::KDF_SP_800_108>;
using ExecutorECC_PrivateToPublic = ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>;
using ExecutorECC_ValidatePubkey = ExecutorBase<bool, operation::ECC_ValidatePubkey>;
using ExecutorECC_GenerateKeyPair = ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>;
using ExecutorECCSI_Sign = ExecutorBase<component::ECCSI_Signature, operation::ECCSI_Sign>;
using ExecutorECDSA_Sign = ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>;
using ExecutorECGDSA_Sign = ExecutorBase<component::ECGDSA_Signature, operation::ECGDSA_Sign>;
using ExecutorECRDSA_Sign = ExecutorBase<component::ECRDSA_Signature, operation::ECRDSA_Sign>;
using ExecutorSchnorr_Sign = ExecutorBase<component::Schnorr_Signature, operation::Schnorr_Sign>;
using ExecutorECCSI_Verify = ExecutorBase<bool, operation::ECCSI_Verify>;
using ExecutorECDSA_Verify = ExecutorBase<bool, operation::ECDSA_Verify>;
using ExecutorECGDSA_Verify = ExecutorBase<bool, operation::ECGDSA_Verify>;
using ExecutorECRDSA_Verify = ExecutorBase<bool, operation::ECRDSA_Verify>;
using ExecutorSchnorr_Verify = ExecutorBase<bool, operation::Schnorr_Verify>;
using ExecutorECDSA_Recover = ExecutorBase<component::ECC_PublicKey, operation::ECDSA_Recover>;
using ExecutorDSA_Verify = ExecutorBase<bool, operation::DSA_Verify>;
using ExecutorDSA_Sign = ExecutorBase<component::DSA_Signature, operation::DSA_Sign>;
using ExecutorDSA_GenerateParameters = ExecutorBase<component::DSA_Parameters, operation::DSA_GenerateParameters>;
using ExecutorDSA_PrivateToPublic = ExecutorBase<component::Bignum, operation::DSA_PrivateToPublic>;
using ExecutorDSA_GenerateKeyPair = ExecutorBase<component::DSA_KeyPair, operation::DSA_GenerateKeyPair>;
using ExecutorECDH_Derive = ExecutorBase<component::Secret, operation::ECDH_Derive>;
using ExecutorECIES_Encrypt = ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>;
using ExecutorECIES_Decrypt = ExecutorBase<component::Cleartext, operation::ECIES_Decrypt>;
using ExecutorECC_Point_Add = ExecutorBase<component::ECC_Point, operation::ECC_Point_Add>;
using ExecutorECC_Point_Sub = ExecutorBase<component::ECC_Point, operation::ECC_Point_Sub>;
using ExecutorECC_Point_Mul = ExecutorBase<component::ECC_Point, operation::ECC_Point_Mul>;
using ExecutorECC_Point_Neg = ExecutorBase<component::ECC_Point, operation::ECC_Point_Neg>;
using ExecutorECC_Point_Dbl = ExecutorBase<component::ECC_Point, operation::ECC_Point_Dbl>;
using ExecutorECC_Point_Cmp = ExecutorBase<bool, operation::ECC_Point_Cmp>;
using ExecutorDH_GenerateKeyPair = ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>;
using ExecutorDH_Derive = ExecutorBase<component::Bignum, operation::DH_Derive>;
using ExecutorBLS_PrivateToPublic = ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>;
using ExecutorBLS_PrivateToPublic_G2 = ExecutorBase<component::G2, operation::BLS_PrivateToPublic_G2>;
using ExecutorBLS_Sign = ExecutorBase<component::BLS_Signature, operation::BLS_Sign>;
using ExecutorBLS_Verify = ExecutorBase<bool, operation::BLS_Verify>;
using ExecutorBLS_BatchSign = ExecutorBase<component::BLS_BatchSignature, operation::BLS_BatchSign>;
using ExecutorBLS_BatchVerify = ExecutorBase<bool, operation::BLS_BatchVerify>;
using ExecutorBLS_Aggregate_G1 = ExecutorBase<component::G1, operation::BLS_Aggregate_G1>;
using ExecutorBLS_Aggregate_G2 = ExecutorBase<component::G2, operation::BLS_Aggregate_G2>;
using ExecutorBLS_Pairing = ExecutorBase<component::Fp12, operation::BLS_Pairing>;
using ExecutorBLS_MillerLoop = ExecutorBase<component::Fp12, operation::BLS_MillerLoop>;
using ExecutorBLS_FinalExp = ExecutorBase<component::Fp12, operation::BLS_FinalExp>;
using ExecutorBLS_HashToG1 = ExecutorBase<component::G1, operation::BLS_HashToG1>;
using ExecutorBLS_HashToG2 = ExecutorBase<component::G2, operation::BLS_HashToG2>;
using ExecutorBLS_MapToG1 = ExecutorBase<component::G1, operation::BLS_MapToG1>;
using ExecutorBLS_MapToG2 = ExecutorBase<component::G2, operation::BLS_MapToG2>;
using ExecutorBLS_IsG1OnCurve = ExecutorBase<bool, operation::BLS_IsG1OnCurve>;
using ExecutorBLS_IsG2OnCurve = ExecutorBase<bool, operation::BLS_IsG2OnCurve>;
using ExecutorBLS_GenerateKeyPair = ExecutorBase<component::BLS_KeyPair, operation::BLS_GenerateKeyPair>;
using ExecutorBLS_Decompress_G1 = ExecutorBase<component::G1, operation::BLS_Decompress_G1>;
using ExecutorBLS_Compress_G1 = ExecutorBase<component::Bignum, operation::BLS_Compress_G1>;
using ExecutorBLS_Decompress_G2 = ExecutorBase<component::G2, operation::BLS_Decompress_G2>;
using ExecutorBLS_Compress_G2 = ExecutorBase<component::G1, operation::BLS_Compress_G2>;
using ExecutorBLS_G1_Add = ExecutorBase<component::G1, operation::BLS_G1_Add>;
using ExecutorBLS_G1_Mul = ExecutorBase<component::G1, operation::BLS_G1_Mul>;
using ExecutorBLS_G1_IsEq = ExecutorBase<bool, operation::BLS_G1_IsEq>;
using ExecutorBLS_G1_Neg = ExecutorBase<component::G1, operation::BLS_G1_Neg>;
using ExecutorBLS_G2_Add = ExecutorBase<component::G2, operation::BLS_G2_Add>;
using ExecutorBLS_G2_Mul = ExecutorBase<component::G2, operation::BLS_G2_Mul>;
using ExecutorBLS_G2_IsEq = ExecutorBase<bool, operation::BLS_G2_IsEq>;
using ExecutorBLS_G2_Neg = ExecutorBase<component::G2, operation::BLS_G2_Neg>;
using ExecutorBLS_G1_MultiExp = ExecutorBase<component::G1, operation::BLS_G1_MultiExp>;
using ExecutorMisc = ExecutorBase<Buffer, operation::Misc>;
using ExecutorSR25519_Verify = ExecutorBase<bool, operation::SR25519_Verify>;

} /* namespace cryptofuzz */
