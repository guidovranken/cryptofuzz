#include "driver.h"
#include <fuzzing/datasource/id.hpp>
#include "tests.h"
#include "executor.h"
#include <cryptofuzz/util.h>
#include <set>
#include <algorithm>
#include <unistd.h>

namespace cryptofuzz {

void Driver::LoadModule(std::shared_ptr<Module> module) {
    modules[module->ID] = module;
}

void Driver::Run(const uint8_t* data, const size_t size) const {
    using fuzzing::datasource::ID;

    static ExecutorDigest executorDigest(CF_OPERATION("Digest"), modules, options);
    static ExecutorHMAC executorHMAC(CF_OPERATION("HMAC"), modules, options);
    static ExecutorUMAC executorUMAC(CF_OPERATION("UMAC"), modules, options);
    static ExecutorCMAC executorCMAC(CF_OPERATION("CMAC"), modules, options);
    static ExecutorSymmetricEncrypt executorSymmetricEncrypt(CF_OPERATION("SymmetricEncrypt"), modules, options);
    static ExecutorSymmetricDecrypt executorSymmetricDecrypt(CF_OPERATION("SymmetricDecrypt"), modules, options);
    static ExecutorKDF_SCRYPT executorKDF_SCRYPT(CF_OPERATION("KDF_SCRYPT"), modules, options);
    static ExecutorKDF_HKDF executorKDF_HKDF(CF_OPERATION("KDF_HKDF"), modules, options);
    static ExecutorKDF_TLS1_PRF executorKDF_TLS1_PRF(CF_OPERATION("KDF_TLS1_PRF"), modules, options);
    static ExecutorKDF_PBKDF executorKDF_PBKDF(CF_OPERATION("KDF_PBKDF"), modules, options);
    static ExecutorKDF_PBKDF1 executorKDF_PBKDF1(CF_OPERATION("KDF_PBKDF1"), modules, options);
    static ExecutorKDF_PBKDF2 executorKDF_PBKDF2(CF_OPERATION("KDF_PBKDF2"), modules, options);
    static ExecutorKDF_ARGON2 executorKDF_ARGON2(CF_OPERATION("KDF_ARGON2"), modules, options);
    static ExecutorKDF_SSH executorKDF_SSH(ID("Cryptofuzz/Operation/KDF_SSH"), modules, options);
    static ExecutorKDF_X963 executorKDF_X963(CF_OPERATION("KDF_X963"), modules, options);
    static ExecutorKDF_BCRYPT executorKDF_BCRYPT(CF_OPERATION("KDF_BCRYPT"), modules, options);
    static ExecutorKDF_SP_800_108 executorKDF_SP_800_108(CF_OPERATION("KDF_SP_800_108"), modules, options);
    static ExecutorECC_PrivateToPublic executorECC_PrivateToPublic(CF_OPERATION("ECC_PrivateToPublic"), modules, options);
    static ExecutorECC_ValidatePubkey executorECC_ValidatePubkey(CF_OPERATION("ECC_ValidatePubkey"), modules, options);
    static ExecutorECC_GenerateKeyPair executorECC_GenerateKeyPair(CF_OPERATION("ECC_GenerateKeyPair"), modules, options);
    static ExecutorECCSI_Sign executorECCSI_Sign(CF_OPERATION("ECCSI_Sign"), modules, options);
    static ExecutorECDSA_Sign executorECDSA_Sign(CF_OPERATION("ECDSA_Sign"), modules, options);
    static ExecutorECGDSA_Sign executorECGDSA_Sign(CF_OPERATION("ECGDSA_Sign"), modules, options);
    static ExecutorECRDSA_Sign executorECRDSA_Sign(CF_OPERATION("ECRDSA_Sign"), modules, options);
    static ExecutorSchnorr_Sign executorSchnorr_Sign(CF_OPERATION("Schnorr_Sign"), modules, options);
    static ExecutorECCSI_Verify executorECCSI_Verify(CF_OPERATION("ECCSI_Verify"), modules, options);
    static ExecutorECDSA_Verify executorECDSA_Verify(CF_OPERATION("ECDSA_Verify"), modules, options);
    static ExecutorECGDSA_Verify executorECGDSA_Verify(CF_OPERATION("ECGDSA_Verify"), modules, options);
    static ExecutorECRDSA_Verify executorECRDSA_Verify(CF_OPERATION("ECRDSA_Verify"), modules, options);
    static ExecutorSchnorr_Verify executorSchnorr_Verify(CF_OPERATION("Schnorr_Verify"), modules, options);
    static ExecutorECDSA_Recover executorECDSA_Recover(CF_OPERATION("ECDSA_Recover"), modules, options);
    static ExecutorDSA_Verify executorDSA_Verify(CF_OPERATION("DSA_Verify"), modules, options);
    static ExecutorDSA_Sign executorDSA_Sign(CF_OPERATION("DSA_Sign"), modules, options);
    static ExecutorDSA_GenerateParameters executorDSA_GenerateParameters(CF_OPERATION("DSA_GenerateParameters"), modules, options);
    static ExecutorDSA_PrivateToPublic executorDSA_PrivateToPublic(CF_OPERATION("DSA_PrivateToPublic"), modules, options);
    static ExecutorDSA_GenerateKeyPair executorDSA_GenerateKeyPair(CF_OPERATION("DSA_GenerateKeyPair"), modules, options);
    static ExecutorECDH_Derive executorECDH_Derive(CF_OPERATION("ECDH_Derive"), modules, options);
    static ExecutorECIES_Encrypt executorECIES_Encrypt(CF_OPERATION("ECIES_Encrypt"), modules, options);
    static ExecutorECIES_Decrypt executorECIES_Decrypt(CF_OPERATION("ECIES_Decrypt"), modules, options);
    static ExecutorECC_Point_Add executorECC_Point_Add(CF_OPERATION("ECC_Point_Add"), modules, options);
    static ExecutorECC_Point_Sub executorECC_Point_Sub(CF_OPERATION("ECC_Point_Sub"), modules, options);
    static ExecutorECC_Point_Mul executorECC_Point_Mul(CF_OPERATION("ECC_Point_Mul"), modules, options);
    static ExecutorECC_Point_Neg executorECC_Point_Neg(CF_OPERATION("ECC_Point_Neg"), modules, options);
    static ExecutorECC_Point_Dbl executorECC_Point_Dbl(CF_OPERATION("ECC_Point_Dbl"), modules, options);
    static ExecutorECC_Point_Cmp executorECC_Point_Cmp(CF_OPERATION("ECC_Point_Cmp"), modules, options);
    static ExecutorDH_GenerateKeyPair executorDH_GenerateKeyPair(CF_OPERATION("DH_GenerateKeyPair"), modules, options);
    static ExecutorDH_Derive executorDH_Derive(CF_OPERATION("DH_Derive"), modules, options);
    static ExecutorBignumCalc executorBignumCalc(CF_OPERATION("BignumCalc"), modules, options);
    static ExecutorBignumCalc_Fp2 executorBignumCalc_Fp2(CF_OPERATION("BignumCalc_Fp2"), modules, options);
    static ExecutorBignumCalc_Fp12 executorBignumCalc_Fp12(CF_OPERATION("BignumCalc_Fp12"), modules, options);
    static ExecutorBignumCalc_Mod_BLS12_381_R executorBignumCalc_mod_bls12_381_r(CF_OPERATION("BignumCalc_Mod_BLS12_381_R"), modules, options);
    static ExecutorBignumCalc_Mod_BLS12_381_P executorBignumCalc_mod_bls12_381_p(CF_OPERATION("BignumCalc_Mod_BLS12_381_P"), modules, options);
    static ExecutorBignumCalc_Mod_BLS12_377_R executorBignumCalc_mod_bls12_377_r(CF_OPERATION("BignumCalc_Mod_BLS12_377_R"), modules, options);
    static ExecutorBignumCalc_Mod_BLS12_377_P executorBignumCalc_mod_bls12_377_p(CF_OPERATION("BignumCalc_Mod_BLS12_377_P"), modules, options);
    static ExecutorBignumCalc_Mod_BN128_R executorBignumCalc_mod_bn128_r(CF_OPERATION("BignumCalc_Mod_BN128_R"), modules, options);
    static ExecutorBignumCalc_Mod_BN128_P executorBignumCalc_mod_bn128_p(CF_OPERATION("BignumCalc_Mod_BN128_P"), modules, options);
    static ExecutorBignumCalc_Mod_Vesta_R executorBignumCalc_mod_vesta_r(CF_OPERATION("BignumCalc_Mod_Vesta_R"), modules, options);
    static ExecutorBignumCalc_Mod_Vesta_P executorBignumCalc_mod_vesta_p(CF_OPERATION("BignumCalc_Mod_Vesta_P"), modules, options);
    static ExecutorBignumCalc_Mod_ED25519 executorBignumCalc_mod_ed25519(CF_OPERATION("BignumCalc_Mod_ED25519"), modules, options);
    static ExecutorBignumCalc_Mod_Edwards_R executorBignumCalc_mod_edwards_r(CF_OPERATION("BignumCalc_Mod_Edwards_R"), modules, options);
    static ExecutorBignumCalc_Mod_Edwards_P executorBignumCalc_mod_edwards_p(CF_OPERATION("BignumCalc_Mod_Edwards_P"), modules, options);
    static ExecutorBignumCalc_Mod_Goldilocks executorBignumCalc_mod_goldilocks(CF_OPERATION("BignumCalc_Mod_Goldilocks"), modules, options);
    static ExecutorBignumCalc_Mod_MNT4_R executorBignumCalc_mod_mnt4_r(CF_OPERATION("BignumCalc_Mod_MNT4_R"), modules, options);
    static ExecutorBignumCalc_Mod_MNT4_P executorBignumCalc_mod_mnt4_p(CF_OPERATION("BignumCalc_Mod_MNT4_P"), modules, options);
    static ExecutorBignumCalc_Mod_MNT6_R executorBignumCalc_mod_mnt6_r(CF_OPERATION("BignumCalc_Mod_MNT6_R"), modules, options);
    static ExecutorBignumCalc_Mod_MNT6_P executorBignumCalc_mod_mnt6_p(CF_OPERATION("BignumCalc_Mod_MNT6_P"), modules, options);
    static ExecutorBignumCalc_Mod_2Exp64 executorBignumCalc_mod_2exp64(CF_OPERATION("BignumCalc_Mod_2Exp64"), modules, options);
    static ExecutorBignumCalc_Mod_2Exp128 executorBignumCalc_mod_2exp128(CF_OPERATION("BignumCalc_Mod_2Exp128"), modules, options);
    static ExecutorBignumCalc_Mod_2Exp256 executorBignumCalc_mod_2exp256(CF_OPERATION("BignumCalc_Mod_2Exp256"), modules, options);
    static ExecutorBignumCalc_Mod_2Exp512 executorBignumCalc_mod_2exp512(CF_OPERATION("BignumCalc_Mod_2Exp512"), modules, options);
    static ExecutorBignumCalc_Mod_SECP256K1 executorBignumCalc_mod_secp256k1(CF_OPERATION("BignumCalc_Mod_SECP256K1"), modules, options);
    static ExecutorBignumCalc_Mod_SECP256K1_P executorBignumCalc_mod_secp256k1_p(CF_OPERATION("BignumCalc_Mod_SECP256K1_P"), modules, options);
    static ExecutorBLS_PrivateToPublic executorBLS_PrivateToPublic(CF_OPERATION("BLS_PrivateToPublic"), modules, options);
    static ExecutorBLS_PrivateToPublic_G2 executorBLS_PrivateToPublic_G2(CF_OPERATION("BLS_PrivateToPublic_G2"), modules, options);
    static ExecutorBLS_Sign executorBLS_Sign(CF_OPERATION("BLS_Sign"), modules, options);
    static ExecutorBLS_Verify executorBLS_Verify(CF_OPERATION("BLS_Verify"), modules, options);
    static ExecutorBLS_BatchSign executorBLS_BatchSign(CF_OPERATION("BLS_BatchSign"), modules, options);
    static ExecutorBLS_BatchVerify executorBLS_BatchVerify(CF_OPERATION("BLS_BatchVerify"), modules, options);
    static ExecutorBLS_Aggregate_G1 executorBLS_Aggregate_G1(CF_OPERATION("BLS_Aggregate_G1"), modules, options);
    static ExecutorBLS_Aggregate_G2 executorBLS_Aggregate_G2(CF_OPERATION("BLS_Aggregate_G2"), modules, options);
    static ExecutorBLS_Pairing executorBLS_Pairing(CF_OPERATION("BLS_Pairing"), modules, options);
    static ExecutorBLS_MillerLoop executorBLS_MillerLoop(CF_OPERATION("BLS_MillerLoop"), modules, options);
    static ExecutorBLS_FinalExp executorBLS_FinalExp(CF_OPERATION("BLS_FinalExp"), modules, options);
    static ExecutorBLS_HashToG1 executorBLS_HashToG1(CF_OPERATION("BLS_HashToG1"), modules, options);
    static ExecutorBLS_HashToG2 executorBLS_HashToG2(CF_OPERATION("BLS_HashToG2"), modules, options);
    static ExecutorBLS_MapToG1 executorBLS_MapToG1(CF_OPERATION("BLS_MapToG1"), modules, options);
    static ExecutorBLS_MapToG2 executorBLS_MapToG2(CF_OPERATION("BLS_MapToG2"), modules, options);
    static ExecutorBLS_IsG1OnCurve executorBLS_IsG1OnCurve(CF_OPERATION("BLS_IsG1OnCurve"), modules, options);
    static ExecutorBLS_IsG2OnCurve executorBLS_IsG2OnCurve(CF_OPERATION("BLS_IsG2OnCurve"), modules, options);
    static ExecutorBLS_GenerateKeyPair executorBLS_GenerateKeyPair(CF_OPERATION("BLS_GenerateKeyPair"), modules, options);
    static ExecutorBLS_Decompress_G1 executorBLS_Decompress_G1(CF_OPERATION("BLS_Decompress_G1"), modules, options);
    static ExecutorBLS_Compress_G1 executorBLS_Compress_G1(CF_OPERATION("BLS_Compress_G1"), modules, options);
    static ExecutorBLS_Decompress_G2 executorBLS_Decompress_G2(CF_OPERATION("BLS_Decompress_G2"), modules, options);
    static ExecutorBLS_Compress_G2 executorBLS_Compress_G2(CF_OPERATION("BLS_Compress_G2"), modules, options);
    static ExecutorBLS_G1_Add executorBLS_G1_Add(CF_OPERATION("BLS_G1_Add"), modules, options);
    static ExecutorBLS_G1_Mul executorBLS_G1_Mul(CF_OPERATION("BLS_G1_Mul"), modules, options);
    static ExecutorBLS_G1_IsEq executorBLS_G1_IsEq(CF_OPERATION("BLS_G1_IsEq"), modules, options);
    static ExecutorBLS_G1_Neg executorBLS_G1_Neg(CF_OPERATION("BLS_G1_Neg"), modules, options);
    static ExecutorBLS_G2_Add executorBLS_G2_Add(CF_OPERATION("BLS_G2_Add"), modules, options);
    static ExecutorBLS_G2_Mul executorBLS_G2_Mul(CF_OPERATION("BLS_G2_Mul"), modules, options);
    static ExecutorBLS_G2_IsEq executorBLS_G2_IsEq(CF_OPERATION("BLS_G2_IsEq"), modules, options);
    static ExecutorBLS_G2_Neg executorBLS_G2_Neg(CF_OPERATION("BLS_G2_Neg"), modules, options);
    static ExecutorBLS_G1_MultiExp executorBLS_G1_MultiExp(CF_OPERATION("BLS_G1_MultiExp"), modules, options);
    static ExecutorMisc executorMisc(CF_OPERATION("Misc"), modules, options);
    static ExecutorSR25519_Verify executorSR25519_Verify(CF_OPERATION("SR25519_Verify"), modules, options);

    try {

        Datasource ds(data, size);

        const auto operation = ds.Get<uint64_t>();

        if ( !options.operations.Have(operation) ) {
            return;
        }

        const auto payload = ds.GetData(0, 1);

        switch ( operation ) {
            case CF_OPERATION("Digest"):
                executorDigest.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("HMAC"):
                executorHMAC.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("UMAC"):
                executorUMAC.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("CMAC"):
                executorCMAC.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("SymmetricEncrypt"):
                executorSymmetricEncrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("SymmetricDecrypt"):
                executorSymmetricDecrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_SCRYPT"):
                executorKDF_SCRYPT.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_HKDF"):
                executorKDF_HKDF.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_TLS1_PRF"):
                executorKDF_TLS1_PRF.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_PBKDF"):
                executorKDF_PBKDF.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_PBKDF1"):
                executorKDF_PBKDF1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_PBKDF2"):
                executorKDF_PBKDF2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_ARGON2"):
                executorKDF_ARGON2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_SSH"):
                executorKDF_SSH.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_X963"):
                executorKDF_X963.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_BCRYPT"):
                executorKDF_BCRYPT.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("KDF_SP_800_108"):
                executorKDF_SP_800_108.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_PrivateToPublic"):
                executorECC_PrivateToPublic.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_ValidatePubkey"):
                executorECC_ValidatePubkey.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_GenerateKeyPair"):
                executorECC_GenerateKeyPair.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECCSI_Sign"):
                executorECCSI_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDSA_Sign"):
                executorECDSA_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECGDSA_Sign"):
                executorECGDSA_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECRDSA_Sign"):
                executorECRDSA_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("Schnorr_Sign"):
                executorSchnorr_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECCSI_Verify"):
                executorECCSI_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDSA_Verify"):
                executorECDSA_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECGDSA_Verify"):
                executorECGDSA_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECRDSA_Verify"):
                executorECRDSA_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("Schnorr_Verify"):
                executorSchnorr_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDSA_Recover"):
                executorECDSA_Recover.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DSA_Verify"):
                executorDSA_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DSA_Sign"):
                executorDSA_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DSA_GenerateParameters"):
                executorDSA_GenerateParameters.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DSA_PrivateToPublic"):
                executorDSA_PrivateToPublic.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DSA_GenerateKeyPair"):
                executorDSA_GenerateKeyPair.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECDH_Derive"):
                executorECDH_Derive.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECIES_Encrypt"):
                executorECIES_Encrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECIES_Decrypt"):
                executorECIES_Decrypt.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Add"):
                executorECC_Point_Add.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Sub"):
                executorECC_Point_Sub.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Mul"):
                executorECC_Point_Mul.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Neg"):
                executorECC_Point_Neg.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Dbl"):
                executorECC_Point_Dbl.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("ECC_Point_Cmp"):
                executorECC_Point_Cmp.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DH_GenerateKeyPair"):
                executorDH_GenerateKeyPair.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("DH_Derive"):
                executorDH_Derive.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc"):
                executorBignumCalc.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Fp2"):
                executorBignumCalc_Fp2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Fp12"):
                executorBignumCalc_Fp12.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BLS12_381_R"):
                executorBignumCalc_mod_bls12_381_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BLS12_381_P"):
                executorBignumCalc_mod_bls12_381_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BLS12_377_R"):
                executorBignumCalc_mod_bls12_377_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BLS12_377_P"):
                executorBignumCalc_mod_bls12_377_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BN128_R"):
                executorBignumCalc_mod_bn128_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_BN128_P"):
                executorBignumCalc_mod_bn128_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_Vesta_R"):
                executorBignumCalc_mod_vesta_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_Vesta_P"):
                executorBignumCalc_mod_vesta_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_ED25519"):
                executorBignumCalc_mod_ed25519.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_Edwards_R"):
                executorBignumCalc_mod_edwards_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_Edwards_P"):
                executorBignumCalc_mod_edwards_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_Goldilocks"):
                executorBignumCalc_mod_goldilocks.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_MNT4_R"):
                executorBignumCalc_mod_mnt4_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_MNT4_P"):
                executorBignumCalc_mod_mnt4_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_MNT6_R"):
                executorBignumCalc_mod_mnt6_r.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_MNT6_P"):
                executorBignumCalc_mod_mnt6_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_2Exp64"):
                executorBignumCalc_mod_2exp64.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_2Exp128"):
                executorBignumCalc_mod_2exp128.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_2Exp256"):
                executorBignumCalc_mod_2exp256.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_2Exp512"):
                executorBignumCalc_mod_2exp512.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_SECP256K1"):
                executorBignumCalc_mod_secp256k1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BignumCalc_Mod_SECP256K1_P"):
                executorBignumCalc_mod_secp256k1_p.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_PrivateToPublic"):
                executorBLS_PrivateToPublic.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_PrivateToPublic_G2"):
                executorBLS_PrivateToPublic_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Sign"):
                executorBLS_Sign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Verify"):
                executorBLS_Verify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_BatchSign"):
                executorBLS_BatchSign.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_BatchVerify"):
                executorBLS_BatchVerify.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Aggregate_G1"):
                executorBLS_Aggregate_G1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Aggregate_G2"):
                executorBLS_Aggregate_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Pairing"):
                executorBLS_Pairing.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_MillerLoop"):
                executorBLS_MillerLoop.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_FinalExp"):
                executorBLS_FinalExp.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_HashToG1"):
                executorBLS_HashToG1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_HashToG2"):
                executorBLS_HashToG2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_MapToG1"):
                executorBLS_MapToG1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_MapToG2"):
                executorBLS_MapToG2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_IsG1OnCurve"):
                executorBLS_IsG1OnCurve.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_IsG2OnCurve"):
                executorBLS_IsG2OnCurve.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_GenerateKeyPair"):
                executorBLS_GenerateKeyPair.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Decompress_G1"):
                executorBLS_Decompress_G1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Compress_G1"):
                executorBLS_Compress_G1.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Decompress_G2"):
                executorBLS_Decompress_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_Compress_G2"):
                executorBLS_Compress_G2.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_Add"):
                executorBLS_G1_Add.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_Mul"):
                executorBLS_G1_Mul.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_IsEq"):
                executorBLS_G1_IsEq.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_Neg"):
                executorBLS_G1_Neg.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_Add"):
                executorBLS_G2_Add.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_Mul"):
                executorBLS_G2_Mul.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_IsEq"):
                executorBLS_G2_IsEq.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G2_Neg"):
                executorBLS_G2_Neg.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("BLS_G1_MultiExp"):
                executorBLS_G1_MultiExp.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("Misc"):
                executorMisc.Run(ds, payload.data(), payload.size());
                break;
            case CF_OPERATION("SR25519_Verify"):
                executorSR25519_Verify.Run(ds, payload.data(), payload.size());
                break;
        }
    } catch ( Datasource::OutOfData& ) {
    }
};

Driver::Driver(const Options options) :
    options(options)
{ }

const Options* Driver::GetOptionsPtr(void) const {
    return &options;
}

} /* namespace cryptofuzz */
