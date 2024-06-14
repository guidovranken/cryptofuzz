#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <mbedtls/platform.h>
#include <psa/crypto.h>

//#pragma clang optimize off //while debugging

namespace cryptofuzz {
namespace module {

#define CF_ASSERT_PSA(expr) CF_ASSERT_EQ(expr, PSA_SUCCESS)

static bool is_cipher_consistent(component::SymmetricCipher cipher) {
    /* For some reason, modules can receive a cipher type that's
     * inconsistent with the key length, even though the module does not
     * have an interface to report that it correctly rejected an
     * invalid length. */
    size_t bits = cipher.key.GetSize() * 8;
    std::string name = repository::CipherToString(cipher.cipherType.Get());

    if (name.find("128") != std::string::npos) {
        return bits == 128;
    }
    if (name.find("192") != std::string::npos) {
        return bits == 192;
    }
    if (name.find("256") != std::string::npos) {
        return bits == 256;
    }
    if (name.rfind("CHACHA", 0) == 0) {
        return bits == 256;
    }
    if (name.rfind("DES_EDE3_", 0) == 0 || name.rfind("DES3_", 0) == 0) {
        return bits == 192;
    }
    if (name.rfind("DES_EDE_", 0) == 0) {
        return bits == 128;
    }
    if (name.rfind("DES_", 0) == 0) {
        return bits == 64;
    }

    // As a fallback, declare the size to be valid, and let the fuzzed library
    // cause a fatal error if it turns out not to be.
    return true;
}

namespace TF_PSA_Crypto_detail {
    Datasource* ds;

    inline void SetGlobalDs(Datasource* ds) {
        TF_PSA_Crypto_detail::ds = ds;
    }

    inline void UnsetGlobalDs(void) {
        TF_PSA_Crypto_detail::ds = nullptr;
    }

    inline bool AllocationFailure(void) {
#if defined(CRYPTOFUZZ_MBEDTLS_ALLOCATION_FAILURES)
        bool fail = false;
        if ( ds == nullptr ) {
            return fail;
        }
        try {
            fail = ds->Get<bool>();
        } catch ( ... ) { }

        return fail;
#else
        return false;
#endif
    }
}

/* Resize a vector to the desired size, to make it ready to receive data. */
static void vector_extend(std::vector<uint8_t>& vector, size_t size) {
    vector.reserve(size);
    vector.resize(size);
    vector.shrink_to_fit();
}

static void* mbedTLS_custom_calloc(size_t A, size_t B) {
    if ( TF_PSA_Crypto_detail::AllocationFailure() == true ) {
        return nullptr;
    }

    /* TODO detect overflows */
    const size_t size = A*B;
    void* p = util::malloc(size);
    if ( size ) {
        memset(p, 0x00, size);
    }
    return p;
}

static void mbedTLS_custom_free(void* ptr) {
    util::free(ptr);
}

TF_PSA_Crypto::TF_PSA_Crypto(void) :
    Module("PSA-Crypto") {

    if ( mbedtls_platform_set_calloc_free(mbedTLS_custom_calloc, mbedTLS_custom_free) != 0 ) {
        abort();
    }

    /* The most plausible error cause here is that Mbed TLS is compiled
     * with MBEDTLS_ENTROPY_NV_SEED enabled and the entropy seed file is
     * missing. To fix that problem, create a 64-byte file called "seedfile"
     * in the current directory. */
    CF_ASSERT_PSA(psa_crypto_init());
}

TF_PSA_Crypto::~TF_PSA_Crypto(void)
{
    mbedtls_psa_crypto_free();
}

namespace TF_PSA_Crypto_detail {

    psa_algorithm_t digest_to_psa_algorithm_t(const component::DigestType& digestType) {
        using fuzzing::datasource::ID;

        static const std::map<uint64_t, psa_algorithm_t> LUT = {
            { CF_DIGEST("MD5"), PSA_ALG_MD5 },
            { CF_DIGEST("RIPEMD160"), PSA_ALG_RIPEMD160 },
            { CF_DIGEST("SHA1"), PSA_ALG_SHA_1 },
            { CF_DIGEST("SHA224"), PSA_ALG_SHA_224 },
            { CF_DIGEST("SHA256"), PSA_ALG_SHA_256 },
            { CF_DIGEST("SHA384"), PSA_ALG_SHA_384 },
            { CF_DIGEST("SHA512"), PSA_ALG_SHA_512 },
            { CF_DIGEST("SHA3-224"), PSA_ALG_SHA3_224 },
            { CF_DIGEST("SHA3-256"), PSA_ALG_SHA3_256 },
            { CF_DIGEST("SHA3-384"), PSA_ALG_SHA3_384 },
            { CF_DIGEST("SHA3-512"), PSA_ALG_SHA3_512 },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return PSA_ALG_NONE;
        }

        return LUT.at(digestType.Get());
    }

    psa_key_type_t cipher_to_psa_key_type_t(const component::SymmetricCipherType& cipherType) {
        const std::string name = repository::CipherToString(cipherType.Get());
        if (name.rfind("AES", 0) == 0 && name.find("_SHA") == std::string::npos) {
            return PSA_KEY_TYPE_AES;
        } else if (name.rfind("ARIA_", 0) == 0) {
            return PSA_KEY_TYPE_ARIA;
        } else if (name.rfind("CAMELLIA_", 0) == 0) {
            return PSA_KEY_TYPE_CAMELLIA;
        } else if (name.rfind("CHACHA", 0) == 0) {
            return PSA_KEY_TYPE_CHACHA20;
        } else if (name.rfind("DES_", 0) == 0 && name.find("_SHA") == std::string::npos) {
            return PSA_KEY_TYPE_DES;
        } else if (name.rfind("DES3_", 0) == 0 && name.find("_SHA") == std::string::npos) {
            return PSA_KEY_TYPE_DES;
        } else {
            return PSA_KEY_TYPE_NONE;
        }
    }

    psa_algorithm_t cipher_to_psa_algorithm_t(const component::SymmetricCipherType& cipherType) {
        uint64_t id = cipherType.Get();
        const std::string name = repository::CipherToString(cipherType.Get());
        if (name.rfind("DES", 0) == 0) {
            /* Only a few old-school block modes are accepted with DES. */
            if (repository::IsCBC(id)) {
                return PSA_ALG_CBC_PKCS7;
            } else if (repository::IsECB(id)) {
                return PSA_ALG_ECB_NO_PADDING;
            } else {
                return PSA_ALG_NONE;
            }
        }
        if (repository::IsCBC(id)) {
            return PSA_ALG_CBC_PKCS7;
        } else if (repository::IsCCM(id)) {
            return PSA_ALG_CCM;
        } else if (name.size() >= 3 && std::equal(name.end() - 3, name.end(), "CFB")) {
            /* Only CFB with segment size = block size is available in this API,
             * not CFB1 or CFB8. */
            return PSA_ALG_CFB;
        } else if (repository::IsCTR(id)) {
            return PSA_ALG_CTR;
        } else if (repository::IsECB(id)) {
            return PSA_ALG_ECB_NO_PADDING;
        } else if (repository::IsGCM(id)) {
            return PSA_ALG_GCM;
        } else if (repository::IsOFB(id)) {
            if (!repository::IsAES(id)) {
                /* Missing support for CAMELLIA and ARIA
                 * https://github.com/Mbed-TLS/mbedtls/issues/8902 */
                return PSA_ALG_NONE;
            }
            return PSA_ALG_OFB;
#if 0 //TODO: requires a double-length key
        } else if (repository::IsXTS(id)) {
            return PSA_ALG_XTS;
#endif
        } else if (id == CF_CIPHER("CHACHA20")) {
            return PSA_ALG_STREAM_CIPHER;
        } else if (id == CF_CIPHER("CHACHA20_POLY1305")) {
            return PSA_ALG_CHACHA20_POLY1305;
        } else {
            return PSA_ALG_NONE;
        }
    }

    class HashOperation {
        psa_hash_operation_t operation;

    public:
        HashOperation() {
            operation = PSA_HASH_OPERATION_INIT;
        }
        ~HashOperation() {
            psa_hash_abort(&operation);
        }

        psa_status_t setup(psa_algorithm_t alg) {
            return psa_hash_setup(&operation, alg);
        }
        psa_status_t update(const unsigned char *input, size_t input_length) {
            return psa_hash_update(&operation, input, input_length);
        }
        psa_status_t finish(unsigned char *output, size_t output_size,
                            size_t *output_length) {
            return psa_hash_finish(&operation, output, output_size, output_length);
        }
        psa_status_t verify(const unsigned char *hash, size_t hash_length) {
            return psa_hash_verify(&operation, hash, hash_length);
        }
    };

    class KeyOperation {
    protected:
        psa_key_type_t key_type = PSA_KEY_TYPE_NONE;
        size_t key_bits = 0;
        psa_key_id_t key = PSA_KEY_ID_NULL;
        psa_algorithm_t alg = PSA_ALG_NONE;

        virtual psa_key_usage_t usage_flags() const = 0;

    public:
        KeyOperation() {
        }
        ~KeyOperation() {
            key_type = PSA_KEY_TYPE_NONE;
            key_bits = 0;
            psa_destroy_key(key);
            key = PSA_KEY_ID_NULL;
            alg = PSA_ALG_NONE;
        }

        psa_status_t set_key(psa_key_type_t key_type_,
                             const unsigned char *key_data, size_t key_length,
                             psa_algorithm_t alg_) {
            key_type = key_type_;
            alg = alg_;
            key_bits = PSA_BYTES_TO_BITS(key_length);
            psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
            psa_set_key_type(&attributes, key_type);
            psa_set_key_usage_flags(&attributes, usage_flags());
            psa_set_key_algorithm(&attributes, alg);
            return psa_import_key(&attributes, key_data, key_length, &key);
        }
    };

    class MACOperation : public KeyOperation {
        psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

        virtual psa_key_usage_t usage_flags() const override {
            return PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
        }

    public:
        MACOperation() {
        }
        ~MACOperation() {
            psa_mac_abort(&operation);
            operation = PSA_MAC_OPERATION_INIT;
        }

        size_t length() {
            return PSA_MAC_LENGTH(key_type, key_bits, alg);
        }

        psa_status_t sign(const unsigned char *input, size_t input_length,
                          unsigned char *output, size_t output_size,
                          size_t *output_length) {
            return psa_mac_compute(key, alg, input, input_length,
                                   output, output_size, output_length);
        }
        psa_status_t verify(const unsigned char *input, size_t input_length,
                            const unsigned char *mac, size_t mac_length) {
            return psa_mac_verify(key, alg, input, input_length,
                                  mac, mac_length);
        }

        psa_status_t sign_start() {
            return psa_mac_sign_setup(&operation, key, alg);
        }
        psa_status_t verify_start() {
            return psa_mac_verify_setup(&operation, key, alg);
        }
        psa_status_t update(const unsigned char *input, size_t input_length) {
            return psa_mac_update(&operation, input, input_length);
        }
        psa_status_t sign_finish(unsigned char *output, size_t output_size,
                                 size_t *output_length) {
            return psa_mac_sign_finish(&operation, output, output_size, output_length);
        }
        psa_status_t verify_finish(const unsigned char *mac, size_t mac_length) {
            return psa_mac_verify_finish(&operation, mac, mac_length);
        }
    };

    class CipherOperation : public KeyOperation {
        psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

        virtual psa_key_usage_t usage_flags() const override {
            return PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
        }

    public:
        CipherOperation() {
        }
        ~CipherOperation() {
            psa_cipher_abort(&operation);
            operation = PSA_CIPHER_OPERATION_INIT;
        }

        size_t block_size() {
            return PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type);
        }
        size_t decrypt_output_size(size_t input_length) {
            return PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_length);
        }
        size_t update_output_size(size_t input_length) {
            size_t size = PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input_length);
            if (alg == PSA_ALG_CBC_PKCS7 && input_length % block_size() == 0) {
                // Compensate for https://github.com/Mbed-TLS/mbedtls/issues/8954
                size += block_size();
            }
            return size;
        }
        size_t finish_output_size() {
            return PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg);
        }
        size_t has_padding() {
            return alg == PSA_ALG_CBC_PKCS7;
        }

        bool is_valid_iv_length(size_t iv_length) {
            switch (alg) {
            case PSA_ALG_STREAM_CIPHER:
                switch (key_type) {
                case PSA_KEY_TYPE_CHACHA20:
                    /* Not 8: https://github.com/Mbed-TLS/mbedtls/issues/5615 */
                    /* Not 16: https://github.com/Mbed-TLS/mbedtls/issues/5616 */
                    return iv_length == 12;
                default:
                    return true;
                }
            case PSA_ALG_CCM_STAR_NO_TAG:
                /* "Currently only 13-byte long IV's are supported." */
                return iv_length == 13;
                break;
#if 0
            case PSA_ALG_CTR:
                /* As of Mbed TLS 3.6.0, only a full-block IV is supported.
                 * https://github.com/Mbed-TLS/mbedtls/issues/8900 */
                return iv_length >= 1 && iv_length <= block_size();
#endif
            default:
                return iv_length == block_size();
            }
        }

        /* Return true for assumed good data.
         * Return false for detected bad data.
         * Abort for unexpected error codes. */
        bool check_finish_status(bool is_encrypt, size_t input_length,
                                 psa_status_t status) {
            if (status == PSA_SUCCESS) {
                return true;
            } else if (!is_encrypt &&
                       has_padding() && status == PSA_ERROR_INVALID_PADDING) {
                /* Found invalid padding */
                return false;
            } else if (!is_encrypt &&
                       has_padding() &&
                       input_length < block_size() &&
                       status == PSA_ERROR_INVALID_ARGUMENT) {
                /* Padding was absent */
                return false;
            } else if ((alg == PSA_ALG_ECB_NO_PADDING ||
                        alg == PSA_ALG_CBC_NO_PADDING ||
                        (alg == PSA_ALG_CBC_PKCS7 && !is_encrypt)) &&
                       input_length % block_size() != 0 &&
                       status == PSA_ERROR_INVALID_ARGUMENT) {
                /* Modes requiring a full block of input */
                return false;
            } else {
                printf("Bad status %d from psa_cipher_finish() or psa_cipher_decrypt()\n",
                       status);
                ::abort();
            }
        }

        /* No one-shot encryption: psa_cipher_encrypt() uses a random IV,
         * and that's not useful for fuzzing. */

        /* input = IV + ciphertext */
        psa_status_t decrypt(const unsigned char *input, size_t input_length,
                             unsigned char *output, size_t output_size,
                             size_t *output_length) {
            return psa_cipher_decrypt(key, alg, input, input_length,
                                      output, output_size, output_length);
        }

        psa_status_t encrypt_setup() {
            return psa_cipher_encrypt_setup(&operation, key, alg);
        }
        psa_status_t decrypt_setup() {
            return psa_cipher_decrypt_setup(&operation, key, alg);
        }
        psa_status_t set_iv(const unsigned char *iv, size_t iv_length) {
            return psa_cipher_set_iv(&operation, iv, iv_length);
        }
        psa_status_t update(const unsigned char *input, size_t input_length,
                            unsigned char *output, size_t output_size,
                            size_t *output_length) {
            return psa_cipher_update(&operation, input, input_length,
                                     output, output_size, output_length);
        }
        psa_status_t finish(unsigned char *output, size_t output_size,
                            size_t *output_length) {
            return psa_cipher_finish(&operation,
                                     output, output_size, output_length);
        }
    };

    class AEADOperation : public KeyOperation {
        psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;

        virtual psa_key_usage_t usage_flags() const override {
            return PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
        }

    public:
        AEADOperation() {
        }
        ~AEADOperation() {
            psa_aead_abort(&operation);
            operation = PSA_AEAD_OPERATION_INIT;
        }

        size_t tag_length() {
            return PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg);
        }
        size_t update_output_size(size_t part_size) {
            return PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, part_size);
        }
        size_t finish_output_size() {
            return PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg);
        }
        size_t verify_output_size() {
            return PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg);
        }

        bool is_valid_iv_length(size_t iv_length) {
            switch (alg) {
            case PSA_ALG_CCM:
                return iv_length >= 7 && iv_length <= 13;
            case PSA_ALG_CHACHA20_POLY1305:
                /* Not 8: https://github.com/Mbed-TLS/mbedtls/issues/5615 */
                return iv_length == 12;
            case PSA_ALG_GCM:
                return iv_length >= 1;
            default:
                return true; // Unexpected. Let set_nonce() crash.
            }
        }

        psa_status_t encrypt(const std::vector<uint8_t>& iv,
                             const std::vector<uint8_t>& aad,
                             const std::vector<uint8_t>& cleartext,
                             std::vector<uint8_t>& ciphertext_with_tag) {
            vector_extend(ciphertext_with_tag,
                          PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg,
                                                       cleartext.size()));
            size_t length = 0;
            psa_status_t status = psa_aead_encrypt(
                key, alg, iv.data(), iv.size(),
                aad.data(), aad.size(),
                cleartext.data(), cleartext.size(),
                ciphertext_with_tag.data(), ciphertext_with_tag.size(),
                &length);
            if (status != PSA_SUCCESS) {
                return PSA_SUCCESS;
            }
            ciphertext_with_tag.resize(length);
            return PSA_SUCCESS;
        }

        psa_status_t decrypt(const std::vector<uint8_t>& iv,
                             const std::vector<uint8_t>& aad,
                             const std::vector<uint8_t>& ciphertext_with_tag,
                             std::vector<uint8_t>& cleartext) {
            vector_extend(cleartext,
                          PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg,
                                                       ciphertext_with_tag.size()));
            size_t length = 0;
            psa_status_t status = psa_aead_decrypt(
                key, alg, iv.data(), iv.size(),
                aad.data(), aad.size(),
                ciphertext_with_tag.data(), ciphertext_with_tag.size(),
                cleartext.data(), cleartext.size(), &length);
            if (status != PSA_SUCCESS) {
                return status;
            }
            cleartext.resize(length);
            return PSA_SUCCESS;
        }

        psa_status_t encrypt_setup() {
            return psa_aead_encrypt_setup(&operation, key, alg);
        }
        psa_status_t decrypt_setup() {
            return psa_aead_decrypt_setup(&operation, key, alg);
        }
        psa_status_t set_lengths(size_t aad_length, size_t cleartext_length) {
            return psa_aead_set_lengths(&operation, aad_length, cleartext_length);
        }
        psa_status_t set_iv(const unsigned char *iv, size_t iv_length) {
            return psa_aead_set_nonce(&operation, iv, iv_length);
        }
        psa_status_t update_aad(const unsigned char *input, size_t input_length) {
            return psa_aead_update_ad(&operation, input, input_length);
        }
        psa_status_t update(const unsigned char *input, size_t input_length,
                            unsigned char *output, size_t output_size,
                            size_t *output_length) {
            return psa_aead_update(&operation, input, input_length,
                                   output, output_size, output_length);
        }
        psa_status_t finish(unsigned char *ciphertext, size_t ciphertext_size,
                            size_t *ciphertext_length,
                            unsigned char *tag, size_t tag_size,
                            size_t *tag_length) {
            return psa_aead_finish(&operation,
                                   ciphertext, ciphertext_size, ciphertext_length,
                                   tag, tag_size, tag_length);
        }
        psa_status_t verify(unsigned char *cleartext, size_t cleartext_size,
                            size_t *cleartext_length,
                            unsigned char *tag, size_t tag_length) {
            return psa_aead_verify(&operation,
                                   cleartext, cleartext_size, cleartext_length,
                                   tag, tag_length);
        }
    };

}

static std::optional<component::Digest> hash_compute(operation::Digest& op,
                                                     Datasource &ds,
                                                     psa_algorithm_t alg) {
    std::vector<uint8_t> md(PSA_HASH_LENGTH(alg));
    size_t length = 0;
    bool const multipart = ds.Get<bool>();
    if (multipart) {
        TF_PSA_Crypto_detail::HashOperation operation;
        /* Initialize */
        util::Multipart parts = util::ToParts(ds, op.cleartext);
        CF_ASSERT_PSA(operation.setup(alg));

        /* Process */
        for (const auto& part : parts) {
            CF_ASSERT_PSA(operation.update(part.first, part.second));
        }

        /* Finalize */
        CF_ASSERT_PSA(operation.finish(md.data(), md.size(), &length));
    } else {
        /* One-shot computation */
        CF_ASSERT_PSA(psa_hash_compute(alg,
                                       op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                                       md.data(), md.size(), &length));
    }
    return component::Digest(md.data(), length);
}

static void hash_verify(operation::Digest& op,
                        Datasource &ds,
                        psa_algorithm_t alg,
                        std::vector<uint8_t> expected_md) {
    /* Biaise towards the expected size */
    bool const correct_size = ds.Get<bool>();
    std::vector<uint8_t> const verify_md =
        correct_size ? ds.GetData(0, expected_md.size(), expected_md.size()) :
        ds.GetData(0, 0, PSA_HASH_MAX_SIZE * 2);
    psa_status_t const expected_verify_status =
        verify_md == expected_md ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;

    bool const multipart = ds.Get<bool>();
    if (multipart) {
        TF_PSA_Crypto_detail::HashOperation operation;
        /* Initialize */
        util::Multipart parts = util::ToParts(ds, op.cleartext);
        CF_ASSERT_PSA(operation.setup(alg));

        /* Process */
        for (const auto& part : parts) {
            CF_ASSERT_PSA(operation.update(part.first, part.second));
        }//

        /* Finalize */
        CF_ASSERT_EQ(operation.verify(verify_md.data(), verify_md.size()),
                     expected_verify_status);
    } else {
        /* One-shot computation */
        CF_ASSERT_EQ(psa_hash_compare(alg,
                                      op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                                      verify_md.data(), verify_md.size()),
                     expected_verify_status);
    }
}

std::optional<component::Digest> TF_PSA_Crypto::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    TF_PSA_Crypto_detail::SetGlobalDs(&ds);

    psa_algorithm_t const alg =
        TF_PSA_Crypto_detail::digest_to_psa_algorithm_t(op.digestType);
    /* Skip unknown algorithms */
    CF_CHECK_NE(alg, PSA_ALG_NONE);

    ret = hash_compute(op, ds, alg);
    hash_verify(op, ds, alg, ret->Get());

end:
    TF_PSA_Crypto_detail::UnsetGlobalDs();

    return ret;
}

static std::optional<component::MAC> mac_compute(
        TF_PSA_Crypto_detail::MACOperation& operation,
        const component::Cleartext& cleartext,
        Datasource &ds) {
    std::vector<uint8_t> mac(operation.length());
    size_t length = 0;
    bool const multipart = ds.Get<bool>();
    if (multipart) {
        util::Multipart parts = util::ToParts(ds, cleartext);
        CF_ASSERT_PSA(operation.sign_start());
        for (const auto& part : parts) {
            CF_ASSERT_PSA(operation.update(part.first, part.second));
        }
        CF_ASSERT_PSA(operation.sign_finish(mac.data(), mac.size(), &length));
    } else {
        /* One-shot computation */
        CF_ASSERT_PSA(operation.sign(cleartext.GetPtr(&ds), cleartext.GetSize(),
                                     mac.data(), mac.size(), &length));
    }
    return component::MAC(mac.data(), length);
}

static void mac_verify(
        TF_PSA_Crypto_detail::MACOperation& operation,
        const component::Cleartext& cleartext,
        Datasource &ds,
        std::vector<uint8_t> expected_mac) {
    /* Biaise towards the expected size */
    bool const correct_size = ds.Get<bool>();
    std::vector<uint8_t> const verify_mac =
        correct_size ? ds.GetData(0, expected_mac.size(), expected_mac.size()) :
        ds.GetData(0, 0, PSA_HASH_MAX_SIZE * 2);
    psa_status_t const expected_verify_status =
        verify_mac == expected_mac ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;

    bool const multipart = ds.Get<bool>();
    if (multipart) {
        util::Multipart parts = util::ToParts(ds, cleartext);
        CF_ASSERT_PSA(operation.verify_start());
        for (const auto& part : parts) {
            CF_ASSERT_PSA(operation.update(part.first, part.second));
        }
        CF_ASSERT_EQ(operation.verify_finish(verify_mac.data(), verify_mac.size()),
                     expected_verify_status);
    } else {
        CF_ASSERT_EQ(operation.verify(cleartext.GetPtr(&ds), cleartext.GetSize(),
                                      verify_mac.data(), verify_mac.size()),
                     expected_verify_status);
    }
}

std::optional<component::MAC> TF_PSA_Crypto::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    TF_PSA_Crypto_detail::SetGlobalDs(&ds);

    psa_algorithm_t const hash_alg =
        TF_PSA_Crypto_detail::digest_to_psa_algorithm_t(op.digestType);
    /* Skip unknown algorithms */
    CF_CHECK_NE(hash_alg, PSA_ALG_NONE);

    /* PSA does not allow empty keys */
    CF_CHECK_NE(op.cipher.key.GetSize(), 0);

    /* PSA does not allow unusually large keys */
    CF_CHECK_LTE(op.cipher.key.GetSize(), PSA_MAX_KEY_BITS / 8);

    {
        TF_PSA_Crypto_detail::MACOperation operation;
        CF_ASSERT_PSA(operation.set_key(PSA_KEY_TYPE_HMAC,
                                        op.cipher.key.GetPtr(&ds),
                                        op.cipher.key.GetSize(),
                                        PSA_ALG_HMAC(hash_alg)));
        ret = mac_compute(operation, op.cleartext, ds);
        mac_verify(operation, op.cleartext, ds, ret->Get());
    }

end:
    TF_PSA_Crypto_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::MAC> TF_PSA_Crypto::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    TF_PSA_Crypto_detail::SetGlobalDs(&ds);

    CF_CHECK_TRUE(is_cipher_consistent(op.cipher));

    {
        psa_key_type_t const key_type =
            TF_PSA_Crypto_detail::cipher_to_psa_key_type_t(op.cipher.cipherType);
        /* Skip unknown ciphers */
        CF_CHECK_NE(key_type, PSA_KEY_TYPE_NONE);
        /* op.cipher encodes a mode. Experimentally, if the mode isn't CBC,
         * we're expected to bail out. */
        CF_CHECK_TRUE(repository::IsCBC(op.cipher.cipherType.Get()));
        /* Skip ciphers that are not supported for CMAC */
        CF_CHECK_TRUE(key_type == PSA_KEY_TYPE_AES ||
                      (key_type == PSA_KEY_TYPE_DES && op.cipher.key.GetSize() == 192));

        TF_PSA_Crypto_detail::MACOperation operation;
        CF_ASSERT_PSA(operation.set_key(key_type,
                                        op.cipher.key.GetPtr(&ds),
                                        op.cipher.key.GetSize(),
                                        PSA_ALG_CMAC));
        ret = mac_compute(operation, op.cleartext, ds);
        mac_verify(operation, op.cleartext, ds, ret->Get());
    }

end:
    TF_PSA_Crypto_detail::UnsetGlobalDs();

    return ret;
}

static bool cipher_decrypt_oneshot(TF_PSA_Crypto_detail::CipherOperation operation,
                                   const std::vector<uint8_t> &iv,
                                   const std::vector<uint8_t>& ciphertext,
                                   std::vector<uint8_t>& cleartext) {
    std::vector<uint8_t> tmp(iv);
    tmp.insert(tmp.end(), ciphertext.begin(), ciphertext.end());
    size_t length = 0;
    vector_extend(cleartext, operation.decrypt_output_size(tmp.size()));
    psa_status_t status =
        operation.decrypt(tmp.data(), tmp.size(),
                          cleartext.data(), cleartext.size(),
                          &length);
    cleartext.resize(length);
    return operation.check_finish_status(false, tmp.size(), status);
}

static void aead_encrypt_oneshot(TF_PSA_Crypto_detail::AEADOperation operation,
                                 const std::vector<uint8_t> &iv,
                                 const std::vector<uint8_t>& aad,
                                 const std::vector<uint8_t>& cleartext,
                                 std::vector<uint8_t>& ciphertext,
                                 std::vector<uint8_t>& tag) {
    size_t tag_length = operation.tag_length();
    std::vector<uint8_t> tmp;
    CF_ASSERT_PSA(operation.encrypt(iv, aad, cleartext, tmp));
    CF_ASSERT(tmp.size() >= tag_length,
              "psa_aead_encrypt() output shorter than tag");
    vector_extend(ciphertext, tmp.size() - tag_length);
    std::copy(tmp.begin(), tmp.end() - tag_length, ciphertext.begin());
    vector_extend(tag, tag_length);
    std::copy(tmp.end() - tag_length, tmp.end(), tag.begin());
}

static bool aead_decrypt_oneshot(TF_PSA_Crypto_detail::AEADOperation operation,
                                 const std::vector<uint8_t>& iv,
                                 const std::vector<uint8_t> &aad,
                                 const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& tag,
                                 std::vector<uint8_t> &cleartext) {
    std::vector<uint8_t> tmp(ciphertext);
    tmp.insert(tmp.end(), tag.begin(), tag.end());
    psa_status_t status = operation.decrypt(iv, aad, tmp, cleartext);
    CF_ASSERT(status == PSA_SUCCESS ||
              status == PSA_ERROR_INVALID_SIGNATURE,
              "psa_aead_decrypt status");
    return status == PSA_SUCCESS;
}

static bool cipher_multipart(TF_PSA_Crypto_detail::CipherOperation operation,
                             bool is_encrypt,
                             const std::optional<std::vector<uint8_t>> iv,
                             const util::Multipart& input_parts,
                             std::vector<uint8_t>& output) {
    if (is_encrypt) {
        CF_ASSERT_PSA(operation.encrypt_setup());
    } else {
        CF_ASSERT_PSA(operation.decrypt_setup());
    }

    if (iv) {
        CF_ASSERT_PSA(operation.set_iv(iv->data(), iv->size()));
    }

    output.resize(0);
    size_t input_length = 0;
    for (const auto& part : input_parts) {
        size_t output_cursor = output.size();
        vector_extend(output, output_cursor + operation.update_output_size(part.second));
        size_t length = 0;
        input_length += part.second;
        CF_ASSERT_PSA(operation.update(part.first, part.second,
                                       output.data() + output_cursor,
                                       output.size() - output_cursor,
                                       &length));
        output.resize(output_cursor + length);
    }

    size_t output_cursor = output.size();
    vector_extend(output, output_cursor + operation.finish_output_size());
    size_t length = 0;
    psa_status_t status = operation.finish(output.data() + output_cursor,
                                           output.size() - output_cursor,
                                           &length);
    output.resize(output_cursor + length);
    return operation.check_finish_status(is_encrypt, input_length, status);
}

static bool aead_multipart(TF_PSA_Crypto_detail::AEADOperation operation,
                           bool is_encrypt,
                           const std::vector<uint8_t>& iv,
                           const util::Multipart& aad_parts, size_t aad_length,
                           const util::Multipart& input_parts, size_t input_length,
                           std::vector<uint8_t>& output,
                           std::vector<uint8_t> &tag) {
    if (is_encrypt) {
        CF_ASSERT_PSA(operation.encrypt_setup());
    } else {
        CF_ASSERT_PSA(operation.decrypt_setup());
    }

    /* Necessary for CCM. Doesn't hurt for other algorithms. */
    CF_ASSERT_PSA(operation.set_lengths(aad_length, input_length));

    CF_ASSERT_PSA(operation.set_iv(iv.data(), iv.size()));

    for (const auto& part : aad_parts) {
        CF_ASSERT_PSA(operation.update_aad(part.first, part.second));
    }

    output.resize(0);
    for (const auto& part : input_parts) {
        size_t output_cursor = output.size();
        vector_extend(output, output_cursor + operation.update_output_size(part.second));
        size_t length = 0;
        CF_ASSERT_PSA(operation.update(part.first, part.second,
                                       output.data() + output_cursor,
                                       output.capacity() - output_cursor,
                                       &length));
        output.resize(output_cursor + length);
    }

    size_t output_cursor = output.size();
    if (is_encrypt) {
        vector_extend(output, output_cursor + operation.finish_output_size());
        vector_extend(tag, operation.tag_length());
        size_t length = 0;
        size_t tag_length = 0;
        CF_ASSERT_PSA(operation.finish(output.data() + output_cursor,
                                       output.size() - output_cursor,
                                       &length,
                                       tag.data(), tag.size(), &tag_length));
        output.resize(output_cursor + length);
        tag.resize(tag_length);
        return true;
    } else {
        vector_extend(output, output_cursor + operation.verify_output_size());
        size_t length = 0;
        psa_status_t status = operation.verify(output.data() + output_cursor,
                                               output.size() - output_cursor,
                                               &length,
                                               tag.data(), tag.size());
        CF_ASSERT(status == PSA_SUCCESS ||
                  status == PSA_ERROR_INVALID_SIGNATURE,
                  "psa_aead_verify status");
        output.resize(output_cursor + length);
        return status == PSA_SUCCESS;
    }
}

static bool cipher_common(operation::Operation& op,
                          bool is_encrypt,
                          component::SymmetricCipher cipher,
                          const std::optional<component::AAD>& aad,
                          const Buffer& input,
                          std::vector<uint8_t> &output,
                          std::vector<uint8_t>& tag) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    TF_PSA_Crypto_detail::SetGlobalDs(&ds);

    CF_CHECK_TRUE(is_cipher_consistent(cipher));

    {
        psa_key_type_t const key_type =
            TF_PSA_Crypto_detail::cipher_to_psa_key_type_t(cipher.cipherType);
        psa_algorithm_t alg =
            TF_PSA_Crypto_detail::cipher_to_psa_algorithm_t(cipher.cipherType);
        /* Skip unknown mechanisms */
        CF_CHECK_NE(key_type, PSA_KEY_TYPE_NONE);
        CF_CHECK_NE(alg, PSA_ALG_NONE);

        bool multipart = ds.Get<bool>();

        if (repository::IsAEAD(cipher.cipherType.Get()) ||
            (repository::IsCCM(cipher.cipherType.Get()) && tag.size() != 0)) {
            TF_PSA_Crypto_detail::AEADOperation operation;
            CF_ASSERT_PSA(operation.set_key(key_type,
                                            cipher.key.GetPtr(&ds),
                                            cipher.key.GetSize(),
                                            alg));

            /* Cryptofuzz can call us with an invalid IV length! */
            CF_CHECK_TRUE(operation.is_valid_iv_length(cipher.iv.GetSize()));

            /* Cryptofuzz can call us with an invalid tag length! */
            /* TODO: support shorter tags */
            CF_CHECK_TRUE(tag.size() == operation.tag_length());

            if (multipart) {
                util::Multipart aad_parts = util::ToParts(ds, *aad);
                util::Multipart input_parts = util::ToParts(ds, input);
                bool verify_ok =
                    aead_multipart(operation, is_encrypt,
                                   cipher.iv.GetConstVectorPtr(),
                                   aad_parts, aad->GetSize(),
                                   input_parts, input.GetSize(),
                                   output, tag);
                CF_CHECK_TRUE(verify_ok);
            } else { // One-shot
                if (is_encrypt) {
                    aead_encrypt_oneshot(operation,
                                         cipher.iv.GetConstVectorPtr(),
                                         aad->GetConstVectorPtr(),
                                         input.GetConstVectorPtr(),
                                         output, tag);
                } else {
                    bool verify_ok =
                        aead_decrypt_oneshot(operation,
                                             cipher.iv.GetConstVectorPtr(),
                                             aad->GetConstVectorPtr(),
                                             input.GetConstVectorPtr(),
                                             tag, output);
                    CF_CHECK_TRUE(verify_ok);
                }
            }

        } else {
            TF_PSA_Crypto_detail::CipherOperation operation;
            if (alg == PSA_ALG_CCM) {
                alg = PSA_ALG_CCM_STAR_NO_TAG;
            }
            CF_ASSERT_PSA(operation.set_key(key_type,
                                            cipher.key.GetPtr(&ds),
                                            cipher.key.GetSize(),
                                            alg));

            /* Cryptofuzz can call us with an invalid IV length! */
            CF_CHECK_TRUE(operation.is_valid_iv_length(cipher.iv.GetSize()));

            /* Encryption is always multipart, because the PSA API
             * only supports one-shot encryption with a random IV,
             * which does not play nicely with fuzzing. */
            if (is_encrypt) {
                multipart = true;
            }

            /* Reject incomplete blocks for unpadded block ciphers */
            if (repository::IsECB(cipher.cipherType.Get()) ||
                repository::IsCBC(cipher.cipherType.Get())) {
                CF_CHECK_EQ(input.GetSize() % operation.block_size(), 0);
            }

            bool decrypt_ok;
            if (multipart) {
                /* Skip set_iv() for ECB */
                const std::optional<std::vector<uint8_t>> iv =
                    (repository::IsECB(cipher.cipherType.Get()) ?
                     std::nullopt :
                     std::optional(cipher.iv.GetConstVectorPtr()));
                util::Multipart input_parts = util::ToParts(ds, input);
                decrypt_ok = cipher_multipart(operation, is_encrypt, iv,
                                              input_parts, output);
            } else {
                /* Ignore IV for ECB: force an empty IV */
                const std::vector<uint8_t> iv =
                    (repository::IsECB(cipher.cipherType.Get()) ?
                     std::vector<uint8_t>(0) :
                     cipher.iv.GetConstVectorPtr());
                decrypt_ok = cipher_decrypt_oneshot(operation, iv,
                                                    input.GetConstVectorPtr(),
                                                    output);
            }
            CF_CHECK_TRUE(decrypt_ok);
        }
    }

    TF_PSA_Crypto_detail::UnsetGlobalDs();
    return true;

end:
    TF_PSA_Crypto_detail::UnsetGlobalDs();
    return false;
}

std::optional<component::Ciphertext> TF_PSA_Crypto::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::vector<uint8_t> output;
    std::vector<uint8_t> tag(op.tagSize ? op.tagSize.value() : 0);
    if (!cipher_common(op, true, op.cipher, op.aad, op.cleartext,
                       output, tag)) {
        return std::nullopt;
    }
    auto tag_opt = op.tagSize ? std::optional(component::Tag(tag)) : std::nullopt;
    return component::Ciphertext(Buffer(output), tag_opt);
}

std::optional<component::Cleartext> TF_PSA_Crypto::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::vector<uint8_t> output;
    if (!cipher_common(op, false, op.cipher, op.aad, op.ciphertext,
                       output, const_cast<std::vector<uint8_t>&>(op.tag->GetConstVectorPtr()))) {
        return std::nullopt;
    }
    return Buffer(output);
}

} /* namespace module */
} /* namespace cryptofuzz */
