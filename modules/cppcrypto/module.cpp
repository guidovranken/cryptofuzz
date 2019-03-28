#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#include <cppcrypto/sha1.h>
#include <cppcrypto/sha256.h>
#include <cppcrypto/sha512.h>
#include <cppcrypto/md5.h>
#include <cppcrypto/whirlpool.h>
#include <cppcrypto/sm3.h>
#include <cppcrypto/sha3.h>
#include <cppcrypto/groestl.h>
#include <cppcrypto/jh.h>
#include <cppcrypto/streebog.h>
#include <cppcrypto/skein256.h>
#include <cppcrypto/skein512.h>
#include <cppcrypto/skein1024.h>

#include <cppcrypto/hmac.h>

#include <cppcrypto/aria.h>
#include <cppcrypto/camellia.h>
#include <cppcrypto/sm4.h>
#include <cppcrypto/groestl.h>

namespace cryptofuzz {
namespace module {

CPPCrypto::CPPCrypto(void) :
    Module("CPPCrypto") { }

template <class Hasher>
std::optional<component::Digest> CPPCrypto::digest(Hasher& hasher, operation::Digest& op, Datasource& ds, size_t hashSize) const {
    util::Multipart parts;

    if ( hashSize == 0 ) {
        hashSize = hasher.hashsize() / 8;
    }

    unsigned char hash[hasher.hashsize() / 8];

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        hasher.init();
    }

    /* Process */
    for (const auto& part : parts) {
        hasher.update(part.first, part.second);
    }

    /* Finalize */
    {
        hasher.final(hash);
        return component::Digest(hash, hashSize);
    }
}

std::optional<component::Digest> CPPCrypto::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case ID("Cryptofuzz/Digest/SHA1"):
            {
                cppcrypto::sha1 hasher;
                return digest<cppcrypto::sha1>(hasher, op, ds);
            }
            break;
        case ID("Cryptofuzz/Digest/SHA256"):
            {
                cppcrypto::sha256 hasher;
                return digest<cppcrypto::sha256>(hasher, op, ds);
            }
            break;
        case ID("Cryptofuzz/Digest/SHA512"):
            {
                cppcrypto::sha512 hasher;
                return digest<cppcrypto::sha512>(hasher, op, ds);
            }
            break;
        case ID("Cryptofuzz/Digest/MD5"):
            {
                cppcrypto::md5 hasher;
                return digest<cppcrypto::md5>(hasher, op, ds);
            }
            break;
        case ID("Cryptofuzz/Digest/WHIRLPOOL"):
            {
                cppcrypto::whirlpool hasher;
                return digest<cppcrypto::whirlpool>(hasher, op, ds);
            }
            break;
        case ID("Cryptofuzz/Digest/SM3"):
            {
                cppcrypto::sm3 hasher;
                return digest<cppcrypto::sm3>(hasher, op, ds);
            }
            break;
        case ID("Cryptofuzz/Digest/SHAKE128"):
            {
                cppcrypto::shake128 hasher;
                return digest<cppcrypto::shake128>(hasher, op, ds, 128 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/SHAKE256"):
            {
                cppcrypto::shake256 hasher;
                return digest<cppcrypto::shake256>(hasher, op, ds, 256 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/GROESTL-256"):
            {
                cppcrypto::groestl hasher(256);
                return digest<cppcrypto::groestl>(hasher, op, ds, 256 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-224"):
            {
                cppcrypto::jh hasher(224);
                return digest<cppcrypto::jh>(hasher, op, ds, 224 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-256"):
            {
                cppcrypto::jh hasher(256);
                return digest<cppcrypto::jh>(hasher, op, ds, 256 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-384"):
            {
                cppcrypto::jh hasher(384);
                return digest<cppcrypto::jh>(hasher, op, ds, 384 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-512"):
            {
                cppcrypto::jh hasher(512);
                return digest<cppcrypto::jh>(hasher, op, ds, 512 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/STREEBOG-256"):
            {
                cppcrypto::streebog hasher(256);
                return digest<cppcrypto::streebog>(hasher, op, ds, 256 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/STREEBOG-512"):
            {
                cppcrypto::streebog hasher(512);
                return digest<cppcrypto::streebog>(hasher, op, ds, 512 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/SKEIN-256"):
            {
                cppcrypto::skein256 hasher(256);
                return digest<cppcrypto::skein256>(hasher, op, ds, 256 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/SKEIN-512"):
            {
                cppcrypto::skein512 hasher(512);
                return digest<cppcrypto::skein512>(hasher, op, ds, 512 / 8);
            }
            break;
        case ID("Cryptofuzz/Digest/SKEIN-1024"):
            {
                cppcrypto::skein1024 hasher(1024);
                return digest<cppcrypto::skein1024>(hasher, op, ds, 1024 / 8);
            }
            break;
    }

    return ret;
}

std::optional<component::MAC> CPPCrypto::OpHMAC(operation::HMAC& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::MAC> ret = std::nullopt;

    return ret;
}

std::optional<component::Ciphertext> CPPCrypto::encryptCBC(cppcrypto::cbc& cbc, operation::SymmetricEncrypt& op, Datasource& ds) const {
    std::optional<component::Ciphertext> ret = std::nullopt;

    util::Multipart parts;

    std::vector<uint8_t> ciphertext;
    unsigned char ciphertextTmp[1024];

    /* Initialize */
    {
        CF_CHECK_EQ(op.cipher.key.GetSize(), cbc.keysize() / 8);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), cbc.ivsize() / 8);
        parts = util::ToParts(ds, op.cleartext);
        cbc.init(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(), cppcrypto::block_cipher::encryption);
    }

    /* Process */
    for (const auto& part : parts) {
        size_t resultLen;
        cbc.encrypt_update(part.first, part.second, ciphertextTmp, resultLen);
        ciphertext.insert(ciphertext.end(), ciphertextTmp, ciphertextTmp + resultLen);
    }

    /* Finalize */
    {
        size_t resultLen;
        cbc.encrypt_final(ciphertextTmp, resultLen);
        ciphertext.insert(ciphertext.end(), ciphertextTmp, ciphertextTmp + resultLen);
        ret = component::Ciphertext(ciphertext.data(), ciphertext.size());
    }

end:

    return ret;
}

std::optional<component::Cleartext> CPPCrypto::decryptCBC(cppcrypto::cbc& cbc, operation::SymmetricDecrypt& op, Datasource& ds) const {
    std::optional<component::Cleartext> ret = std::nullopt;

    util::Multipart parts;

    std::vector<uint8_t> cleartext;
    unsigned char cleartextTmp[1024];

    /* Initialize */
    {
        CF_CHECK_EQ(op.cipher.key.GetSize(), cbc.keysize() / 8);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), cbc.ivsize() / 8);
        parts = util::ToParts(ds, op.ciphertext);
        cbc.init(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(), cppcrypto::block_cipher::decryption);
    }

    /* Process */
    for (const auto& part : parts) {
        size_t resultLen;
        cbc.decrypt_update(part.first, part.second, cleartextTmp, resultLen);
        cleartext.insert(cleartext.end(), cleartextTmp, cleartextTmp + resultLen);
    }

    /* Finalize */
    {
        size_t resultLen;
        cbc.decrypt_final(cleartextTmp, resultLen);
        cleartext.insert(cleartext.end(), cleartextTmp, cleartextTmp + resultLen);
        ret = component::Ciphertext(cleartext.data(), cleartext.size());
    }

end:

    return ret;
}

std::optional<component::Digest> CPPCrypto::encryptCTR(cppcrypto::ctr& ctr, operation::SymmetricEncrypt& op, Datasource& ds, const size_t keySize, const size_t blockSize) const {
    (void)ds;
    std::optional<component::Ciphertext> ret = std::nullopt;

    unsigned char ciphertextTmp[op.cleartext.GetSize()];

    /* Initialize */
    {
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
        /* The length of the key in bytes should be equal to keysize()/8 of the block cipher (cppcrypto documentation)*/
        CF_CHECK_EQ(op.cipher.key.GetSize(), keySize);
        /* the length of the initialization vector (iv) in bytes should be equal to or smaller than blocksize()/8 of the block cipher (cppcrypto documentation) */
        CF_CHECK_LTE(op.cipher.iv.GetSize(), blockSize);
        ctr.init(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
    }

    /* Process */
    {
        ctr.encrypt(op.cleartext.GetPtr(), op.cleartext.GetSize(), ciphertextTmp);
    }

    /* Finalize */
    {
        ret = component::Ciphertext(ciphertextTmp, op.cleartext.GetSize());
    }

end:
    /* CTR crypting does not seem to work so return nullopt */
    return std::nullopt;

    return ret;
}

std::optional<component::Cleartext> CPPCrypto::decryptCTR(cppcrypto::ctr& ctr, operation::SymmetricDecrypt& op, Datasource& ds, const size_t keySize, const size_t blockSize) const {
    (void)ds;
    std::optional<component::Ciphertext> ret = std::nullopt;

    unsigned char cleartextTmp[op.ciphertext.GetSize()];

    /* Initialize */
    {
        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        /* The length of the key in bytes should be equal to keysize()/8 of the block cipher (cppcrypto documentation)*/
        CF_CHECK_EQ(op.cipher.key.GetSize(), keySize);
        /* the length of the initialization vector (iv) in bytes should be equal to or smaller than blocksize()/8 of the block cipher (cppcrypto documentation) */
        CF_CHECK_LTE(op.cipher.iv.GetSize(), blockSize);
        ctr.init(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
    }

    /* Process */
    {
        ctr.decrypt(op.ciphertext.GetPtr(), op.ciphertext.GetSize(), cleartextTmp);
    }

    /* Finalize */
    {
        ret = component::Cleartext(cleartextTmp, op.ciphertext.GetSize());
    }

end:
    /* CTR crypting does not seem to work so return nullopt */
    return std::nullopt;

    return ret;
}

std::optional<component::Ciphertext> CPPCrypto::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    using fuzzing::datasource::ID;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<component::Ciphertext> ret = std::nullopt;

    switch ( op.cipher.cipherType.Get() ) {
        case ID("Cryptofuzz/Cipher/ARIA_128_CBC"):
            {
                cppcrypto::aria128 cipher;
                cppcrypto::cbc cbc(cipher);
                return encryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_192_CBC"):
            {
                cppcrypto::aria192 cipher;
                cppcrypto::cbc cbc(cipher);
                return encryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_256_CBC"):
            {
                cppcrypto::aria256 cipher;
                cppcrypto::cbc cbc(cipher);
                return encryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"):
            {
                cppcrypto::camellia128 cipher;
                cppcrypto::cbc cbc(cipher);
                return encryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"):
            {
                cppcrypto::camellia192 cipher;
                cppcrypto::cbc cbc(cipher);
                return encryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"):
            {
                cppcrypto::camellia256 cipher;
                cppcrypto::cbc cbc(cipher);
                return encryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/SM4_CBC"):
            {
                cppcrypto::sm4 cipher;
                cppcrypto::cbc cbc(cipher);
                /* Do not return ciphertext due to mismatch:
                   Difference detected

                    Operation:
                    operation name: SymmetricDecrypt
                    ciphertext: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} (16 bytes)
                    cipher iv: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0xcd, 0x9f, 0x1a, 0x00, 0x00} (16 bytes)
                    cipher key: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x10} (16 bytes)
                    cipher: SM4_CBC
                    cleartextSize: 4225023

                    Module CPPCrypto result:

                    {0x5c, 0xd2, 0xe2, 0xb2, 0xdc, 0xfa, 0x70, 0xdc, 0x86, 0xff, 0x15} (11 bytes)

                    Module OpenSSL result:

                    {}
                 */
                encryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_128_CTR"):
            {
                cppcrypto::aria128 cipher;
                cppcrypto::ctr ctr(cipher);
                return encryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_192_CTR"):
            {
                cppcrypto::aria192 cipher;
                cppcrypto::ctr ctr(cipher);
                return encryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_256_CTR"):
            {
                cppcrypto::aria256 cipher;
                cppcrypto::ctr ctr(cipher);
                return encryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CTR"):
            {
                cppcrypto::camellia128 cipher;
                cppcrypto::ctr ctr(cipher);
                return encryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CTR"):
            {
                cppcrypto::camellia192 cipher;
                cppcrypto::ctr ctr(cipher);
                return encryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CTR"):
            {
                cppcrypto::camellia256 cipher;
                cppcrypto::ctr ctr(cipher);
                return encryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/SM4_CTR"):
            {
                cppcrypto::sm4 cipher;
                cppcrypto::ctr ctr(cipher);
                return encryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
    }

    return ret;
}

std::optional<component::Cleartext> CPPCrypto::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    using fuzzing::datasource::ID;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<component::Cleartext> ret = std::nullopt;

    switch ( op.cipher.cipherType.Get() ) {
        case ID("Cryptofuzz/Cipher/ARIA_128_CBC"):
            {
                cppcrypto::aria128 cipher;
                cppcrypto::cbc cbc(cipher);
                return decryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_192_CBC"):
            {
                cppcrypto::aria192 cipher;
                cppcrypto::cbc cbc(cipher);
                return decryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_256_CBC"):
            {
                cppcrypto::aria256 cipher;
                cppcrypto::cbc cbc(cipher);
                return decryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"):
            {
                cppcrypto::camellia128 cipher;
                cppcrypto::cbc cbc(cipher);
                return decryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"):
            {
                cppcrypto::camellia192 cipher;
                cppcrypto::cbc cbc(cipher);
                return decryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"):
            {
                cppcrypto::camellia256 cipher;
                cppcrypto::cbc cbc(cipher);
                return decryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/SM4_CBC"):
            {
                cppcrypto::sm4 cipher;
                cppcrypto::cbc cbc(cipher);
                /* Do not return cleartext due to mismatch:
                   Difference detected

                    Operation:
                    operation name: SymmetricDecrypt
                    ciphertext: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} (16 bytes)
                    cipher iv: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0xcd, 0x9f, 0x1a, 0x00, 0x00} (16 bytes)
                    cipher key: {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x10} (16 bytes)
                    cipher: SM4_CBC
                    cleartextSize: 4225023

                    Module CPPCrypto result:

                    {0x5c, 0xd2, 0xe2, 0xb2, 0xdc, 0xfa, 0x70, 0xdc, 0x86, 0xff, 0x15} (11 bytes)

                    Module OpenSSL result:

                    {}
                 */
                decryptCBC(cbc, op, ds);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_128_CTR"):
            {
                cppcrypto::aria128 cipher;
                cppcrypto::ctr ctr(cipher);
                return decryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_192_CTR"):
            {
                cppcrypto::aria192 cipher;
                cppcrypto::ctr ctr(cipher);
                return decryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/ARIA_256_CTR"):
            {
                cppcrypto::aria256 cipher;
                cppcrypto::ctr ctr(cipher);
                return decryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CTR"):
            {
                cppcrypto::camellia128 cipher;
                cppcrypto::ctr ctr(cipher);
                return decryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CTR"):
            {
                cppcrypto::camellia192 cipher;
                cppcrypto::ctr ctr(cipher);
                return decryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CTR"):
            {
                cppcrypto::camellia256 cipher;
                cppcrypto::ctr ctr(cipher);
                return decryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
        case ID("Cryptofuzz/Cipher/SM4_CTR"):
            {
                cppcrypto::sm4 cipher;
                cppcrypto::ctr ctr(cipher);
                return decryptCTR(ctr, op, ds, cipher.keysize() / 8, cipher.blocksize() / 8);
            }
            break;
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
