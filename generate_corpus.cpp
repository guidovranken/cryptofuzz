#include <stdio.h>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <fuzzing/datasource/id.hpp>

using fuzzing::datasource::ID;

size_t counter = 0;

static const std::vector<size_t> sizes = {
    //0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512,
    0, 1, 2, 4, 8, 16, 32
};

static const std::vector<uint64_t> digestTypes = {
    ID("Cryptofuzz/Module/OpenSSL"),
    ID("Cryptofuzz/Digest/SHA1"),
    ID("Cryptofuzz/Digest/SHA224"),
    ID("Cryptofuzz/Digest/SHA256"),
    ID("Cryptofuzz/Digest/SHA384"),
    ID("Cryptofuzz/Digest/SHA512"),
    ID("Cryptofuzz/Digest/MD4"),
    ID("Cryptofuzz/Digest/MD5"),
    ID("Cryptofuzz/Digest/MDC2"),
    ID("Cryptofuzz/Digest/RIPEMD160"),
    ID("Cryptofuzz/Digest/WHIRLPOOL"),
    ID("Cryptofuzz/Digest/SM3"),
    ID("Cryptofuzz/Digest/BLAKE2B512"),
    ID("Cryptofuzz/Digest/BLAKE2S256"),
    ID("Cryptofuzz/Digest/SHAKE128"),
    ID("Cryptofuzz/Digest/SHAKE256"),
    ID("Cryptofuzz/Digest/SHA3-224"),
    ID("Cryptofuzz/Digest/SHA3-256"),
    ID("Cryptofuzz/Digest/SHA3-384"),
    ID("Cryptofuzz/Digest/SHA3-512"),
    ID("Cryptofuzz/Digest/SHA512-224"),
    ID("Cryptofuzz/Digest/SHA512-256"),
};

static const std::vector<uint64_t> cipherTypes = {
    ID("Cryptofuzz/Cipher/AES_128_CBC"),
    ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA1"),
    ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA256"),
    ID("Cryptofuzz/Cipher/AES_128_CCM"),
    ID("Cryptofuzz/Cipher/AES_128_CFB"),
    ID("Cryptofuzz/Cipher/AES_128_CFB1"),
    ID("Cryptofuzz/Cipher/AES_128_CFB8"),
    ID("Cryptofuzz/Cipher/AES_128_CTR"),
    ID("Cryptofuzz/Cipher/AES_128_ECB"),
    ID("Cryptofuzz/Cipher/AES_128_GCM"),
    ID("Cryptofuzz/Cipher/AES_128_OCB"),
    ID("Cryptofuzz/Cipher/AES_128_OFB"),
    ID("Cryptofuzz/Cipher/AES_128_WRAP"),
    ID("Cryptofuzz/Cipher/AES_128_WRAP_PAD"),
    ID("Cryptofuzz/Cipher/AES_128_XTS"),
    ID("Cryptofuzz/Cipher/AES_192_CBC"),
    ID("Cryptofuzz/Cipher/AES_192_CCM"),
    ID("Cryptofuzz/Cipher/AES_192_CFB"),
    ID("Cryptofuzz/Cipher/AES_192_CFB1"),
    ID("Cryptofuzz/Cipher/AES_192_CFB8"),
    ID("Cryptofuzz/Cipher/AES_192_CTR"),
    ID("Cryptofuzz/Cipher/AES_192_ECB"),
    ID("Cryptofuzz/Cipher/AES_192_GCM"),
    ID("Cryptofuzz/Cipher/AES_192_OCB"),
    ID("Cryptofuzz/Cipher/AES_192_OFB"),
    ID("Cryptofuzz/Cipher/AES_192_WRAP"),
    ID("Cryptofuzz/Cipher/AES_192_WRAP_PAD"),
    ID("Cryptofuzz/Cipher/AES_256_CBC"),
    ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA1"),
    ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA256"),
    ID("Cryptofuzz/Cipher/AES_256_CCM"),
    ID("Cryptofuzz/Cipher/AES_256_CFB"),
    ID("Cryptofuzz/Cipher/AES_256_CFB1"),
    ID("Cryptofuzz/Cipher/AES_256_CFB8"),
    ID("Cryptofuzz/Cipher/AES_256_CTR"),
    ID("Cryptofuzz/Cipher/AES_256_ECB"),
    ID("Cryptofuzz/Cipher/AES_256_GCM"),
    ID("Cryptofuzz/Cipher/AES_256_OCB"),
    ID("Cryptofuzz/Cipher/AES_256_OFB"),
    ID("Cryptofuzz/Cipher/AES_256_WRAP"),
    ID("Cryptofuzz/Cipher/AES_256_WRAP_PAD"),
    ID("Cryptofuzz/Cipher/AES_256_XTS"),
    ID("Cryptofuzz/Cipher/ARIA_128_CBC"),
    ID("Cryptofuzz/Cipher/ARIA_128_CCM"),
    ID("Cryptofuzz/Cipher/ARIA_128_CFB"),
    ID("Cryptofuzz/Cipher/ARIA_128_CFB1"),
    ID("Cryptofuzz/Cipher/ARIA_128_CFB8"),
    ID("Cryptofuzz/Cipher/ARIA_128_CTR"),
    ID("Cryptofuzz/Cipher/ARIA_128_ECB"),
    ID("Cryptofuzz/Cipher/ARIA_128_GCM"),
    ID("Cryptofuzz/Cipher/ARIA_128_OFB"),
    ID("Cryptofuzz/Cipher/ARIA_192_CBC"),
    ID("Cryptofuzz/Cipher/ARIA_192_CCM"),
    ID("Cryptofuzz/Cipher/ARIA_192_CFB"),
    ID("Cryptofuzz/Cipher/ARIA_192_CFB1"),
    ID("Cryptofuzz/Cipher/ARIA_192_CFB8"),
    ID("Cryptofuzz/Cipher/ARIA_192_CTR"),
    ID("Cryptofuzz/Cipher/ARIA_192_ECB"),
    ID("Cryptofuzz/Cipher/ARIA_192_GCM"),
    ID("Cryptofuzz/Cipher/ARIA_192_OFB"),
    ID("Cryptofuzz/Cipher/ARIA_256_CBC"),
    ID("Cryptofuzz/Cipher/ARIA_256_CCM"),
    ID("Cryptofuzz/Cipher/ARIA_256_CFB"),
    ID("Cryptofuzz/Cipher/ARIA_256_CFB1"),
    ID("Cryptofuzz/Cipher/ARIA_256_CFB8"),
    ID("Cryptofuzz/Cipher/ARIA_256_CTR"),
    ID("Cryptofuzz/Cipher/ARIA_256_ECB"),
    ID("Cryptofuzz/Cipher/ARIA_256_GCM"),
    ID("Cryptofuzz/Cipher/ARIA_256_OFB"),
    ID("Cryptofuzz/Cipher/BF_CBC"),
    ID("Cryptofuzz/Cipher/BF_CFB"),
    ID("Cryptofuzz/Cipher/BF_ECB"),
    ID("Cryptofuzz/Cipher/BF_OFB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"),
    ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB1"),
    ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB8"),
    ID("Cryptofuzz/Cipher/CAMELLIA_128_CTR"),
    ID("Cryptofuzz/Cipher/CAMELLIA_128_ECB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_128_OFB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"),
    ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB1"),
    ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB8"),
    ID("Cryptofuzz/Cipher/CAMELLIA_192_CTR"),
    ID("Cryptofuzz/Cipher/CAMELLIA_192_ECB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_192_OFB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"),
    ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB1"),
    ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB8"),
    ID("Cryptofuzz/Cipher/CAMELLIA_256_CTR"),
    ID("Cryptofuzz/Cipher/CAMELLIA_256_ECB"),
    ID("Cryptofuzz/Cipher/CAMELLIA_256_OFB"),
    ID("Cryptofuzz/Cipher/CAST5_CBC"),
    ID("Cryptofuzz/Cipher/CAST5_CFB"),
    ID("Cryptofuzz/Cipher/CAST5_ECB"),
    ID("Cryptofuzz/Cipher/CAST5_OFB"),
    ID("Cryptofuzz/Cipher/CHACHA20"),
    ID("Cryptofuzz/Cipher/CHACHA20_POLY1305"),
    ID("Cryptofuzz/Cipher/DESX_CBC"),
    ID("Cryptofuzz/Cipher/DES_CBC"),
    ID("Cryptofuzz/Cipher/DES_CFB"),
    ID("Cryptofuzz/Cipher/DES_CFB1"),
    ID("Cryptofuzz/Cipher/DES_CFB8"),
    ID("Cryptofuzz/Cipher/DES_ECB"),
    ID("Cryptofuzz/Cipher/DES_EDE"),
    ID("Cryptofuzz/Cipher/DES_EDE3"),
    ID("Cryptofuzz/Cipher/DES_EDE3_CBC"),
    ID("Cryptofuzz/Cipher/DES_EDE3_CFB"),
    ID("Cryptofuzz/Cipher/DES_EDE3_CFB1"),
    ID("Cryptofuzz/Cipher/DES_EDE3_CFB8"),
    ID("Cryptofuzz/Cipher/DES_EDE3_OFB"),
    ID("Cryptofuzz/Cipher/DES_EDE3_WRAP"),
    ID("Cryptofuzz/Cipher/DES_EDE_CBC"),
    ID("Cryptofuzz/Cipher/DES_EDE_CFB"),
    ID("Cryptofuzz/Cipher/DES_EDE_OFB"),
    ID("Cryptofuzz/Cipher/DES_OFB"),
    ID("Cryptofuzz/Cipher/IDEA_CBC"),
    ID("Cryptofuzz/Cipher/IDEA_CFB"),
    ID("Cryptofuzz/Cipher/IDEA_ECB"),
    ID("Cryptofuzz/Cipher/IDEA_OFB"),
    ID("Cryptofuzz/Cipher/RC2_40_CBC"),
    ID("Cryptofuzz/Cipher/RC2_64_CBC"),
    ID("Cryptofuzz/Cipher/RC2_CBC"),
    ID("Cryptofuzz/Cipher/RC2_CFB"),
    ID("Cryptofuzz/Cipher/RC2_ECB"),
    ID("Cryptofuzz/Cipher/RC2_OFB"),
    ID("Cryptofuzz/Cipher/RC4"),
    ID("Cryptofuzz/Cipher/RC4_40"),
    ID("Cryptofuzz/Cipher/RC4_HMAC_MD5"),
    ID("Cryptofuzz/Cipher/RC5_32_12_16_CBC"),
    ID("Cryptofuzz/Cipher/RC5_32_12_16_CFB"),
    ID("Cryptofuzz/Cipher/RC5_32_12_16_ECB"),
    ID("Cryptofuzz/Cipher/RC5_32_12_16_OFB"),
    ID("Cryptofuzz/Cipher/SEED_CBC"),
    ID("Cryptofuzz/Cipher/SEED_CFB"),
    ID("Cryptofuzz/Cipher/SEED_ECB"),
    ID("Cryptofuzz/Cipher/SEED_OFB"),
    ID("Cryptofuzz/Cipher/SM4_CBC"),
    ID("Cryptofuzz/Cipher/SM4_CFB"),
    ID("Cryptofuzz/Cipher/SM4_CTR"),
    ID("Cryptofuzz/Cipher/SM4_ECB"),
    ID("Cryptofuzz/Cipher/SM4_OFB"),
};
static void write(const std::string corpusDirectory, const std::vector<uint8_t>& data) {
    counter++;
    const std::string filename = corpusDirectory + "/" + std::to_string(counter);

    FILE* fp = fopen(filename.c_str(), "wb");
    fwrite(data.data(), data.size(), 1, fp);
    fclose(fp);
}

static void emit(std::vector<uint8_t>& to, const std::vector<uint8_t>& from) {
    const uint32_t fromSize = from.size();
    to.insert(to.end(), (const uint8_t*)&fromSize, ((const uint8_t*)&fromSize) + sizeof(fromSize));
    to.insert(to.end(), from.data(), from.data() + from.size());
}

static void emit(std::vector<uint8_t>& to, const uint64_t from) {
    std::vector<uint8_t> fromV(sizeof(from), 0);
    memcpy(fromV.data(), &from, sizeof(from));

    emit(to, fromV);
}

static void generate_Digest_inner(const std::string corpusDirectory, const size_t cleartextSize, const uint64_t digestType, const uint64_t modifierSize, const uint64_t moduleID) {
    std::vector<uint8_t> toWrite;

    {
        static const uint64_t id = ID("Cryptofuzz/Operation/Digest");
        emit(toWrite, id);
    }

    {
        {
            std::vector<uint8_t> payload;

            {
                std::vector<uint8_t> cleartext(cleartextSize, 0);
                emit(payload, cleartext);
                emit(payload, digestType);
            }

            emit(toWrite, payload);
        }


        {
            std::vector<uint8_t> modifier(modifierSize, 0);
            emit(toWrite, modifier);
        }

        {
            emit(toWrite, moduleID);
        }
    }

    write(corpusDirectory, toWrite);
}

static void generate_Digest(const std::string corpusDirectory, const uint64_t moduleID) {
    for (const auto& digestType : digestTypes) {
        for (const auto& cleartextSize : sizes) {
            for (const auto& modifierSize : sizes) {
                generate_Digest_inner(corpusDirectory, cleartextSize, digestType, modifierSize, moduleID);
            }
        }
    }
}

static void generate_SymmetricEncrypt_inner(const std::string corpusDirectory, const size_t cleartextSize, const size_t ivSize, const size_t keySize, const uint64_t cipherType, const uint64_t modifierSize, const uint64_t moduleID) {
    std::vector<uint8_t> toWrite;

    {
        static const uint64_t id = ID("Cryptofuzz/Operation/SymmetricEncrypt");
        emit(toWrite, id);
    }

    {
        {
            std::vector<uint8_t> payload;

            {
                std::vector<uint8_t> cleartext(cleartextSize, 0);
                emit(payload, cleartext);

                std::vector<uint8_t> iv(ivSize, 0);
                emit(payload, iv);

                std::vector<uint8_t> key(keySize, 0);
                emit(payload, key);

                emit(payload, cipherType);

                static const uint64_t ciphertextSize = 102400;
                emit(payload, ciphertextSize);
            }

            emit(toWrite, payload);
        }


        {
            std::vector<uint8_t> modifier(modifierSize, 0);
            emit(toWrite, modifier);
        }

        {
            emit(toWrite, moduleID);
        }
    }

    write(corpusDirectory, toWrite);
}

static void generate_HMAC_inner(const std::string corpusDirectory, const size_t cleartextSize, const uint64_t digestType, const size_t ivSize, const size_t keySize, const uint64_t cipherType, const uint64_t modifierSize, const uint64_t moduleID) {
    std::vector<uint8_t> toWrite;

    {
        static const uint64_t id = ID("Cryptofuzz/Operation/HMAC");
        emit(toWrite, id);
    }

    {
        {
            std::vector<uint8_t> payload;

            {
                std::vector<uint8_t> cleartext(cleartextSize, 0);
                emit(payload, cleartext);

                emit(payload, digestType);

                std::vector<uint8_t> iv(ivSize, 0);
                emit(payload, iv);

                std::vector<uint8_t> key(keySize, 0);
                emit(payload, key);

                emit(payload, cipherType);
            }

            emit(toWrite, payload);
        }


        {
            std::vector<uint8_t> modifier(modifierSize, 0);
            emit(toWrite, modifier);
        }

        {
            emit(toWrite, moduleID);
        }
    }

    write(corpusDirectory, toWrite);
}


static void generate_HMAC(const std::string corpusDirectory, const uint64_t moduleID) {
    for (const auto& cipherType : cipherTypes) {
        for (const auto& cleartextSize : sizes) {
            for (const auto& ivSize : sizes) {
                for (const auto& keySize : sizes) {
                    for (const auto& digestType : digestTypes) {
                        for (const auto& modifierSize : sizes) {
                            generate_HMAC_inner(corpusDirectory, cleartextSize, digestType, ivSize, keySize, cipherType, modifierSize, moduleID);
                        }
                    }
                }
            }
        }
    }
}

static void generate_CMAC_inner(const std::string corpusDirectory, const size_t cleartextSize, const size_t ivSize, const size_t keySize, const uint64_t cipherType, const uint64_t modifierSize, const uint64_t moduleID) {
    std::vector<uint8_t> toWrite;

    {
        static const uint64_t id = ID("Cryptofuzz/Operation/CMAC");
        emit(toWrite, id);
    }

    {
        {
            std::vector<uint8_t> payload;

            {
                std::vector<uint8_t> cleartext(cleartextSize, 0);
                emit(payload, cleartext);

                std::vector<uint8_t> iv(ivSize, 0);
                emit(payload, iv);

                std::vector<uint8_t> key(keySize, 0);
                emit(payload, key);

                emit(payload, cipherType);
            }

            emit(toWrite, payload);
        }


        {
            std::vector<uint8_t> modifier(modifierSize, 0);
            emit(toWrite, modifier);
        }

        {
            emit(toWrite, moduleID);
        }
    }

    write(corpusDirectory, toWrite);
}

static void generate_CMAC(const std::string corpusDirectory, const uint64_t moduleID) {
    for (const auto& cipherType : cipherTypes) {
        for (const auto& cleartextSize : sizes) {
            for (const auto& ivSize : sizes) {
                for (const auto& keySize : sizes) {
                    for (const auto& modifierSize : sizes) {
                        generate_CMAC_inner(corpusDirectory, cleartextSize, ivSize, keySize, cipherType, modifierSize, moduleID);
                    }
                }
            }
        }
    }
}

static void generate_SymmetricEncrypt(const std::string corpusDirectory, const uint64_t moduleID) {
    for (const auto& cipherType : cipherTypes) {
        for (const auto& cleartextSize : sizes) {
            for (const auto& ivSize : sizes) {
                for (const auto& keySize : sizes) {
                    for (const auto& modifierSize : sizes) {
                        generate_SymmetricEncrypt_inner(corpusDirectory, cleartextSize, ivSize, keySize, cipherType, modifierSize, moduleID);
                    }
                }
            }
        }
    }
}

int main(int argc, char** argv)
{
    if ( argc != 2 ) {
        printf("Usage: %s <corpus directory>\n", argv[0]);
        return 1;
    }

    std::string corpusDirectory = argv[1];

    static const std::vector<uint64_t> moduleIDs = {
        ID("Cryptofuzz/Module/OpenSSL"),
    };

    // TEST -- generate_SymmetricEncrypt_inner(corpusDirectory, 2, 0, 4, ID("Cryptofuzz/Cipher/RC4_40"), 0, ID("Cryptofuzz/Module/OpenSSL"));

    for (const auto& moduleID : moduleIDs) {
        generate_Digest(corpusDirectory, moduleID);
        generate_HMAC(corpusDirectory, moduleID);
        generate_CMAC(corpusDirectory, moduleID);
        generate_SymmetricEncrypt(corpusDirectory, moduleID);
    }

    return 0;
}
