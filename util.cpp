#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>
#include <cstdlib>

namespace cryptofuzz {
namespace util {

size_t GetDigestSize(const component::DigestType digestType) {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, size_t> LUT = {
        { ID("Cryptofuzz/Digest/SHA1"), 20},
        { ID("Cryptofuzz/Digest/SHA224"), 28},
        { ID("Cryptofuzz/Digest/SHA256"), 32},
        { ID("Cryptofuzz/Digest/SHA384"), 48},
        { ID("Cryptofuzz/Digest/SHA512"), 64},
        { ID("Cryptofuzz/Digest/MD4"), 16},
        { ID("Cryptofuzz/Digest/MD5"), 16},
        { ID("Cryptofuzz/Digest/MDC2"), 16},
        { ID("Cryptofuzz/Digest/RIPEMD160"), 20},
        { ID("Cryptofuzz/Digest/WHIRLPOOL"), 64},
        { ID("Cryptofuzz/Digest/SM3"), 32},
        { ID("Cryptofuzz/Digest/BLAKE2B512"), 64},
        { ID("Cryptofuzz/Digest/BLAKE2S256"), 32},
        { ID("Cryptofuzz/Digest/SHAKE128"), 16},
        { ID("Cryptofuzz/Digest/SHAKE256"), 32}
        /* TODO add
         * "Cryptofuzz/Digest/SHA3-224"
         * "Cryptofuzz/Digest/SHA3-256"
         * "Cryptofuzz/Digest/SHA3-384"
         * "Cryptofuzz/Digest/SHA3-512"
         * "Cryptofuzz/Digest/SHA512-224"
         * "Cryptofuzz/Digest/SHA512-256"
         */
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        /* XXX */
        return 1;
    }

    return LUT.at(digestType.Get());
}

std::string DigestIDToString(const component::DigestType digestType) {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, std::string> LUT = {
        { ID("Cryptofuzz/Digest/SHA1"), "SHA1" },
        { ID("Cryptofuzz/Digest/SHA224"), "SHA224" },
        { ID("Cryptofuzz/Digest/SHA256"), "SHA256" },
        { ID("Cryptofuzz/Digest/SHA384"), "SHA384" },
        { ID("Cryptofuzz/Digest/SHA512"), "SHA512" },
        { ID("Cryptofuzz/Digest/MD4"), "MD4" },
        { ID("Cryptofuzz/Digest/MD5"), "MD5" },
        { ID("Cryptofuzz/Digest/MDC2"), "MDC2" },
        { ID("Cryptofuzz/Digest/RIPEMD160"), "RIPEMD160" },
        { ID("Cryptofuzz/Digest/WHIRLPOOL"), "WHIRLPOOL" },
        { ID("Cryptofuzz/Digest/SM3"), "SM3" },
        { ID("Cryptofuzz/Digest/BLAKE2B512"), "BLAKE2B512" },
        { ID("Cryptofuzz/Digest/BLAKE2S256"), "BLAKE2S256" },
        { ID("Cryptofuzz/Digest/SHAKE128"), "SHAKE128" },
        { ID("Cryptofuzz/Digest/SHAKE256"), "SHAKE256" },
        { ID("Cryptofuzz/Digest/SHA3-224"), "SHA3-224" },
        { ID("Cryptofuzz/Digest/SHA3-256"), "SHA3-256" },
        { ID("Cryptofuzz/Digest/SHA3-384"), "SHA3-384" },
        { ID("Cryptofuzz/Digest/SHA3-512"), "SHA3-512" },
        { ID("Cryptofuzz/Digest/SHA512-224"), "SHA512-224" },
        { ID("Cryptofuzz/Digest/SHA512-256"), "SHA512-256" },
        { ID("Cryptofuzz/Digest/GROESTL-256"), "GROESTL-256" },
        { ID("Cryptofuzz/Digest/JH-224"), "JH-224" },
        { ID("Cryptofuzz/Digest/JH-256"), "JH-256" },
        { ID("Cryptofuzz/Digest/JH-384"), "JH-384" },
        { ID("Cryptofuzz/Digest/JH-512"), "JH-512" },
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        return "(unknown)";
    }

    return LUT.at(digestType.Get());
}
std::string SymmetricCipherIDToString(const component::SymmetricCipherType cipherType) {
    using fuzzing::datasource::ID;

    switch ( cipherType.Get() ) {
        case ID("Cryptofuzz/Cipher/DES_CFB"):
            return "DES_CFB";
        case ID("Cryptofuzz/Cipher/DES_CFB1"):
            return "DES_CFB1";
        case ID("Cryptofuzz/Cipher/DES_CFB8"):
            return "DES_CFB8";
        case ID("Cryptofuzz/Cipher/DES_EDE_CFB"):
            return "DES_EDE_CFB";
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB"):
            return "DES_EDE3_CFB";
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB1"):
            return "DES_EDE3_CFB1";
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB8"):
            return "DES_EDE3_CFB8";
        case ID("Cryptofuzz/Cipher/DES_OFB"):
            return "DES_OFB";
        case ID("Cryptofuzz/Cipher/DES_EDE_OFB"):
            return "DES_EDE_OFB";
        case ID("Cryptofuzz/Cipher/DES_EDE3_OFB"):
            return "DES_EDE3_OFB";
        case ID("Cryptofuzz/Cipher/DESX_CBC"):
            return "DESX_CBC";
        case ID("Cryptofuzz/Cipher/DES_CBC"):
            return "DES_CBC";
        case ID("Cryptofuzz/Cipher/DES_EDE_CBC"):
            return "DES_EDE_CBC";
        case ID("Cryptofuzz/Cipher/DES_EDE3_CBC"):
            return "DES_EDE3_CBC";
        case ID("Cryptofuzz/Cipher/DES_ECB"):
            return "DES_ECB";
        case ID("Cryptofuzz/Cipher/DES_EDE"):
            return "DES_EDE";
        case ID("Cryptofuzz/Cipher/DES_EDE3"):
            return "DES_EDE3";
        case ID("Cryptofuzz/Cipher/DES_EDE3_WRAP"):
            return "DES_EDE3_WRAP";
        case ID("Cryptofuzz/Cipher/RC4"):
            return "RC4";
        case ID("Cryptofuzz/Cipher/RC4_40"):
            return "RC4_40";
        case ID("Cryptofuzz/Cipher/RC4_HMAC_MD5"):
            return "RC4_HMAC_MD5";
        case ID("Cryptofuzz/Cipher/IDEA_ECB"):
            return "IDEA_ECB";
        case ID("Cryptofuzz/Cipher/IDEA_CFB"):
            return "IDEA_CFB";
        case ID("Cryptofuzz/Cipher/IDEA_OFB"):
            return "IDEA_OFB";
        case ID("Cryptofuzz/Cipher/IDEA_CBC"):
            return "IDEA_CBC";
        case ID("Cryptofuzz/Cipher/SEED_ECB"):
            return "SEED_ECB";
        case ID("Cryptofuzz/Cipher/SEED_CFB"):
            return "SEED_CFB";
        case ID("Cryptofuzz/Cipher/SEED_OFB"):
            return "SEED_OFB";
        case ID("Cryptofuzz/Cipher/SEED_CBC"):
            return "SEED_CBC";
        case ID("Cryptofuzz/Cipher/SM4_ECB"):
            return "SM4_ECB";
        case ID("Cryptofuzz/Cipher/SM4_CBC"):
            return "SM4_CBC";
        case ID("Cryptofuzz/Cipher/SM4_CFB"):
            return "SM4_CFB";
        case ID("Cryptofuzz/Cipher/SM4_OFB"):
            return "SM4_OFB";
        case ID("Cryptofuzz/Cipher/SM4_CTR"):
            return "SM4_CTR";
        case ID("Cryptofuzz/Cipher/RC2_ECB"):
            return "RC2_ECB";
        case ID("Cryptofuzz/Cipher/RC2_CFB"):
            return "RC2_CFB";
        case ID("Cryptofuzz/Cipher/RC2_OFB"):
            return "RC2_OFB";
        case ID("Cryptofuzz/Cipher/RC2_CBC"):
            return "RC2_CBC";
        case ID("Cryptofuzz/Cipher/RC2_40_CBC"):
            return "RC2_40_CBC";
        case ID("Cryptofuzz/Cipher/RC2_64_CBC"):
            return "RC2_64_CBC";
        case ID("Cryptofuzz/Cipher/BF_ECB"):
            return "BF_ECB";
        case ID("Cryptofuzz/Cipher/BF_CFB"):
            return "BF_CFB";
        case ID("Cryptofuzz/Cipher/BF_OFB"):
            return "BF_OFB";
        case ID("Cryptofuzz/Cipher/BF_CBC"):
            return "BF_CBC";
        case ID("Cryptofuzz/Cipher/CAST5_ECB"):
            return "CAST5_ECB";
        case ID("Cryptofuzz/Cipher/CAST5_CFB"):
            return "CAST5_CFB";
        case ID("Cryptofuzz/Cipher/CAST5_OFB"):
            return "CAST5_OFB";
        case ID("Cryptofuzz/Cipher/CAST5_CBC"):
            return "CAST5_CBC";
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_ECB"):
            return "RC5_32_12_16_ECB";
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_CFB"):
            return "RC5_32_12_16_CFB";
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_OFB"):
            return "RC5_32_12_16_OFB";
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_CBC"):
            return "RC5_32_12_16_CBC";
        case ID("Cryptofuzz/Cipher/AES_128_ECB"):
            return "AES_128_ECB";
        case ID("Cryptofuzz/Cipher/AES_128_CBC"):
            return "AES_128_CBC";
        case ID("Cryptofuzz/Cipher/AES_128_CFB"):
            return "AES_128_CFB";
        case ID("Cryptofuzz/Cipher/AES_128_CFB1"):
            return "AES_128_CFB1";
        case ID("Cryptofuzz/Cipher/AES_128_CFB8"):
            return "AES_128_CFB8";
        case ID("Cryptofuzz/Cipher/AES_128_OFB"):
            return "AES_128_OFB";
        case ID("Cryptofuzz/Cipher/AES_128_CTR"):
            return "AES_128_CTR";
        case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            return "AES_128_GCM";
        case ID("Cryptofuzz/Cipher/AES_128_OCB"):
            return "AES_128_OCB";
        case ID("Cryptofuzz/Cipher/AES_128_XTS"):
            return "AES_128_XTS";
        case ID("Cryptofuzz/Cipher/AES_128_CCM"):
            return "AES_128_CCM";
        case ID("Cryptofuzz/Cipher/AES_128_WRAP"):
            return "AES_128_WRAP";
        case ID("Cryptofuzz/Cipher/AES_128_WRAP_PAD"):
            return "AES_128_WRAP_PAD";
        case ID("Cryptofuzz/Cipher/AES_192_ECB"):
            return "AES_192_ECB";
        case ID("Cryptofuzz/Cipher/AES_192_CBC"):
            return "AES_192_CBC";
        case ID("Cryptofuzz/Cipher/AES_192_CFB"):
            return "AES_192_CFB";
        case ID("Cryptofuzz/Cipher/AES_192_CFB1"):
            return "AES_192_CFB1";
        case ID("Cryptofuzz/Cipher/AES_192_CFB8"):
            return "AES_192_CFB8";
        case ID("Cryptofuzz/Cipher/AES_192_OFB"):
            return "AES_192_OFB";
        case ID("Cryptofuzz/Cipher/AES_192_CTR"):
            return "AES_192_CTR";
        case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            return "AES_192_GCM";
        case ID("Cryptofuzz/Cipher/AES_192_OCB"):
            return "AES_192_OCB";
        case ID("Cryptofuzz/Cipher/AES_192_CCM"):
            return "AES_192_CCM";
        case ID("Cryptofuzz/Cipher/AES_192_WRAP"):
            return "AES_192_WRAP";
        case ID("Cryptofuzz/Cipher/AES_192_WRAP_PAD"):
            return "AES_192_WRAP_PAD";
        case ID("Cryptofuzz/Cipher/AES_256_ECB"):
            return "AES_256_ECB";
        case ID("Cryptofuzz/Cipher/AES_256_CBC"):
            return "AES_256_CBC";
        case ID("Cryptofuzz/Cipher/AES_256_CFB"):
            return "AES_256_CFB";
        case ID("Cryptofuzz/Cipher/AES_256_CFB1"):
            return "AES_256_CFB1";
        case ID("Cryptofuzz/Cipher/AES_256_CFB8"):
            return "AES_256_CFB8";
        case ID("Cryptofuzz/Cipher/AES_256_OFB"):
            return "AES_256_OFB";
        case ID("Cryptofuzz/Cipher/AES_256_CTR"):
            return "AES_256_CTR";
        case ID("Cryptofuzz/Cipher/AES_256_GCM"):
            return "AES_256_GCM";
        case ID("Cryptofuzz/Cipher/AES_256_OCB"):
            return "AES_256_OCB";
        case ID("Cryptofuzz/Cipher/AES_256_XTS"):
            return "AES_256_XTS";
        case ID("Cryptofuzz/Cipher/AES_256_CCM"):
            return "AES_256_CCM";
        case ID("Cryptofuzz/Cipher/AES_256_WRAP"):
            return "AES_256_WRAP";
        case ID("Cryptofuzz/Cipher/AES_256_WRAP_PAD"):
            return "AES_256_WRAP_PAD";
        case ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA1"):
            return "AES_128_CBC_HMAC_SHA1";
        case ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA1"):
            return "AES_256_CBC_HMAC_SHA1";
        case ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA256"):
            return "AES_128_CBC_HMAC_SHA256";
        case ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA256"):
            return "AES_256_CBC_HMAC_SHA256";
        case ID("Cryptofuzz/Cipher/ARIA_128_ECB"):
            return "ARIA_128_ECB";
        case ID("Cryptofuzz/Cipher/ARIA_128_CBC"):
            return "ARIA_128_CBC";
        case ID("Cryptofuzz/Cipher/ARIA_128_CFB"):
            return "ARIA_128_CFB";
        case ID("Cryptofuzz/Cipher/ARIA_128_CFB1"):
            return "ARIA_128_CFB1";
        case ID("Cryptofuzz/Cipher/ARIA_128_CFB8"):
            return "ARIA_128_CFB8";
        case ID("Cryptofuzz/Cipher/ARIA_128_CTR"):
            return "ARIA_128_CTR";
        case ID("Cryptofuzz/Cipher/ARIA_128_OFB"):
            return "ARIA_128_OFB";
        case ID("Cryptofuzz/Cipher/ARIA_128_GCM"):
            return "ARIA_128_GCM";
        case ID("Cryptofuzz/Cipher/ARIA_128_CCM"):
            return "ARIA_128_CCM";
        case ID("Cryptofuzz/Cipher/ARIA_192_ECB"):
            return "ARIA_192_ECB";
        case ID("Cryptofuzz/Cipher/ARIA_192_CBC"):
            return "ARIA_192_CBC";
        case ID("Cryptofuzz/Cipher/ARIA_192_CFB"):
            return "ARIA_192_CFB";
        case ID("Cryptofuzz/Cipher/ARIA_192_CFB1"):
            return "ARIA_192_CFB1";
        case ID("Cryptofuzz/Cipher/ARIA_192_CFB8"):
            return "ARIA_192_CFB8";
        case ID("Cryptofuzz/Cipher/ARIA_192_CTR"):
            return "ARIA_192_CTR";
        case ID("Cryptofuzz/Cipher/ARIA_192_OFB"):
            return "ARIA_192_OFB";
        case ID("Cryptofuzz/Cipher/ARIA_192_GCM"):
            return "ARIA_192_GCM";
        case ID("Cryptofuzz/Cipher/ARIA_192_CCM"):
            return "ARIA_192_CCM";
        case ID("Cryptofuzz/Cipher/ARIA_256_ECB"):
            return "ARIA_256_ECB";
        case ID("Cryptofuzz/Cipher/ARIA_256_CBC"):
            return "ARIA_256_CBC";
        case ID("Cryptofuzz/Cipher/ARIA_256_CFB"):
            return "ARIA_256_CFB";
        case ID("Cryptofuzz/Cipher/ARIA_256_CFB1"):
            return "ARIA_256_CFB1";
        case ID("Cryptofuzz/Cipher/ARIA_256_CFB8"):
            return "ARIA_256_CFB8";
        case ID("Cryptofuzz/Cipher/ARIA_256_CTR"):
            return "ARIA_256_CTR";
        case ID("Cryptofuzz/Cipher/ARIA_256_OFB"):
            return "ARIA_256_OFB";
        case ID("Cryptofuzz/Cipher/ARIA_256_GCM"):
            return "ARIA_256_GCM";
        case ID("Cryptofuzz/Cipher/ARIA_256_CCM"):
            return "ARIA_256_CCM";
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_ECB"):
            return "CAMELLIA_128_ECB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"):
            return "CAMELLIA_128_CBC";
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB"):
            return "CAMELLIA_128_CFB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB1"):
            return "CAMELLIA_128_CFB1";
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB8"):
            return "CAMELLIA_128_CFB8";
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_OFB"):
            return "CAMELLIA_128_OFB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_ECB"):
            return "CAMELLIA_192_ECB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"):
            return "CAMELLIA_192_CBC";
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB"):
            return "CAMELLIA_192_CFB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB1"):
            return "CAMELLIA_192_CFB1";
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB8"):
            return "CAMELLIA_192_CFB8";
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_OFB"):
            return "CAMELLIA_192_OFB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_ECB"):
            return "CAMELLIA_256_ECB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"):
            return "CAMELLIA_256_CBC";
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB"):
            return "CAMELLIA_256_CFB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB1"):
            return "CAMELLIA_256_CFB1";
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB8"):
            return "CAMELLIA_256_CFB8";
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_OFB"):
            return "CAMELLIA_256_OFB";
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CTR"):
            return "CAMELLIA_128_CTR";
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CTR"):
            return "CAMELLIA_192_CTR";
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CTR"):
            return "CAMELLIA_256_CTR";
        case ID("Cryptofuzz/Cipher/CHACHA20"):
            return "CHACHA20";
        case ID("Cryptofuzz/Cipher/CHACHA20_POLY1305"):
            return "CHACHA20_POLY1305";
        default:
            return "(unknown cipher)";
    }
}

Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer) {
    Multipart ret;

    /* Position in buffer */
    size_t curPos = 0;

    try {
        while ( ds.Get<bool>() == true ) {
            const size_t left = buffer.GetSize() - curPos;

            /* Determine part length */
            const size_t len = left == 0 ? 0 : ds.Get<uint64_t>() % left;

            /* Append part */
            if ( len == 0 ) {
                /* Intentionally invalid pointer to detect dereference
                 * of buffer of size 0 */
                ret.push_back( {GetNullPtr(), 0} );
            } else {
                ret.push_back( {buffer.GetPtr() + curPos, len} );
            }

            /* Advance */
            curPos += len;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    /* Append the remainder of the buffer */
    if ( buffer.GetSize() - curPos == 0 ) {
        /* Intentionally invalid pointer to detect dereference
         * of buffer of size 0 */
        ret.push_back( {GetNullPtr(), 0} );
    } else {
        ret.push_back( {buffer.GetPtr() + curPos, buffer.GetSize() - curPos} );
    }

    return ret;
}

std::string HexDump(const void *_data, const size_t len, const std::string description) {
    unsigned char *data = (unsigned char*)_data;

    std::stringstream ss;

    if ( description.size() > 0 ) {
        ss << description << " = ";
    }

    ss << "{";
    for (size_t i = 0; i < len; i++) {
        if ((i % 16) == 0 && i != 0) {
            ss << std::endl;
        }
        if ( (i % 16) == 0 && i != 0 ) {
            size_t padding;
            if ( description.size() > 0 ) {
                padding = description.size() + 4;
            } else {
                padding = 1;
            }
            for (size_t j = 0; j < padding; j++) {
                ss << " ";
            }
        }
        ss << "0x" << std::setw(2) << std::setfill('0') << std::hex << (int)(data[i]);
        if ( i == len - 1 ) {
            ss << "} (" << std::dec << len << " bytes)";
        } else {
            ss << ", ";
        }
    }
    if ( len == 0 ) {
        ss << "}";
    }

    return ss.str();
}

std::string HexDump(std::vector<uint8_t> data, const std::string description) {
    return HexDump(data.data(), data.size(), description);
}

std::string ToString(const Buffer& buffer) {
    return HexDump(buffer.Get());
}

std::string ToString(const bool val) {
    return val ? "true" : "false";
}

class HaveBadPointer {
    private:
        bool haveBadPointer = false;
    public:
        HaveBadPointer(void) {
            const char* env = getenv("CRYPTOFUZZ_NULL_IS_BADPTR");
            if ( env == nullptr ) {
                haveBadPointer = false;
            } else {
                haveBadPointer = true;
            }
        }

        bool Get(void) const {
            return haveBadPointer;
        }
};

static HaveBadPointer haveBadPointer;

uint8_t* GetNullPtr(void) {
    return haveBadPointer.Get() == true ? (uint8_t*)0x12 : nullptr;
}

uint8_t* malloc(const size_t n) {
    return n == 0 ? GetNullPtr() : (uint8_t*)::malloc(n);
}

uint8_t* realloc(void* ptr, const size_t n) {
    if ( n == 0 ) {
        free(ptr);
        return GetNullPtr();
    } else {
        if ( ptr != GetNullPtr() ) {
            return (uint8_t*)::realloc(ptr, n);
        } else {
            return malloc(n);
        }
    }
}

void free(void* ptr) {
    if ( ptr != GetNullPtr() ) {
        ::free(ptr);
    }
}

} /* namespace util */
} /* namespace cryptofuzz */
