#include <cryptofuzz/util.h>
#include <cryptofuzz/util_hexdump.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <boost/algorithm/string/join.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include "third_party/cpu_features/include/cpuinfo_x86.h"

namespace cryptofuzz {
namespace util {

Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, const uint8_t* in, const size_t inSize) {
    if ( repository::IsXTS( cipherType.Get() ) ) {
        /* XTS does not support chunked updating.
         * See: https://github.com/openssl/openssl/issues/8699
         */
        return { { in, inSize} };
    } else if ( repository::IsCCM( cipherType.Get() ) ) {
        /* CCM does not support chunked updating.
         * See: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_CCM_mode
         */
        return { { in, inSize} };
    } else {
        return util::ToParts(ds, in, inSize);
    }
}

Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize) {
    return CipherInputTransform(
        ds,
        cipherType,
        util::ToInPlace(ds, out, outSize, in, inSize),
        inSize);
}

const uint8_t* ToInPlace(fuzzing::datasource::Datasource& ds, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize) {
    bool inPlace = false;

    if ( outSize >= inSize ) {
        try {
            inPlace = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }
    }

    if ( inPlace == true && inSize > 0 ) {
        memcpy(out, in, inSize);
    }

    return inPlace ? out : in;
}

Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer) {
    return ToParts(ds, buffer.GetPtr(), buffer.GetSize());
}

Multipart ToParts(fuzzing::datasource::Datasource& ds, const uint8_t* data, const size_t size) {
    Multipart ret;

    /* Position in buffer */
    size_t curPos = 0;

    try {
        while ( ds.Get<bool>() == true ) {
            const size_t left = size - curPos;

            /* Determine part length */
            const size_t len = left == 0 ? 0 : ds.Get<uint64_t>() % left;

            /* Append part */
            if ( len == 0 ) {
                /* Intentionally invalid pointer to detect dereference
                 * of buffer of size 0 */
                ret.push_back( {GetNullPtr(), 0} );
            } else {
                ret.push_back( {data + curPos, len} );
            }

            /* Advance */
            curPos += len;
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    /* Append the remainder of the buffer */
    if ( size - curPos == 0 ) {
        /* Intentionally invalid pointer to detect dereference
         * of buffer of size 0 */
        ret.push_back( {GetNullPtr(), 0} );
    } else {
        ret.push_back( {data + curPos, size - curPos} );
    }

    return ret;
}

std::vector<uint8_t> Pkcs7Pad(std::vector<uint8_t> in, const size_t blocksize) {
    size_t numPadBytes = blocksize - (in.size() % blocksize);

    const uint8_t padByte = static_cast<uint8_t>(numPadBytes);
    for (size_t i = 0; i < numPadBytes; i++) {
        in.push_back(padByte);
    }

    return in;
}

std::optional<std::vector<uint8_t>> Pkcs7Unpad(std::vector<uint8_t> in, const size_t blocksize) {
    if ( in.size() == 0 || (in.size() % blocksize) != 0 ) {
        return std::nullopt;
    }

    const auto numPadBytes = static_cast<size_t>(in.back());

    if ( numPadBytes > in.size() ) {
        return std::nullopt;
    }

    return std::vector<uint8_t>(in.data(), in.data() + in.size() - numPadBytes);
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

std::string ToString(const component::Ciphertext& ciphertext) {
    std::string ret;

    ret += util::HexDump(ciphertext.ciphertext.GetPtr(), ciphertext.ciphertext.GetSize(), "ciphertext");

    ret += "\n";

    if ( ciphertext.tag != std::nullopt ) {
        ret += util::HexDump(ciphertext.tag->GetPtr(), ciphertext.tag->GetSize(), "tag");
    } else {
        ret += "(tag is nullopt)";
    }

    return ret;
}

std::string ToString(const component::ECC_PublicKey& val) {
    std::string ret;

    ret += "X: ";
    ret += val.first.ToString();
    ret += "\n";

    ret += "Y: ";
    ret += val.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::ECC_KeyPair& val) {
    std::string ret;

    ret += "Priv: ";
    ret += val.priv.ToString();
    ret += "\n";

    ret += "X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::Bignum& val) {
    return val.ToString();
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

bool HaveSSE42(void) {
    const cpu_features::X86Info info = cpu_features::GetX86Info();
    const auto features = info.features;
    return features.sse4_2;
}

void abort(const std::vector<std::string> components) {
    const std::string joined = boost::algorithm::join(components, "-");
    printf("Assertion failure: %s\n", joined.c_str());
    fflush(stdout);
    ::abort();
}

static int HexCharToDec(const char c) {
    if ( c >= '0' && c <= '9' ) {
        return c - '0';
    } else if ( c >= 'a' && c <= 'f' ) {
        return c - 'a' + 10;
    } else if ( c >= 'A' && c <= 'F' ) {
        return c - 'A' + 10;
    } else {
        assert(0);
    }
}

std::string HexToDec(std::string s) {
    std::string ret;
    bool negative = false;

    if ( s.empty() ) {
        return ret;
    }

    if ( s.size() >= 2 && s[0] == '0' && s[1] == 'x' ) {
        s = s.substr(2);
    }

    if ( s.size() >= 1 && s[0] == '-' ) {
        s = s.substr(1);
        negative = true;
    }

    boost::multiprecision::cpp_int total;

    for (long i = s.size() - 1; i >= 0; i--) {
        total += boost::multiprecision::cpp_int(HexCharToDec(s[i])) << ((s.size()-i-1)*4);
    }

    std::stringstream ss;
    if ( negative ) ss << "-";
    ss << total;

    if ( ss.str().empty() ) {
        return "0";
    } else {
        return ss.str();
    }
}

std::string DecToHex(std::string s) {
    s.erase(0, s.find_first_not_of('0'));
    boost::multiprecision::cpp_int i(s);
    bool negative;
    if ( i < 0 ) {
        negative = true;
        i -= (i*2);
    } else {
        negative = false;
    }
    std::stringstream ss;
    if ( negative == true ) {
        ss << "-";
    }
    ss << std::hex << i;
    return ss.str();
}

} /* namespace util */
} /* namespace cryptofuzz */
