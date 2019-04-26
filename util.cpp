#include <cryptofuzz/util.h>
#include <cryptofuzz/util_hexdump.h>
#include <fuzzing/datasource/id.hpp>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>
#include <cstdlib>

namespace cryptofuzz {
namespace util {

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
