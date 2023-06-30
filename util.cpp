#include <cryptofuzz/util.h>
#include <cryptofuzz/util_hexdump.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/crypto.h>
#include <fuzzing/datasource/id.hpp>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <algorithm>
#include <boost/algorithm/string/join.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/algorithm/hex.hpp>
#if defined(__x86_64__) || defined(__amd64__)
  #include "third_party/cpu_features/include/cpuinfo_x86.h"
#endif
#include "mutatorpool.h"
#include "config.h"

uint32_t PRNG(void);

extern "C" {
    sigjmp_buf cryptofuzz_jmpbuf;
    unsigned char cryptofuzz_longjmp_triggered = 0;
}

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
        } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
        }
    }

    if ( inPlace == true && inSize > 0 ) {
        memcpy(out, in, inSize);
    }

    return inPlace ? out : in;
}

static std::vector<size_t> Split(fuzzing::datasource::Datasource& ds, size_t N) {
    std::vector<size_t> ret;

    try {
        while ( N ) {
            ret.push_back( ds.Get<uint64_t>() % N );
            N -= ret.back();
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
    }

    ret.push_back(N);

    return ret;
}

Multipart ToParts(fuzzing::datasource::Datasource& ds, const std::vector<uint8_t>& buffer, const size_t blocksize) {
    return ToParts(ds, buffer.data(), buffer.size(), blocksize);
}

Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer, const size_t blocksize) {
    return ToParts(ds, buffer.GetPtr(), buffer.GetSize(), blocksize);
}

Multipart ToParts(fuzzing::datasource::Datasource& ds, const uint8_t* data, const size_t size, const size_t blocksize) {
    const bool blocks = blocksize != 0;
    const auto parts = Split(ds, !blocks ? size : size / blocksize);
    Multipart ret;
    size_t curPos = 0;
    for (const auto& p : parts) {
        const size_t n = !blocks ? p : blocksize * p;
        ret.push_back({data + curPos, n});
        curPos += n;
    }
    if ( curPos < size ) {
        ret.push_back({data + curPos, size - curPos});
    }
    return ret;
}

Multipart ToEqualParts(const Buffer& buffer, const size_t partSize) {
    return ToEqualParts(buffer.GetPtr(), buffer.GetSize(), partSize);
}

Multipart ToEqualParts(const uint8_t* data, const size_t size, const size_t partSize) {
    Multipart ret;

    const size_t numParts = size / partSize;

    for (size_t i = 0; i < numParts; i++) {
        ret.push_back( {data + (i*partSize), partSize} );
    }

    const size_t remainder = size % partSize;

    ret.push_back( {data + size - remainder, remainder} );

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

std::string ToString(const component::ECCSI_Signature& val) {
    std::string ret;

    ret += "X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    ret += "PVT X: ";
    ret += val.pvt.first.ToString();
    ret += "\n";

    ret += "PVT Y: ";
    ret += val.pvt.second.ToString();
    ret += "\n";

    ret += "R: ";
    ret += val.signature.first.ToString();
    ret += "\n";

    ret += "S: ";
    ret += val.signature.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::ECDSA_Signature& val) {
    std::string ret;

    ret += "X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    ret += "R: ";
    ret += val.signature.first.ToString();
    ret += "\n";

    ret += "S: ";
    ret += val.signature.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::BLS_Signature& val) {
    std::string ret;

    ret += "Pub X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Pub Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    ret += "Sig v: ";
    ret += val.signature.first.first.ToString();
    ret += "\n";

    ret += "Sig w: ";
    ret += val.signature.first.second.ToString();
    ret += "\n";

    ret += "Sig x: ";
    ret += val.signature.second.first.ToString();
    ret += "\n";

    ret += "Sig y: ";
    ret += val.signature.second.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::BLS_BatchSignature& val) {
    std::string ret;

    for (const auto& cur : val.msgpub) {
        ret += "G1 X: ";
        ret += cur.first.first.ToString();
        ret += "\n";
        ret += "G1 Y: ";
        ret += cur.first.second.ToString();
        ret += "\n";

        ret += "\n";

        ret += "G2 V: ";
        ret += cur.second.first.first.ToString();
        ret += "\n";
        ret += "G2 W: ";
        ret += cur.second.first.second.ToString();
        ret += "\n";
        ret += "G2 X: ";
        ret += cur.second.second.first.ToString();
        ret += "\n";
        ret += "G2 Y: ";
        ret += cur.second.second.second.ToString();
        ret += "\n";

        ret += "----------";
        ret += "\n";
    }
    return ret;
}

std::string ToString(const component::BLS_KeyPair& val) {
    std::string ret;

    ret += "Priv : ";
    ret += val.priv.ToString();
    ret += "\n";

    ret += "Pub X: ";
    ret += val.pub.first.ToString();
    ret += "\n";

    ret += "Pub Y: ";
    ret += val.pub.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::Bignum& val) {
    return val.ToString();
}

std::string ToString(const component::G2& val) {
    std::string ret;

    ret += "X1: ";
    ret += val.first.first.ToString();
    ret += "\n";

    ret += "Y1: ";
    ret += val.first.second.ToString();
    ret += "\n";

    ret += "X2: ";
    ret += val.second.first.ToString();
    ret += "\n";

    ret += "Y2: ";
    ret += val.second.second.ToString();
    ret += "\n";

    return ret;
}

std::string ToString(const component::Fp12& val) {
    std::string ret;

    ret += "bn1: " + val.bn1.ToString() + "\n";
    ret += "bn2: " + val.bn2.ToString() + "\n";
    ret += "bn3: " + val.bn3.ToString() + "\n";
    ret += "bn4: " + val.bn4.ToString() + "\n";
    ret += "bn5: " + val.bn5.ToString() + "\n";
    ret += "bn6: " + val.bn6.ToString() + "\n";
    ret += "bn7: " + val.bn7.ToString() + "\n";
    ret += "bn8: " + val.bn8.ToString() + "\n";
    ret += "bn9: " + val.bn9.ToString() + "\n";
    ret += "bn10: " + val.bn10.ToString() + "\n";
    ret += "bn11: " + val.bn11.ToString() + "\n";
    ret += "bn12: " + val.bn12.ToString() + "\n";

    return ret;
}

std::string ToString(const component::DSA_Parameters& val) {
    std::string ret;

    ret += "P: " + val.p.ToString() + "\n";
    ret += "Q: " + val.q.ToString() + "\n";
    ret += "G: " + val.g.ToString() + "\n";

    return ret;
}

std::string ToString(const component::DSA_Signature& val) {
    std::string ret;

    ret += "R: " + val.signature.first.ToString() + "\n";
    ret += "S: " + val.signature.second.ToString() + "\n";
    ret += "Pub: " + val.pub.ToString() + "\n";

    return ret;
}

nlohmann::json ToJSON(const Buffer& buffer) {
    return buffer.ToJSON();
}

nlohmann::json ToJSON(const bool val) {
    return val;
}

nlohmann::json ToJSON(const component::Ciphertext& ciphertext) {
    nlohmann::json ret;

    ret["ciphertext"] = ciphertext.ciphertext.ToJSON();

    if ( ciphertext.tag != std::nullopt ) {
        ret["tag"] = ciphertext.tag->ToJSON();
    }

    return ret;
}

nlohmann::json ToJSON(const component::ECC_PublicKey& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::ECC_KeyPair& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::ECCSI_Signature& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::ECDSA_Signature& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::Bignum& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::G2& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::BLS_Signature& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::BLS_BatchSignature& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::BLS_KeyPair& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::Fp12& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::DSA_Parameters& val) {
    return val.ToJSON();
}

nlohmann::json ToJSON(const component::DSA_Signature& val) {
    return val.ToJSON();
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

fuzzing::datasource::Datasource* global_ds = nullptr;

void SetGlobalDs(fuzzing::datasource::Datasource* ds) {
    CF_ASSERT(global_ds == nullptr, "global_ds was already set");

    global_ds = ds;
}

void UnsetGlobalDs(void) {
    CF_ASSERT(global_ds != nullptr, "Trying to unset empty global_ds");

    global_ds = nullptr;
}

uint8_t* GetNullPtr(fuzzing::datasource::Datasource* ds) {
    if ( global_ds != nullptr ) {
        ds = global_ds;
    }

    if ( ds != nullptr ) {
        try {
            return ds->Get<uint8_t*>();
        } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
            return (uint8_t*)0x12;
        }
    }
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
#if defined(__x86_64__) || defined(__amd64__)
     const cpu_features::X86Info info = cpu_features::GetX86Info();
     const auto features = info.features;
     return features.sse4_2;
#else
    return false;
#endif
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

    if ( s.size() >= 1 && s[0] == '-' ) {
        s = s.substr(1);
        negative = true;
    }

    if ( s.size() >= 2 && s[0] == '0' && s[1] == 'x' ) {
        s = s.substr(2);
    }

    if ( negative == false && s.size() >= 1 && s[0] == '-' ) {
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

std::string DecToHex(std::string s, const std::optional<size_t> padTo) {
    bool negative = false;
    if ( s.size() && s[0] == '-' ) {
        s.erase(0, 1);
        negative = true;
    }
    s.erase(0, s.find_first_not_of('0'));
    boost::multiprecision::cpp_int i(s);
    std::stringstream ss;
    if ( negative == true ) {
        ss << "-";
    }
    ss << std::hex << i;
    auto ret = ss.str();
    if ( ret.size() % 2 != 0 ) {
        ret = "0" + ret;
    }
    if ( padTo != std::nullopt && ret.size() < *padTo ) {
        ret = std::string(*padTo - ret.size(), '0') + ret;
    }
    return ret;
}

std::vector<uint8_t> HexToBin(const std::string s) {
    std::vector<uint8_t> data;

    boost::algorithm::unhex(s, std::back_inserter(data));

    return data;
}

std::optional<std::vector<uint8_t>> DecToBin(const std::string s, std::optional<size_t> size) {
    if ( !s.empty() && s[0] == '-' ) {
        return std::nullopt;
    }
    std::vector<uint8_t> v;
    boost::multiprecision::cpp_int c(s);
    boost::multiprecision::export_bits(c, std::back_inserter(v), 8);
    if ( size == std::nullopt ) {
        return v;
    }

    if ( v.size() > *size ) {
        return std::nullopt;
    }
    const auto diff = *size - v.size();

    std::vector<uint8_t> ret(*size);
    if ( diff > 0 ) {
        memset(ret.data(), 0, diff);
    }
    memcpy(ret.data() + diff, v.data(), v.size());

    return ret;
}

std::string BinToHex(const uint8_t* data, const size_t size) {
    return BinToHex(std::vector<uint8_t>(data, data + size));
}

std::string BinToHex(const std::vector<uint8_t> data) {
    std::string res;
    boost::algorithm::hex_lower(data.begin(), data.end(), back_inserter(res));

    return res;
}

std::string BinToDec(const uint8_t* data, const size_t size) {
    return BinToDec(std::vector<uint8_t>(data, data + size));
}

std::string BinToDec(const std::vector<uint8_t> data) {
    if ( data.empty() ) {
        return "0";
    }

    boost::multiprecision::cpp_int i;
    boost::multiprecision::import_bits(i, data.data(), data.data() + data.size());

    std::stringstream ss;
    ss << i;

    if ( ss.str().empty() ) {
        return "0";
    } else {
        return ss.str();
    }
}

std::optional<std::vector<uint8_t>> ToDER(const std::string A, const std::string B) {
    std::vector<uint8_t> ret;

    const auto ABin = DecToBin(A);
    if ( ABin == std::nullopt ) {
        return std::nullopt;
    }
    const auto BBin = DecToBin(B);
    if ( BBin == std::nullopt ) {
        return std::nullopt;
    }

    size_t ABinSize = ABin->size();
    size_t BBinSize = BBin->size();
    if ( ABinSize + BBinSize + 2 + 2 > 255 ) {
        return std::nullopt;
    }

    const bool AHigh = ABinSize > 0 && ((*ABin)[0] & 0x80) == 0x80;
    const bool BHigh = BBinSize > 0 && ((*BBin)[0] & 0x80) == 0x80;

    ABinSize += AHigh ? 1 : 0;
    BBinSize += BHigh ? 1 : 0;

    ret.push_back(0x30);
    ret.push_back(2 + ABinSize + 2 + BBinSize);

    ret.push_back(0x02);
    ret.push_back(ABinSize);
    if ( AHigh == true ) {
        ret.push_back(0x00);
    }
    ret.insert(std::end(ret), std::begin(*ABin), std::end(*ABin));

    ret.push_back(0x02);
    ret.push_back(BBinSize);
    if ( BHigh == true ) {
        ret.push_back(0x00);
    }
    ret.insert(std::end(ret), std::begin(*BBin), std::end(*BBin));

    return ret;
}

std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::string s) {
    return SignatureFromDER(HexToBin(s));
}

std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::vector<uint8_t> data) {
#define ADVANCE(n) { \
    i += n; \
    left -= n; \
}

#define GETBYTE() { \
    CF_CHECK_LT(i, data.size()); \
    b = data[i]; \
    ADVANCE(1); \
}
    std::optional<std::pair<std::string, std::string>> ret = std::nullopt;
    uint8_t b;
    size_t i = 0, left = data.size();
    std::string R, S;

    GETBYTE(); CF_CHECK_EQ(b, 0x30);

    GETBYTE(); CF_CHECK_EQ(b, left);

    /* R */
    {
        GETBYTE(); CF_CHECK_EQ(b, 0x02);

        GETBYTE(); CF_CHECK_LTE(b, left);
        auto size = b;

        R = BinToDec(std::vector<uint8_t>(&data[i], &data[i+size]));
        ADVANCE(size);

    }

    /* S */
    {
        GETBYTE(); CF_CHECK_EQ(b, 0x02);

        GETBYTE(); CF_CHECK_LTE(b, left);
        auto size = b;

        S = BinToDec(std::vector<uint8_t>(&data[i], &data[i+size]));
        ADVANCE(size);
    }

    ret = {R, S};

end:
    return ret;
}

std::optional<std::pair<std::string, std::string>> PubkeyFromASN1(const uint64_t curveType, const std::string s) {
    return PubkeyFromASN1(curveType, HexToBin(s));
}

std::optional<std::pair<std::string, std::string>> PubkeyFromASN1(const uint64_t curveType, const std::vector<uint8_t> data) {
    const auto numBits = cryptofuzz::repository::ECC_CurveToBits(curveType);
    if ( numBits == std::nullopt ) {
        return std::nullopt;
    }
    const size_t coordsize = (*numBits + 7) / 8;
    if ( data.size() < ((coordsize*2) + 2) ) {
        return std::nullopt;
    }

    const uint8_t* start2 = data.data() + data.size() - (coordsize * 2);
    const uint8_t* start1 = start2 - 2;

    if ( start1[0] != 0x00 || start1[1] != 0x04 ) {
        return std::nullopt;
    }

    return std::pair<std::string, std::string>{
        BinToDec({start2, start2 + coordsize}),
        BinToDec({start2 + coordsize, start2 + (coordsize * 2)}),
    };
}

std::string SHA1(const std::vector<uint8_t> data) {
    return BinToHex(crypto::sha1(data));
}

void HintBignum(const std::string bn) {
    if ( bn.size() < config::kMaxBignumSize ) {
        Pool_Bignum.Set(bn);
    }
}

void HintBignumPow2(size_t maxSize) {
    if ( maxSize > config::kMaxBignumSize ) {
        maxSize = config::kMaxBignumSize;
    }

    if ( maxSize == 0 ) {
        return;
    }

    boost::multiprecision::cpp_int pow2(1);
    const size_t count = PRNG() % static_cast<size_t>(maxSize * 3.322);
    pow2 <<= count;
    HintBignum(pow2.str());
}

void HintBignumInt(void) {
    HintBignum( std::to_string(PRNG() % 2147483648) );
}

void HintBignumOpt(const std::optional<std::string> bn) {
    if ( bn != std::nullopt ) {
        HintBignum(*bn);
    }
}

std::vector<uint8_t> Append(const std::vector<uint8_t> A, const std::vector<uint8_t> B) {
    std::vector<uint8_t> ret;

    ret.reserve(A.size() + B.size());
    ret.insert(ret.end(), A.begin(), A.end());
    ret.insert(ret.end(), B.begin(), B.end());

    return ret;
}

std::vector<uint8_t> RemoveLeadingZeroes(std::vector<uint8_t> v) {
    const auto it = std::find_if(v.begin(), v.end(), [](const size_t v) { return v != 0; });
    v.erase(v.begin(), it);
    return v;
}

std::vector<uint8_t> AddLeadingZeroes(fuzzing::datasource::Datasource& ds, const std::vector<uint8_t>& v) {
    const auto stripped = RemoveLeadingZeroes(v);

    uint16_t numZeroes = 0;
    try {
        numZeroes = ds.Get<uint8_t>();
        numZeroes %= 64;
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
    }
    const std::vector<uint8_t> zeroes(numZeroes, 0);

    return Append(zeroes, stripped);
}

void AdjustECDSASignature(const uint64_t curveType, component::Bignum& s) {
    if ( curveType == CF_ECC_CURVE("secp256k1") ) {
        if ( !s.IsGreaterThan("57896044618658097711785492504343953926418782139537452191302581570759080747168") ) {
            return;
        }
        s.SubFrom("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    } else if ( curveType == CF_ECC_CURVE("secp256r1") ) {
        if ( !s.IsGreaterThan("57896044605178124381348723474703786764998477612067880171211129530534256022184") ) {
            return;
        }
        s.SubFrom("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    } else {
        /* No modification required */
        return;
    }
}

static inline boost::multiprecision::cpp_int sqrt_mod(
        const boost::multiprecision::cpp_int& in,
        const boost::multiprecision::cpp_int& prime) {
    using namespace boost::multiprecision;

    /* https://www.rieselprime.de/ziki/Modular_square_root */

    if ( prime % 4 == 3 ) {
        const cpp_int r = powm(in, (prime + 1) / 4, prime);

        return r;
    } else if ( prime % 8 == 5 ) {
        const cpp_int v = powm((2 * in), (prime - 5) / 8, prime);
        const cpp_int i = (2 * in * pow(v, 2)) % prime;
        const cpp_int r = (in * v * (i - 1)) % prime;

        return r;
    }

    /* Other primes not yet supported */

    return 0;
}

/* Find corresponding Y coordinate given X, A, B, P */
std::string Find_ECC_Y(
        const std::string& x,
        const std::string& a,
        const std::string& b,
        const std::string& p,
        const std::string& o, const bool addOrder) {
    using namespace boost::multiprecision;

    const cpp_int A(a), B(b), P(p);
    const cpp_int X = cpp_int(x) % P;

    const cpp_int Z = (pow(X, 3) + (A*X) + B) % P;
    const cpp_int res = sqrt_mod(Z, P) + (addOrder ? cpp_int(o) : cpp_int(0));

    return res.str();
}

std::array<std::string, 3> ToRandomProjective(
        fuzzing::datasource::Datasource& ds,
        const std::string& x,
        const std::string& y,
        const uint64_t curveType,
        const bool jacobian,
        const bool inRange) {
    using namespace boost::multiprecision;
    const auto p = cryptofuzz::repository::ECC_CurveToPrime(curveType);
    if ( p == std::nullopt ) {
        return {x, y, "1"};
    }

    std::vector<uint8_t> data;
    try {
        data = ds.GetData(0, 0, 1024 / 8);
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
    }
    if ( data.empty() ) {
        return {x, y, "1"};
    }

    cpp_int X(x), Y(y);
    const cpp_int P(*p);

    if ( inRange == true ) {
        /* Ensure coordinates are within bounds.
         *
         * This is to prevent that an affine ECC_Point with oversized coordinates
         * will be regarded as invalid by a library, but then the projective
         * coordinates (which are always within bounds, because they are reduced
         * MOD P below), are regarded as valid.
         *
         * This can create discrepancies in operations such as ECC_ValidatePubKey.
         */
        if ( X < 0 || X >= P ) {
            return {x, y, "1"};
        }
        if ( Y < 0 || Y >= P ) {
            return {x, y, "1"};
        }
    }

    cpp_int Z;
    boost::multiprecision::import_bits(Z, data.data(), data.data() + data.size());
    Z %= P;
    if ( Z == 0 ) {
        return {x, y, "1"};
    }
    if ( jacobian == true ) {
        X = (X * (Z * Z)) % P;
        Y = (Y * (Z * Z * Z)) % P;
    } else {
        X = (X * Z) % P;
        Y = (Y * Z) % P;
    }
    return {X.str(), Y.str(), Z.str()};
}

extern "C" {
    __attribute__((weak)) void __msan_unpoison(const volatile void*, size_t) { }
}

void MemorySanitizerUnpoison(const void* data, const size_t size) {
    __msan_unpoison(data, size);
}

} /* namespace util */
} /* namespace cryptofuzz */
