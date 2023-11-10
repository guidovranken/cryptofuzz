#include <cryptofuzz/crypto.h>
#include <cryptofuzz/generic.h>
#include <cryptofuzz/components.h>
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptofuzz/repository.h>
#include "third_party/json/json.hpp"
#include "config.h"

namespace cryptofuzz {

/* Type */

Type::Type(Datasource& ds) :
    type ( ds.Get<uint64_t>(0) )
{ }

Type::Type(const Type& other) :
    type(other.type)
{ }

Type::Type(nlohmann::json json) :
    type(json.get<uint64_t>())
{ }

uint64_t Type::Get(void) const {
    return type;
}

bool Type::Is(const uint64_t t) const {
    return type == t;
}

bool Type::Is(const std::vector<uint64_t> t) const {
    return std::find(t.begin(), t.end(), type) != t.end();
}

nlohmann::json Type::ToJSON(void) const {
    nlohmann::json j;
    /* Store as string, not as number, because JavaScript's number
     * type has only 53 bits of precision.
     */
    j = std::to_string(type);
    return j;
}

bool Type::operator==(const Type& rhs) const {
    return type == rhs.type;
}

void Type::Serialize(Datasource& ds) const {
    ds.Put<>(type);
}

/* Buffer */

Buffer::Buffer(Datasource& ds) :
    data( ds.GetData(0, 0, (10*1024*1024)) )
{ }

Buffer::Buffer(nlohmann::json json) {
    const auto s = json.get<std::string>();
    boost::algorithm::unhex(s, std::back_inserter(data));
}

Buffer::Buffer(const std::vector<uint8_t>& data) :
    data(data)
{ }

Buffer::Buffer(const uint8_t* data, const size_t size) :
    data(data, data + size)
{ }

Buffer::Buffer(void) { }

std::vector<uint8_t> Buffer::Get(void) const {
    return data;
}

const uint8_t* Buffer::GetPtr(fuzzing::datasource::Datasource* ds) const {
    if ( data.size() == 0 ) {
        return util::GetNullPtr(ds);
    } else {
        return data.data();
    }
}

std::vector<uint8_t>& Buffer::GetVectorPtr(void) {
    return data;
}

const std::vector<uint8_t>& Buffer::GetConstVectorPtr(void) const {
    return data;
}

size_t Buffer::GetSize(void) const {
    return data.size();
}

bool Buffer::operator==(const Buffer& rhs) const {
    return data == rhs.data;
}

nlohmann::json Buffer::ToJSON(void) const {
    nlohmann::json j;
    std::string asHex;
    boost::algorithm::hex(data, std::back_inserter(asHex));
    j = asHex;
    return j;
}

std::string Buffer::ToHex(void) const {
    std::string asHex;
    boost::algorithm::hex(data, std::back_inserter(asHex));
    return asHex;
}

void Buffer::Serialize(Datasource& ds) const {
    ds.PutData(data);
}

Datasource Buffer::AsDatasource(void) const {
    return Datasource(data.data(), data.size());
}

std::string Buffer::AsString(void) const {
    return std::string(data.data(), data.data() + data.size());
}

Buffer Buffer::ECDSA_Pad(const size_t retSize) const {
    size_t bufSize = GetSize();

    if ( bufSize > retSize ) {
        bufSize = retSize;
    }

    std::vector<uint8_t> ret(retSize);

    if ( retSize != 0 ) {
        const size_t delta = retSize - bufSize;

        if ( delta != 0 ) {
            memset(ret.data(), 0, delta);
        }

        if ( bufSize != 0 ) {
            memcpy(ret.data() + delta, GetPtr(), bufSize);
        }
    }

    return Buffer(ret);
}

/* Randomly modify an ECDSA input in such a way that it remains equivalent
 * to ECDSA verify/sign functions
 */
Buffer Buffer::ECDSA_RandomPad(Datasource& ds, const Type& curveType) const {
    const auto numBits = cryptofuzz::repository::ECC_CurveToBits(curveType.Get());
    if ( numBits == std::nullopt ) {
        /* The size of this curve is not known, so return the original buffer */
        return Buffer(data);
    }

    if ( *numBits % 8 != 0 ) {
        /* Curve sizes which are not a byte multiple are currently not supported,
         * so return the original buffer
         */
        return Buffer(data);
    }

    const size_t numBytes = (*numBits + 7) / 8;

    std::vector<uint8_t> stripped;
    {
        size_t startPos;
        const size_t endPos = GetSize() > numBytes ? numBytes : GetSize();

        for (startPos = 0; startPos < endPos; startPos++) {
            if ( data[startPos] != 0 ) {
                break;
            }
        }
        const auto& ref = GetConstVectorPtr();

        stripped.insert(std::end(stripped), std::begin(ref) + startPos, std::begin(ref) + endPos);
    }

    /* Decide how many bytes to insert */
    uint16_t numInserts = 0;
    try {
        numInserts = ds.Get<uint16_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

    std::vector<uint8_t> ret;

    /* Left-pad the input until it is the curve size */
    {
        if ( stripped.size() < numBytes ) {
            const size_t needed = numBytes - stripped.size();
            const std::vector<uint8_t> zeroes(numInserts > needed ? needed : numInserts, 0);
            ret.insert(std::end(ret), std::begin(zeroes), std::end(zeroes));
            numInserts -= zeroes.size();
        }
    }

    /* Insert the input */
    ret.insert(std::end(ret), std::begin(stripped), std::end(stripped));

    /* Right-pad the input with random bytes (if available) or zeroes */
    if ( numInserts > 0 ) {
        std::vector<uint8_t> toInsert;
        try {
            toInsert = ds.GetData(0, numInserts, numInserts);
        } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
            toInsert = std::vector<uint8_t>(numInserts, 0);
        }
        ret.insert(std::end(ret), std::begin(toInsert), std::end(toInsert));
    }

    return Buffer(ret);
}

Buffer Buffer::SHA256(void) const {
    const auto hash = crypto::sha256(Get());
    return Buffer(hash);
}

bool Buffer::IsZero(void) const {
    for (size_t i = 0; i < data.size(); i++) {
        if ( data[i] != 0 ) {
            return false;
        }
    }

    return true;
}

/* Bignum */

Bignum::Bignum(Datasource& ds) :
    data(ds) {
    transform();
}

Bignum::Bignum(nlohmann::json json) :
    Bignum(json.get<std::string>())
{
}

Bignum::Bignum(const std::string s) :
    data((const uint8_t*)s.data(), s.size())
{ }

void Bignum::transform(void) {
    auto& ptr = data.GetVectorPtr();

    for (size_t i = 0; i < ptr.size(); i++) {
        if ( isdigit(ptr[i]) ) continue;
        if ( config::kNegativeIntegers == true ) {
            if ( i == 0 && ptr[i] == '-') continue;
        }
        ptr[i] %= 10;
        ptr[i] += '0';
    }
}

bool Bignum::operator==(const Bignum& rhs) const {
    return data == rhs.data;
}

size_t Bignum::GetSize(void) const {
    return data.GetSize();
}

bool Bignum::IsZero(void) const {
    const auto t = ToTrimmedString();
    return t == "0" || t == "-" || t == "-0";
}

bool Bignum::IsOne(void) const {
    const auto t = ToTrimmedString();
    return t == "1";
}

bool Bignum::IsNegative(void) const {
    return data.GetSize() && data.GetConstVectorPtr()[0] == '-';
}

bool Bignum::IsPositive(void) const {
    return !IsZero() && !IsNegative();
}

bool Bignum::IsGreaterThan(const std::string& other) const {
    CF_ASSERT(IsNegative() == false, "IsGreaterThan on negative numbers not supported");
    const auto s = ToTrimmedString();
    if ( s.size() > other.size() ) {
        return true;
    } else if ( s.size() < other.size() ) {
        return false;
    } else {
        for (size_t i = 0; i < s.size(); i++) {
            const int a = s[i];
            const int b = other[i];
            if ( a > b ) {
                return true;
            } else if ( a < b ) {
                return false;
            }
        }
    }

    CF_ASSERT(s == other, "Logic error");
    return false;
}

bool Bignum::IsLessThan(const std::string& other) const {
    boost::multiprecision::cpp_int A(ToTrimmedString());
    boost::multiprecision::cpp_int B(other);
    return A < B;
}

bool Bignum::IsOdd(void) const {
    const auto s = ToTrimmedString();
    return ((s.back() - '0') % 2) == 1;
}

void Bignum::ToPositive(void) {
    if ( !IsNegative() ) {
        return;
    }

    data.GetVectorPtr().erase(data.GetVectorPtr().begin());
}

void Bignum::SubFrom(const std::string& v) {
    boost::multiprecision::cpp_int A(ToTrimmedString());
    boost::multiprecision::cpp_int B(v);
    boost::multiprecision::cpp_int res = B - A;
    const auto s = res.str();
    data = {(const uint8_t*)s.data(), s.size()};
}

std::string Bignum::ToString(void) const {
    const auto ptr = data.GetPtr();
    return std::string(ptr, ptr + data.GetSize());
}

std::string Bignum::ToTrimmedString(void) const {
    auto s = ToString();
    trim_left_if(s, boost::is_any_of("0"));

    if ( s == "" ) {
        return "0";
    } else {
        return s;
    }
}

/* Prefix the string with a pseudo-random amount of zeroes */
std::string Bignum::ToString(Datasource& ds) const {
    std::string zeros;

    try {
        while ( ds.Get<bool>() == true ) {
            zeros += "0";
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }

    auto s = ToTrimmedString();
    const bool isNegative = IsNegative();
    if ( s.size() && s[0] == '-' ) {
        s.erase(0, 1);
    }
    return (isNegative ? "-" : "") + zeros + s;
}

std::optional<std::vector<uint8_t>> Bignum::ToBin(std::optional<size_t> size) const {
    return util::DecToBin(ToTrimmedString(), size);
}

nlohmann::json Bignum::ToJSON(void) const {
    return ToString();
}

void Bignum::Serialize(Datasource& ds) const {
    data.Serialize(ds);
}

namespace component {
/* SymmetricCipher */

SymmetricCipher::SymmetricCipher(Datasource& ds) :
    iv(ds),
    key(ds),
    cipherType(ds)
{ }

SymmetricCipher::SymmetricCipher(nlohmann::json json) :
    iv(json["iv"]),
    key(json["key"]),
    cipherType(json["cipherType"])
{ }

nlohmann::json SymmetricCipher::ToJSON(void) const {
    nlohmann::json j;
    j["iv"] = iv.ToJSON();
    j["key"] = key.ToJSON();
    j["cipherType"] = cipherType.ToJSON();
    return j;
}

bool SymmetricCipher::operator==(const SymmetricCipher& rhs) const {
    return
        (iv == rhs.iv) &&
        (key == rhs.key) &&
        (cipherType == rhs.cipherType);
}
void SymmetricCipher::Serialize(Datasource& ds) const {
    iv.Serialize(ds);
    key.Serialize(ds);
    cipherType.Serialize(ds);
}

/* Ciphertext */

Ciphertext::Ciphertext(Datasource& ds) :
    ciphertext(ds),
    tag( ds.Get<bool>() ? std::nullopt : std::make_optional<Tag>(ds) )
{ }

Ciphertext::Ciphertext(Buffer ciphertext, std::optional<Tag> tag) :
    ciphertext(ciphertext),
    tag(tag)
{ }

bool Ciphertext::operator==(const Ciphertext& rhs) const {
    return (ciphertext == rhs.ciphertext) && (tag == rhs.tag);
}

void Ciphertext::Serialize(Datasource& ds) const {
    ciphertext.Serialize(ds);
    if ( tag == std::nullopt ) {
        ds.Put<bool>(true);
    } else {
        ds.Put<bool>(false);
        tag->Serialize(ds);
    }
}

/* BignumPair */

BignumPair::BignumPair(Datasource& ds) :
    first(ds),
    second(ds)
{ }

BignumPair::BignumPair(const std::string first, const std::string second) :
    first(first),
    second(second)
{ }

BignumPair::BignumPair(nlohmann::json json) :
    first(json[0].get<std::string>()),
    second(json[1].get<std::string>())
{ }


bool BignumPair::operator==(const BignumPair& rhs) const {
    return
        (first == rhs.first) &&
        (second == rhs.second);
}

void BignumPair::Serialize(Datasource& ds) const {
    first.Serialize(ds);
    second.Serialize(ds);
}

nlohmann::json BignumPair::ToJSON(void) const {
    return std::vector<nlohmann::json>{first.ToJSON(), second.ToJSON()};
}

/* ECC_KeyPair */

ECC_KeyPair::ECC_KeyPair(Datasource& ds) :
    priv(ds),
    pub(ds)
{ }

ECC_KeyPair::ECC_KeyPair(ECC_PrivateKey priv, BignumPair pub) :
    priv(priv),
    pub(pub)
{ }

ECC_KeyPair::ECC_KeyPair(nlohmann::json json) :
    priv(json["priv"]),
    pub(json["pub"])
{ }

bool ECC_KeyPair::operator==(const ECC_KeyPair& rhs) const {
    return
        (priv == rhs.priv) &&
        (pub == rhs.pub);
}

void ECC_KeyPair::Serialize(Datasource& ds) const {
    priv.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json ECC_KeyPair::ToJSON(void) const {
    return std::vector<nlohmann::json>{priv.ToJSON(), pub.ToJSON()};
}

/* ECCSI_Signature */
ECCSI_Signature::ECCSI_Signature(Datasource& ds) :
    signature(ds),
    pub(ds),
    pvt(ds)
{ }

ECCSI_Signature::ECCSI_Signature(BignumPair signature, ECC_PublicKey pub, BignumPair pvt) :
    signature(signature),
    pub(pub),
    pvt(pvt)
{ }

ECCSI_Signature::ECCSI_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"]),
    pvt(json["pvt"])
{ }

bool ECCSI_Signature::operator==(const ECCSI_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub) &&
        (pvt == rhs.pvt);
}

void ECCSI_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
    pvt.Serialize(ds);
}

nlohmann::json ECCSI_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

/* ECDSA_Signature */
ECDSA_Signature::ECDSA_Signature(Datasource& ds) :
    signature(ds),
    pub(ds)
{ }

ECDSA_Signature::ECDSA_Signature(BignumPair signature, ECC_PublicKey pub) :
    signature(signature),
    pub(pub)
{ }

ECDSA_Signature::ECDSA_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"])
{ }

bool ECDSA_Signature::operator==(const ECDSA_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub);
}

void ECDSA_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json ECDSA_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

/* MACType */

MACType::MACType(Datasource& ds) :
    mode(ds.Get<bool>()),
    type(ds)
{ }

MACType::MACType(nlohmann::json json) :
    mode(json["mode"].get<bool>()),
    type(json["type"])
{ }

nlohmann::json MACType::ToJSON(void) const {
    nlohmann::json j;
    j["mode"] = mode;
    j["type"] = type.ToJSON();
    return j;
}

bool MACType::operator==(const MACType& rhs) const {
    return
        (mode == rhs.mode) &&
        (type == rhs.type);
}

void MACType::Serialize(Datasource& ds) const {
    ds.Put<>(mode);
    type.Serialize(ds);
}

G2::G2(nlohmann::json json) :
    first(json[0]),
    second(json[1]) {
}

nlohmann::json G2::ToJSON(void) const {
    return std::vector<nlohmann::json>{
        first.first.ToJSON(), first.second.ToJSON(),
        second.first.ToJSON(), second.second.ToJSON()
    };
}

void G2::Serialize(Datasource& ds) const {
    first.Serialize(ds);
    second.Serialize(ds);
}

nlohmann::json Fp12::ToJSON(void) const {
    return std::vector<nlohmann::json>{
        bn1.ToJSON(),
        bn2.ToJSON(),
        bn3.ToJSON(),
        bn4.ToJSON(),
        bn5.ToJSON(),
        bn6.ToJSON(),
        bn7.ToJSON(),
        bn8.ToJSON(),
        bn9.ToJSON(),
        bn10.ToJSON(),
        bn11.ToJSON(),
        bn12.ToJSON(),
    };
}

Fp12::Fp12(nlohmann::json json) :
    bn1(json[0].get<std::string>()),
    bn2(json[1].get<std::string>()),
    bn3(json[2].get<std::string>()),
    bn4(json[3].get<std::string>()),
    bn5(json[4].get<std::string>()),
    bn6(json[5].get<std::string>()),
    bn7(json[6].get<std::string>()),
    bn8(json[7].get<std::string>()),
    bn9(json[8].get<std::string>()),
    bn10(json[9].get<std::string>()),
    bn11(json[10].get<std::string>()),
    bn12(json[11].get<std::string>())
{ }

void Fp12::Serialize(Datasource& ds) const {
    bn1.Serialize(ds);
    bn2.Serialize(ds);
    bn3.Serialize(ds);
    bn4.Serialize(ds);
    bn5.Serialize(ds);
    bn6.Serialize(ds);
    bn7.Serialize(ds);
    bn8.Serialize(ds);
    bn9.Serialize(ds);
    bn10.Serialize(ds);
    bn11.Serialize(ds);
    bn12.Serialize(ds);
}

nlohmann::json DSA_Parameters::ToJSON(void) const {
    return std::vector<nlohmann::json>{
        p.ToJSON(),
        q.ToJSON(),
        g.ToJSON(),
    };
}

DSA_Parameters::DSA_Parameters(nlohmann::json json) :
    p(json["p"].get<std::string>()),
    q(json["q"].get<std::string>()),
    g(json["g"].get<std::string>())
{ }

void DSA_Parameters::Serialize(Datasource& ds) const {
    p.Serialize(ds);
    q.Serialize(ds);
    g.Serialize(ds);
}

/* DSA_Signature */
DSA_Signature::DSA_Signature(Datasource& ds) :
    signature(ds),
    pub(ds)
{ }

DSA_Signature::DSA_Signature(BignumPair signature, Bignum pub) :
    signature(signature),
    pub(pub)
{ }

DSA_Signature::DSA_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"])
{ }

bool DSA_Signature::operator==(const DSA_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub);
}

void DSA_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json DSA_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

/* BLS_Signature */
BLS_Signature::BLS_Signature(Datasource& ds) :
    signature(ds),
    pub(ds)
{ }

BLS_Signature::BLS_Signature(G2 signature, ECC_PublicKey pub) :
    signature(signature),
    pub(pub)
{ }

BLS_Signature::BLS_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"])
{ }

bool BLS_Signature::operator==(const BLS_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub);
}

void BLS_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json BLS_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

/* BLS_BatchSign_Vector */

BLS_BatchSign_Vector::BLS_BatchSign_Vector(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        c.push_back( BatchSign_single{{ds}, {ds}} );
    }
}

BLS_BatchSign_Vector::BLS_BatchSign_Vector(nlohmann::json json) {
    for (const auto& j : json) {
        c.push_back( BatchSign_single{
                j["priv"],
                {j["g1_x"], j["g1_y"]} });
    }
}

void BLS_BatchSign_Vector::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(c.size());
    for (const auto& component : c) {
        component.priv.Serialize(ds);
        component.g1.Serialize(ds);
    }
}

/* BLS_BatchSignature */

BLS_BatchSignature::BLS_BatchSignature(std::vector< std::pair<G1, G2> > msgpub) :
    msgpub(msgpub)
{ }

bool BLS_BatchSignature::operator==(const BLS_BatchSignature& rhs) const {
    return
        (msgpub == rhs.msgpub);
}

void BLS_BatchSignature::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(msgpub.size());
    for (const auto& component : msgpub) {
        component.first.Serialize(ds);
        component.second.Serialize(ds);
    }
}

nlohmann::json BLS_BatchSignature::ToJSON(void) const {
    return {}; /* TODO */
}


/* BLS_KeyPair */

BLS_KeyPair::BLS_KeyPair(Datasource& ds) :
    priv(ds),
    pub(ds)
{ }

BLS_KeyPair::BLS_KeyPair(BLS_PrivateKey priv, BignumPair pub) :
    priv(priv),
    pub(pub)
{ }

bool BLS_KeyPair::operator==(const BLS_KeyPair& rhs) const {
    return
        (priv == rhs.priv) &&
        (pub == rhs.pub);
}

void BLS_KeyPair::Serialize(Datasource& ds) const {
    priv.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json BLS_KeyPair::ToJSON(void) const {
    return std::vector<nlohmann::json>{priv.ToJSON(), pub.ToJSON()};
}

/* BLS_BatchVerify_Vector */

BLS_BatchVerify_Vector::BLS_BatchVerify_Vector(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        c.push_back( BatchVerify_single{{ds}, {ds}} );
    }
}

BLS_BatchVerify_Vector::BLS_BatchVerify_Vector(nlohmann::json json) {
    for (const auto& j : json) {
        c.push_back( BatchVerify_single{
                {j["g1_x"], j["g1_y"]},
                {j["g2_v"], j["g2_w"], j["g2_x"], j["g2_y"]} });
    }
}

void BLS_BatchVerify_Vector::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(c.size());
    for (const auto& component : c) {
        component.g1.Serialize(ds);
        component.g2.Serialize(ds);
    }
}

nlohmann::json BLS_BatchVerify_Vector::ToJSON(void) const {
    nlohmann::json j = nlohmann::json::array();
    for (const auto& cur : c) {
        nlohmann::json curj;
        curj["g1_x"] = cur.g1.first.ToJSON();
        curj["g1_y"] = cur.g1.second.ToJSON();

        curj["g2_v"] = cur.g2.first.first.ToJSON();
        curj["g2_w"] = cur.g2.first.second.ToJSON();
        curj["g2_x"] = cur.g2.second.first.ToJSON();
        curj["g2_y"] = cur.g2.second.second.ToJSON();

        j.push_back(curj);
    }
    return j;
}

/* BLS_G1_Vector */

BLS_G1_Vector::BLS_G1_Vector(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        points.push_back( component::G1(ds) );
    }
}

BLS_G1_Vector::BLS_G1_Vector(nlohmann::json json) {
    for (const auto& j : json) {
        points.push_back( component::G1{j["x"], j["y"]} );
    }
}

void BLS_G1_Vector::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(points.size());
    for (const auto& signature : points) {
        signature.Serialize(ds);
    }
}

/* BLS_G1_Scalar_Vector */

BLS_G1_Scalar_Vector::BLS_G1_Scalar_Vector(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        points_scalars.push_back({
                component::G1(ds),
                component::Bignum(ds),
        });
    }
}

BLS_G1_Scalar_Vector::BLS_G1_Scalar_Vector(nlohmann::json json) {
    for (const auto& j : json) {
        points_scalars.push_back({
                component::G1{j["x"], j["y"]},
                component::Bignum{j["scalar"]},
        });
    }
}

void BLS_G1_Scalar_Vector::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(points_scalars.size());
    for (const auto& point_scalar : points_scalars) {
        point_scalar.first.Serialize(ds);
        point_scalar.second.Serialize(ds);
    }
}

/* BLS_G2_Vector */

BLS_G2_Vector::BLS_G2_Vector(Datasource& ds) {
    const auto num = ds.Get<uint32_t>(0);
    for (size_t i = 0; i < num; i++) {
        points.push_back( component::G2(ds) );
    }
}

BLS_G2_Vector::BLS_G2_Vector(nlohmann::json json) {
    for (const auto& j : json) {
        points.push_back( component::G2{j["v"], j["w"], j["x"], j["y"]} );
    }
}

void BLS_G2_Vector::Serialize(Datasource& ds) const {
    ds.Put<uint32_t>(points.size());
    for (const auto& signature : points) {
        signature.Serialize(ds);
    }
}

/* SR25519_Signature */
SR25519_Signature::SR25519_Signature(Datasource& ds) :
    signature(ds),
    pub(ds)
{ }

SR25519_Signature::SR25519_Signature(BignumPair signature, Bignum pub) :
    signature(signature),
    pub(pub)
{ }

SR25519_Signature::SR25519_Signature(nlohmann::json json) :
    signature(json["signature"]),
    pub(json["pub"])
{ }

bool SR25519_Signature::operator==(const SR25519_Signature& rhs) const {
    return
        (signature == rhs.signature) &&
        (pub == rhs.pub);
}

void SR25519_Signature::Serialize(Datasource& ds) const {
    signature.Serialize(ds);
    pub.Serialize(ds);
}

nlohmann::json SR25519_Signature::ToJSON(void) const {
    return std::vector<nlohmann::json>{signature.ToJSON(), pub.ToJSON()};
}

} /* namespace component */

} /* namespace cryptofuzz */
