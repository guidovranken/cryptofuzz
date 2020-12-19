#include <cryptofuzz/generic.h>
#include <cryptofuzz/components.h>
#include <cryptofuzz/util.h>
#include "third_party/json/json.hpp"

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

std::string Bignum::ToString(void) const {
    return std::string(data.GetPtr(), data.GetPtr() + data.GetSize());
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
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    return zeros + ToTrimmedString();
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

} /* namespace component */

} /* namespace cryptofuzz */
