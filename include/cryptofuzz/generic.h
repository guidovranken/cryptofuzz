#pragma once

#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include "../../third_party/json/json.hpp"

namespace cryptofuzz {

using fuzzing::datasource::Datasource;

class Type {
    private:
        const uint64_t type;
    public:

        Type(Datasource& ds);
        Type(const Type& other); /* Copy constructor */
        Type(nlohmann::json json);

        uint64_t Get(void) const;
        bool Is(const uint64_t t) const;
        bool Is(const std::vector<uint64_t> t) const;
        nlohmann::json ToJSON(void) const;
        bool operator==(const Type& rhs) const;
        void Serialize(Datasource& ds) const;
};

class Buffer {
    private:
        std::vector<uint8_t> data;
    public:
        Buffer(Datasource& ds);
        Buffer(nlohmann::json json);
        explicit Buffer(const std::vector<uint8_t>& data);
        Buffer(const uint8_t* data, const size_t size);
        Buffer(void);

        std::vector<uint8_t> Get(void) const;
        const uint8_t* GetPtr(fuzzing::datasource::Datasource* ds = nullptr) const;
        std::vector<uint8_t>& GetVectorPtr(void);
        const std::vector<uint8_t>& GetConstVectorPtr(void) const;
        size_t GetSize(void) const;
        bool operator==(const Buffer& rhs) const;
        nlohmann::json ToJSON(void) const;
        std::string ToHex(void) const;
        void Serialize(Datasource& ds) const;
        Datasource AsDatasource(void) const;
        std::string AsString(void) const;
        Buffer ECDSA_Pad(const size_t size) const;
        Buffer ECDSA_RandomPad(Datasource& ds, const Type& curveType) const;
        Buffer SHA256(void) const;
        bool IsZero(void) const;
};

class Bignum {
    private:
        Buffer data;
        void transform(void);
    public:
        Bignum(Datasource& ds);
        Bignum(nlohmann::json json);
        Bignum(const std::string s);

        bool operator==(const Bignum& rhs) const;
        size_t GetSize(void) const;
        bool IsZero(void) const;
        bool IsOne(void) const;
        bool IsNegative(void) const;
        bool IsPositive(void) const;
        bool IsGreaterThan(const std::string& other) const;
        bool IsLessThan(const std::string& other) const;
        bool IsOdd(void) const;
        void ToPositive(void);
        void SubFrom(const std::string& v);
        std::string ToString(void) const;
        std::string ToTrimmedString(void) const;
        std::string ToString(Datasource& ds) const;
        std::optional<std::vector<uint8_t>> ToBin(std::optional<size_t> size = std::nullopt) const;
        nlohmann::json ToJSON(void) const;
        void Serialize(Datasource& ds) const;
};

} /* namespace cryptofuzz */
