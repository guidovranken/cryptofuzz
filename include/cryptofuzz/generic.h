#pragma once

#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include "../../third_party/json/json.hpp"

namespace cryptofuzz {

namespace util {
    uint8_t* GetNullPtr(void);
}

using fuzzing::datasource::Datasource;

class Type {
    private:
        const uint64_t type;
    public:

        Type(Datasource& ds) : type ( ds.Get<uint64_t>(0) )
        { }

        /* Copy constructor */
        Type(const Type& other) :
            type(other.type)
        { }

        Type(nlohmann::json json) :
            type(json.get<uint64_t>())
        { }

        uint64_t Get(void) const {
            return type;
        }

        nlohmann::json ToJSON(void) const {
            nlohmann::json j;
            j = type;
            return j;
        }

        inline bool operator==(const Type& rhs) const {
            return type == rhs.type;
        }
};

class Buffer {
    private:
        std::vector<uint8_t> data;
    public:
        Buffer(Datasource& ds) :
            data( ds.GetData(0, 0, 32000) )
        { }

        Buffer(nlohmann::json json) {
            const auto s = json.get<std::string>();
            boost::algorithm::unhex(s, std::back_inserter(data));
        }

        explicit Buffer(const std::vector<uint8_t>& data) :
            data(data)
        { }

        Buffer(const uint8_t* data, const size_t size) :
            data(data, data + size)
        { }

        Buffer(void) { }

        std::vector<uint8_t> Get(void) const {
            return data;
        }

        const uint8_t* GetPtr(void) const {
            if ( data.size() == 0 ) {
                return util::GetNullPtr();
            } else {
                return data.data();
            }
        }

        std::vector<uint8_t>& GetVectorPtr(void) {
            return data;
        }

        size_t GetSize(void) const {
            return data.size();
        }

        inline bool operator==(const Buffer& rhs) const {
            return data == rhs.data;
        }

        nlohmann::json ToJSON(void) const {
            nlohmann::json j;
            std::string asHex;
            boost::algorithm::hex(data, std::back_inserter(asHex));
            j = asHex;
            return j;
        }
};

class Bignum {
    private:
        Buffer data;
        void transform(void) {
            auto& ptr = data.GetVectorPtr();

            for (size_t i = 0; i < ptr.size(); i++) {
                if ( isdigit(ptr[i]) ) continue;
                ptr[i] %= 10;
                ptr[i] += '0';
            }
        }
    public:
        Bignum(Datasource& ds) :
            data(ds) {
            transform();
        }

        Bignum(nlohmann::json json) :
            Bignum(json.get<std::string>())
        {
        }

        Bignum(const std::string s) :
            data((const uint8_t*)s.data(), s.size())
        { }


        inline bool operator==(const Bignum& rhs) const {
            return data == rhs.data;
        }

        size_t GetSize(void) const {
            return data.GetSize();
        }

        std::string ToString(void) const {
            return std::string(data.GetPtr(), data.GetPtr() + data.GetSize());
        }

        std::string ToTrimmedString(void) const {
            auto s = ToString();
            trim_left_if(s, boost::is_any_of("0"));

            if ( s == "" ) {
                return "0";
            } else {
                return s;
            }
        }

        /* Prefix the string with a pseudo-random amount of zeroes */
        std::string ToString(Datasource& ds) const {
            std::string zeros;

            try {
                while ( ds.Get<bool>() == true ) {
                    zeros += "0";
                }
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

            return zeros + ToTrimmedString();
        }

        nlohmann::json ToJSON(void) const {
            return ToString();
        }
};

} /* namespace cryptofuzz */
