#pragma once

#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <boost/algorithm/hex.hpp>
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

        /* TODO comparison operator */
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

        Buffer(const uint8_t* data, const size_t size) :
            data(data, data + size)
        { }

        Buffer(void) { }

        /* Copy constructor */
        Buffer(const Buffer& other) {
            data = other.data;
        }

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

} /* namespace cryptofuzz */
