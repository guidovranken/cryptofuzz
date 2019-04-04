#pragma once

#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>

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

        uint64_t Get(void) const {
            return type;
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
};

} /* namespace cryptofuzz */
