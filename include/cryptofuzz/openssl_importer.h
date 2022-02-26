#pragma once

#include "../../third_party/json/json.hpp"
#include <string>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {

class OpenSSL_Importer {
    public:
        enum type {
            ExpMod,
            Div,
        };
    private:
        const std::string filename;
        const std::string outDir;
        enum type t;
        void LoadInput(const std::vector<uint8_t> data);
        void write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2);
    public:
        OpenSSL_Importer(const std::string filename, const std::string outDir, const enum type t);
        void Run(void);
};

} /* namespace cryptofuzz */
