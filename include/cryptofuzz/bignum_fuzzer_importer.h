#pragma once

#include "../../third_party/json/json.hpp"
#include <string>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {

class Bignum_Fuzzer_Importer {
    public:
    private:
        const std::string filename;
        const std::string outDir;
        void write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2);
        void LoadInput(const std::vector<uint8_t> data);
    public:
        Bignum_Fuzzer_Importer(const std::string filename, const std::string outDir);
        void Run(void);
};

} /* namespace cryptofuzz */
