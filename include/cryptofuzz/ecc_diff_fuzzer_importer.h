#pragma once

#include "../../third_party/json/json.hpp"
#include <string>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {

class ECC_Diff_Fuzzer_Importer {
    private:
        const std::string filename;
        const std::string outDir;
        void LoadInput(const std::vector<uint8_t> data);
        void write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2);
    public:
        ECC_Diff_Fuzzer_Importer(const std::string filename, const std::string outDir);
        void Run(void);
};

} /* namespace cryptofuzz */
