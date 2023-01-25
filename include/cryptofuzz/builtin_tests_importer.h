#pragma once

#include "../../third_party/json/json.hpp"
#include <string>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {

class Builtin_tests_importer {
    public:
    private:
        const std::string outDir;
        void ecdsa_verify_tests(void);
        void ecc_point_add_tests(void);
        void write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2);
    public:
        Builtin_tests_importer(const std::string outDir);
        void Run(void);
};

} /* namespace cryptofuzz */
