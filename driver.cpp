#include "driver.h"
#include <fuzzing/datasource/id.hpp>
#include "tests.h"
#include "executor.h"
#include <cryptofuzz/util.h>
#include <set>
#include <unistd.h>

namespace cryptofuzz {

void Driver::LoadModule(std::shared_ptr<Module> module) {
    modules[module->ID] = module;
}

void Driver::Run(const uint8_t* data, const size_t size) const {
    using fuzzing::datasource::ID;

    static ExecutorDigest executorDigest(ID("Cryptofuzz/Operation/Digest"), modules, debug);
    static ExecutorHMAC executorHMAC(ID("Cryptofuzz/Operation/HMAC"), modules, debug);
    static ExecutorCMAC executorCMAC(ID("Cryptofuzz/Operation/CMAC"), modules, debug);
    static ExecutorSymmetricEncrypt executorSymmetricEncrypt(ID("Cryptofuzz/Operation/SymmetricEncrypt"), modules, debug);
    static ExecutorSymmetricDecrypt executorSymmetricDecrypt(ID("Cryptofuzz/Operation/SymmetricDecrypt"), modules, debug);
    static ExecutorKDF_SCRYPT executorKDF_SCRYPT(ID("Cryptofuzz/Operation/KDF_SCRYPT"), modules, debug);
    static ExecutorKDF_HKDF executorKDF_HKDF(ID("Cryptofuzz/Operation/KDF_HKDF"), modules, debug);
    static ExecutorKDF_TLS1_PRF executorKDF_TLS1_PRF(ID("Cryptofuzz/Operation/KDF_TLS1_PRF"), modules, debug);
    static ExecutorKDF_PBKDF2 executorKDF_PBKDF2(ID("Cryptofuzz/Operation/KDF_PBKDF2"), modules, debug);
    static ExecutorSign executorSign(ID("Cryptofuzz/Operation/Sign"), modules, debug);
    static ExecutorVerify executorVerify(ID("Cryptofuzz/Operation/Verify"), modules, debug);

    try {

        Datasource ds(data, size);

        const auto operation = ds.Get<uint64_t>();
        const auto payload = ds.GetData(0, 1);

        switch ( operation ) {
            case    ID("Cryptofuzz/Operation/Digest"):
                executorDigest.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/HMAC"):
                executorHMAC.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/CMAC"):
                executorCMAC.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/SymmetricEncrypt"):
                executorSymmetricEncrypt.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/SymmetricDecrypt"):
                executorSymmetricDecrypt.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/KDF_SCRYPT"):
                executorKDF_SCRYPT.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/KDF_HKDF"):
                executorKDF_HKDF.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/KDF_TLS1_PRF"):
                executorKDF_TLS1_PRF.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/KDF_PBKDF2"):
                executorKDF_PBKDF2.Run(ds, payload.data(), payload.size());
                break;
#if 0
            case    ID("Cryptofuzz/Operation/Sign"):
                executorSign.Run(ds, payload.data(), payload.size());
                break;
            case    ID("Cryptofuzz/Operation/Verify"):
                executorVerify.Run(ds, payload.data(), payload.size());
                break;
#endif
        }
    } catch ( Datasource::OutOfData ) {
    }
};

Driver::Driver(const bool debug) :
    debug(debug)
{ }

} /* namespace cryptofuzz */
