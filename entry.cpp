#include <cstddef>
#include <cstdint>
#include <memory>
#include "driver.h"

#include <modules/openssl/module.h>
//#include <modules/publicdomain/module.h>
//#include <modules/cppcrypto/module.h>
//#include <modules/mbedtls/module.h>
//#include <modules/boost/module.h>
//#include <modules/monero/module.h>

std::shared_ptr<cryptofuzz::Driver> driver = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    driver = std::make_shared<cryptofuzz::Driver>();

    driver->LoadModule( std::make_shared<cryptofuzz::module::OpenSSL>() );
    //driver->LoadModule( std::make_shared<cryptofuzz::module::mbedTLS>() );
    //driver->LoadModule( std::make_shared<cryptofuzz::module::Boost>() );
    //driver->LoadModule( std::make_shared<cryptofuzz::module::PublicDomain>() );
    //driver->LoadModule( std::make_shared<cryptofuzz::module::CPPCrypto>() );
    //driver->LoadModule( std::make_shared<cryptofuzz::module::Monero>() );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    driver->Run(data, size);

    return 0;
}
