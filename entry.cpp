#include <cstddef>
#include <cstdint>
#include <memory>
#include "driver.h"

#include <modules/openssl/module.h>

#ifdef CRYPTOFUZZ_PUBLICDOMAIN
#include <modules/publicdomain/module.h>
#endif

#ifdef CRYPTOFUZZ_CPPCRYPTO
#include <modules/cppcrypto/module.h>
#endif

#ifdef CRYPTOFUZZ_MBEDTLS
#include <modules/mbedtls/module.h>
#endif

#ifdef CRYPTOFUZZ_BOOST
#include <modules/boost/module.h>
#endif

#ifdef CRYPTOFUZZ_MONERO
#include <modules/monero/module.h>
#endif

std::shared_ptr<cryptofuzz::Driver> driver = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    driver = std::make_shared<cryptofuzz::Driver>();

    driver->LoadModule( std::make_shared<cryptofuzz::module::OpenSSL>() );

#ifdef CRYPTOFUZZ_PUBLICDOMAIN
    driver->LoadModule( std::make_shared<cryptofuzz::module::PublicDomain>() );
#endif

#ifdef CRYPTOFUZZ_CPPCRYPTO
    driver->LoadModule( std::make_shared<cryptofuzz::module::CPPCrypto>() );
#endif

#ifdef CRYPTOFUZZ_MBEDTLS
    driver->LoadModule( std::make_shared<cryptofuzz::module::mbedTLS>() );
#endif

#ifdef CRYPTOFUZZ_BOOST
    driver->LoadModule( std::make_shared<cryptofuzz::module::Boost>() );
#endif

#ifdef CRYPTOFUZZ_MONERO
    driver->LoadModule( std::make_shared<cryptofuzz::module::Monero>() );
#endif

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    driver->Run(data, size);

    return 0;
}
