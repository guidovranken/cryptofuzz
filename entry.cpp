#include <cstddef>
#include <cstdint>
#include <memory>
#include "driver.h"

#include <modules/openssl/module.h>

#if defined(CRYPTOFUZZ_BITCOIN)
  #include <modules/bitcoin/module.h>
#endif

#if defined(CRYPTOFUZZ_REFERENCE)
  #include <modules/reference/module.h>
#endif

#if defined(CRYPTOFUZZ_CPPCRYPTO)
  #include <modules/cppcrypto/module.h>
#endif

#if defined(CRYPTOFUZZ_MBEDTLS)
  #include <modules/mbedtls/module.h>
#endif

#if defined(CRYPTOFUZZ_BOOST)
  #include <modules/boost/module.h>
#endif

#if defined(CRYPTOFUZZ_MONERO)
  #include <modules/monero/module.h>
#endif

#if defined(CRYPTOFUZZ_VERACRYPT)
  #include <modules/veracrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBSODIUM)
  #include <modules/libsodium/module.h>
#endif

#if defined(CRYPTOFUZZ_CRYPTOPP)
  #include <modules/cryptopp/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBGCRYPT)
  #include <modules/libgcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_EVERCRYPT)
  #include <modules/evercrypt/module.h>
#endif

std::shared_ptr<cryptofuzz::Driver> driver = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    bool debug = false;

    for (int i = 1; i < *argc; i++) {
        const std::string arg((*argv)[i]);

        if ( arg == "--debug") {
            debug = true;
        }
    }

    driver = std::make_shared<cryptofuzz::Driver>(debug);

    driver->LoadModule( std::make_shared<cryptofuzz::module::OpenSSL>() );

#if defined(CRYPTOFUZZ_BITCOIN)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Bitcoin>() );
#endif

#if defined(CRYPTOFUZZ_REFERENCE)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Reference>() );
#endif

#if defined(CRYPTOFUZZ_CPPCRYPTO)
    driver->LoadModule( std::make_shared<cryptofuzz::module::CPPCrypto>() );
#endif

#if defined(CRYPTOFUZZ_MBEDTLS)
    driver->LoadModule( std::make_shared<cryptofuzz::module::mbedTLS>() );
#endif

#if defined(CRYPTOFUZZ_BOOST)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Boost>() );
#endif

#if defined(CRYPTOFUZZ_MONERO)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Monero>() );
#endif

#if defined(CRYPTOFUZZ_VERACRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Veracrypt>() );
#endif

#if defined(CRYPTOFUZZ_LIBSODIUM)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libsodium>() );
#endif

#if defined(CRYPTOFUZZ_CRYPTOPP)
    driver->LoadModule( std::make_shared<cryptofuzz::module::CryptoPP>() );
#endif

#if defined(CRYPTOFUZZ_LIBGCRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libgcrypt>() );
#endif

#if defined(CRYPTOFUZZ_EVERCRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::EverCrypt>() );
#endif
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    driver->Run(data, size);

    return 0;
}
