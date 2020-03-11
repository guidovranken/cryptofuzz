#include <fuzzing/datasource/datasource.hpp>
#include <cryptofuzz/generic.h>
#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>

#if 0
int main(void)
{
    fuzzing::datasource::Datasource ds(nullptr, 0);
    int i = 10;
    ds.Put<>(i);

    const auto data = ds.GetOut();
    
    fuzzing::datasource::Datasource ds2(data.data(), data.size());
    auto i2 = ds2.Get<int>();
    printf("%d\n", i2);
    return 0;
}
#endif

template <class T>
void testType(const uint8_t *data, size_t size) {
    fuzzing::datasource::Datasource dsIn(data, size);
    fuzzing::datasource::Datasource dsOut(nullptr, 0);

    T v1(dsIn);
    v1.Serialize(dsOut);

    const auto serialized = dsOut.GetOut();

    try {
        fuzzing::datasource::Datasource dsIn2(serialized.data(), serialized.size());
        T v2(dsIn2);

        if ( !(v1 == v2) ) abort();
    } catch ( ... ) {
        abort();
    }
}

template <class T>
void testOperation(const uint8_t *data, size_t size) {
    fuzzing::datasource::Datasource dsIn(data, size);
    fuzzing::datasource::Datasource dsOut(nullptr, 0);

    cryptofuzz::component::Modifier modifier;
    T v1(dsIn, modifier);
    v1.Serialize(dsOut);

    const auto serialized = dsOut.GetOut();

    try {
        fuzzing::datasource::Datasource dsIn2(serialized.data(), serialized.size());
        T v2(dsIn2, modifier);

        if ( !(v1 == v2) ) abort();

        if ( dsIn2.Left() != 0 ) abort();
    } catch ( ... ) {
        abort();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    try {
        testType<cryptofuzz::Type>(data, size);
        testType<cryptofuzz::Buffer>(data, size);
        testType<cryptofuzz::Bignum>(data, size);
        testType<cryptofuzz::component::SymmetricCipher>(data, size);
        testType<cryptofuzz::component::Ciphertext>(data, size);
        testType<cryptofuzz::component::BignumPair>(data, size);
        testType<cryptofuzz::component::ECC_KeyPair>(data, size);
        testOperation<cryptofuzz::operation::Digest>(data, size);
        testOperation<cryptofuzz::operation::HMAC>(data, size);
        testOperation<cryptofuzz::operation::SymmetricEncrypt>(data, size);
        testOperation<cryptofuzz::operation::SymmetricDecrypt>(data, size);
        testOperation<cryptofuzz::operation::KDF_SCRYPT>(data, size);
        testOperation<cryptofuzz::operation::KDF_HKDF>(data, size);
        testOperation<cryptofuzz::operation::KDF_TLS1_PRF>(data, size);
        testOperation<cryptofuzz::operation::KDF_PBKDF>(data, size);
        testOperation<cryptofuzz::operation::KDF_PBKDF1>(data, size);
        testOperation<cryptofuzz::operation::KDF_PBKDF2>(data, size);
        testOperation<cryptofuzz::operation::KDF_ARGON2>(data, size);
        testOperation<cryptofuzz::operation::KDF_SSH>(data, size);
        testOperation<cryptofuzz::operation::KDF_X963>(data, size);
        testOperation<cryptofuzz::operation::CMAC>(data, size);
        testOperation<cryptofuzz::operation::ECC_PrivateToPublic>(data, size);
        testOperation<cryptofuzz::operation::ECC_GenerateKeyPair>(data, size);
        testOperation<cryptofuzz::operation::ECDSA_Sign>(data, size);
        testOperation<cryptofuzz::operation::ECDSA_Verify>(data, size);
        testOperation<cryptofuzz::operation::ECDH_Derive>(data, size);
        testOperation<cryptofuzz::operation::BignumCalc>(data, size);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
    return 0;
}
