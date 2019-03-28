#pragma once

#include <cryptofuzz/generic.h>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {
namespace component {

using SymmetricCipherType = Type;
using AsymmetricCipherType = Type;
using DigestType = Type;
using KDFType = Type;

using Modifier = Buffer;
using Cleartext = Buffer;
using Digest = Buffer;
using MAC = Buffer;
using Ciphertext = Buffer;
using SymmetricIV = Buffer;
using SymmetricKey = Buffer;
using AsymmetricPrivKey = Buffer;
using Key = Buffer;
using Envelope = Buffer;
using Signature = Buffer;
using PrivateKeyPEM = Buffer;

class SymmetricCipher {
    public:
        const SymmetricIV iv;
        const SymmetricKey key;
        const SymmetricCipherType cipherType;
        SymmetricCipher(Datasource& ds) :
            iv(ds),
            key(ds),
            cipherType(ds)
        { }
};

class AsymmetricCipher {
    public:
        const AsymmetricPrivKey privKey;
        const AsymmetricCipherType cipherType;
        AsymmetricCipher(Datasource& ds) :
            privKey(ds),
            cipherType(ds)
        { }
};

} /* namespace component */
} /* namespace cryptofuzz */
