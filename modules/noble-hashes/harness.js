var OpDigest = function(FuzzerInput) {
    var digestType = BigInt(FuzzerInput['digestType']);

    var hashFn = ToHashFn(digestType);
    if ( hashFn == undefined ) {
        return;
    }

    var res;

    if ( FuzzerInput['haveParts'] == false ) {
        res = hashFn(
                HexToBytes(FuzzerInput['cleartext'])
        );
    } else {
        var hasher = hashFn.init();

        for (var i = 0; i < FuzzerInput['parts'].length; i++) {
            hasher.update(
                HexToBytes(FuzzerInput['parts'][i])
            );
        }

        res = hasher.digest();
    }

    FuzzerOutput = JSON.stringify(BytesToHex(res));
}

var OpHMAC = function(FuzzerInput) {
    var digestType = BigInt(FuzzerInput['digestType']);

    var hashFn = ToHashFn(digestType);
    if ( hashFn == undefined ) {
        return;
    }

    var res;

    if ( FuzzerInput['haveParts'] == false ) {
        var res = exports.hmac(
            hashFn,
            HexToBytes(FuzzerInput['cipher']['key']),
            HexToBytes(FuzzerInput['cleartext'])
        );
    } else {
        var hasher = exports.hmac.init(
            hashFn,
            HexToBytes(FuzzerInput['cipher']['key'])
        );

        for (var i = 0; i < FuzzerInput['parts'].length; i++) {
            hasher.update(
                HexToBytes(FuzzerInput['parts'][i])
            );
        }

        res = hasher.digest();
    }

    FuzzerOutput = JSON.stringify(BytesToHex(res));
}

var OpHKDF = function(FuzzerInput) {
    var digestType = BigInt(FuzzerInput['digestType']);

    var hashFn = ToHashFn(digestType);
    if ( hashFn == undefined ) {
        return;
    }

    try {
        FuzzerOutput = JSON.stringify(
            BytesToHex(
                exports.hkdf(
                    hashFn,
                    HexToBytes(FuzzerInput['password']),
                    HexToBytes(FuzzerInput['salt']),
                    HexToBytes(FuzzerInput['info']),
                    parseInt(FuzzerInput['keySize']),
                )
            )
        );
    } catch ( e ) { }
}

var OpPBKDF2 = function(FuzzerInput) {
    var digestType = BigInt(FuzzerInput['digestType']);

    var hashFn = ToHashFn(digestType);
    if ( hashFn == undefined ) {
        return;
    }

    var iterations = parseInt(FuzzerInput['iterations']);
    if ( iterations < 1 ) {
        return;
    }
    FuzzerOutput = JSON.stringify(
        BytesToHex(
            exports.pbkdf2(
                hashFn,
                HexToBytes(FuzzerInput['password']),
                HexToBytes(FuzzerInput['salt']),
                {
                    c: iterations,
                    dkLen: parseInt(FuzzerInput['keySize'])
                }
            )
        )
    );
}

FuzzerInput = JSON.parse(FuzzerInput);
var operation = BigInt(FuzzerInput['operation']);

var ToHashFn = function(digestType) {
    var hashfn = undefined;
    if ( IsSHA256(digestType) ) {
        hashfn = exports.sha256;
    } else if ( IsSHA512(digestType) ) {
        hashfn = exports.sha512;
    } else if ( IsRIPEMD160(digestType) ) {
        hashfn = exports.ripemd160;
    } else if ( IsBLAKE2S256(digestType) ) {
        hashfn = exports.blake2s;
    } else if ( IsBLAKE2B512(digestType) ) {
        hashfn = exports.blake2b;
    } else if ( IsSHA3_224(digestType) ) {
        hashfn = exports.sha3_224;
    } else if ( IsSHA3_256(digestType) ) {
        hashfn = exports.sha3_256;
    } else if ( IsSHA3_384(digestType) ) {
        hashfn = exports.sha3_384;
    } else if ( IsSHA3_512(digestType) ) {
        hashfn = exports.sha3_512;
    } else if ( IsKECCAK_224(digestType) ) {
        hashfn = exports.keccak_224;
    } else if ( IsKECCAK_256(digestType) ) {
        hashfn = exports.keccak_256;
    } else if ( IsKECCAK_384(digestType) ) {
        hashfn = exports.keccak_384;
    } else if ( IsKECCAK_512(digestType) ) {
        hashfn = exports.keccak_512;
    }

    return hashfn;
}

var HexToBytes = function(hex) {
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}

var BytesToHex = function(bytes) {
    bytes = new Uint8Array(bytes);
    bytes = [...bytes].map(x => x.toString(16).padStart(2, '0')).join('');
    return bytes;
}

if ( IsDigest(operation) ) {
    OpDigest(FuzzerInput)
} else if ( IsHMAC(operation) ) {
    OpHMAC(FuzzerInput)
} else if ( IsKDF_HKDF(operation) ) {
    OpHKDF(FuzzerInput)
} else if ( IsKDF_PBKDF2(operation) ) {
    OpPBKDF2(FuzzerInput)
}
