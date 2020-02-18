var crypto = require('crypto')
var Buffer = require('buffer').Buffer;

var fromHexString = function(hexString) {
    return new Buffer(hexString, 'hex');
}

FuzzerInput = JSON.parse(FuzzerInput);

var toParts = function(modifier, input) {
    var ret = [];
    var modifierPos = 0;
    var pos = 0;

    while ( input.length - pos > 0 ) {
        var curLength = input.length - pos;

        if ( modifierPos + 3 <= modifier.length ) {
            var chunk = modifier.slice(modifierPos, modifierPos+3);
            var length = 0;
            length += chunk[0] << 16;
            length += chunk[1] << 8;
            length += chunk[2];

            curLength = length % (curLength+1);
            modifierPos += 3;
        }

        var slice = input.slice(pos, pos+curLength);
        ret.push(slice);
        pos += curLength;
    }

    return ret;
}

var toDigestString = function(digestType) {
    if ( IsMD5(digestType) ) {
        return 'md5';
    } else if ( IsSHA1(digestType) ) {
        return 'sha1';
    } else if ( IsSHA224(digestType) ) {
        return 'sha224';
    } else if ( IsSHA256(digestType) ) {
        return 'sha256';
    } else if ( IsSHA384(digestType) ) {
        return 'sha384';
    } else if ( IsSHA512(digestType) ) {
        return 'sha512';
    } else if ( IsRIPEMD160(digestType) ) {
        return 'rmd160';
    }

    throw "Invalid digest type";
}

var toCurveString = function(curveType) {
    if ( Issecp256k1(curveType) ) {
        return 'secp256k1';
    }
    throw "Invalid curve";

    /* Other curves are awfully slow */
    if ( Issecp256k1(curveType) ) {
        return 'secp256k1';
    } else if ( Issecp224r1(curveType) ) {
        return 'secp224r1';
    } else if ( Issecp256r1(curveType) ) {
        return 'prime256v1';
    } else if ( Issecp192r1(curveType) ) {
        return 'prime192v1';
    /* TODO
    } else if ( Ised25519(curveType) ) {
        return 'ed25519';
    */
    } else if ( Issecp384r1(curveType) ) {
        return 'secp384r1';
    } else if ( Issecp521r1(curveType) ) {
        return 'secp521r1';
    }

    throw "Invalid curve";
}

var OpDigest = function(FuzzerInput) {
    var digestType = parseInt(FuzzerInput['digestType']);
    var cleartext = fromHexString(FuzzerInput['cleartext']);
    var modifier = fromHexString(FuzzerInput['modifier']);

    var digestString;
    try {
        digestString = toDigestString(digestType);
    } catch ( e ) { return; }

    var parts = toParts(modifier, cleartext);
    var fn = crypto.createHash(digestString);
    parts.forEach(part => fn.update(part));
    var ret = fn.digest('hex');
    FuzzerOutput = JSON.stringify(ret);
}

var OpHMAC = function(FuzzerInput) {
    var digestType = parseInt(FuzzerInput['digestType']);
    var cleartext = fromHexString(FuzzerInput['cleartext']);
    var key = fromHexString(FuzzerInput['cipher']['key']);
    var modifier = fromHexString(FuzzerInput['modifier']);

    var digestString;
    try {
        digestString = toDigestString(digestType);
    } catch ( e ) { return; }

    var parts = toParts(modifier, cleartext);
    var fn = crypto.createHmac(digestString, key);
    parts.forEach(part => fn.update(part));
    var ret = fn.digest('hex');
    FuzzerOutput = JSON.stringify(ret);
}

var OpSymmetricEncrypt = function(FuzzerInput) {
    var cleartext = fromHexString(FuzzerInput['cleartext']);
    var cipherType = parseInt(FuzzerInput['cipher']['cipherType']);
    var key = fromHexString(FuzzerInput['cipher']['key']);
    var iv = fromHexString(FuzzerInput['cipher']['iv']);
    var aad = fromHexString(FuzzerInput['aad']);
    var tagSize = parseInt(FuzzerInput['tagSize']);
    
    /* TODO */
}

var OpSymmetricDecrypt = function(FuzzerInput) {
    var ciphertext = fromHexString(FuzzerInput['ciphertext']);
    var cipherType = parseInt(FuzzerInput['cipher']['cipherType']);
    var key = fromHexString(FuzzerInput['cipher']['key']);
    var iv = fromHexString(FuzzerInput['cipher']['iv']);
    var aad = fromHexString(FuzzerInput['aad']);
    var tag = fromHexString(FuzzerInput['tag']);

    /* TODO */
}

var OpKDF_PBKDF2 = function(FuzzerInput) {
    var digestType = parseInt(FuzzerInput['digestType']);
    var iterations = parseInt(FuzzerInput['iterations']);
    var keySize = parseInt(FuzzerInput['keySize']);
    var password = fromHexString(FuzzerInput['password']);
    var salt = fromHexString(FuzzerInput['salt']);
    var modifier = fromHexString(FuzzerInput['modifier']);

    if ( iterations == 0 ) return;

    var digestString;
    try {
        digestString = toDigestString(digestType);
    } catch ( e ) { return; }

    var derivedKey = crypto.pbkdf2Sync(password, salt, iterations, keySize, digestString).toString('hex');

    FuzzerOutput = JSON.stringify(derivedKey);
}

var OpKDF_SCRYPT = function(FuzzerInput) {
    /* not supported by crypto-browserify */
    return;

    var password = fromHexString(FuzzerInput['password']);
    var salt = fromHexString(FuzzerInput['salt']);
    var N = parseInt(FuzzerInput['N']);
    var r = parseInt(FuzzerInput['r']);
    var p = parseInt(FuzzerInput['p']);
    var keySize = parseInt(FuzzerInput['keySize']);
    var modifier = fromHexString(FuzzerInput['modifier']);

    if ( N == 0 || r == 0 || p == 0 ) {
        return;
    }

    crypto.scrypt(password, salt, keySize, { N: N, r : r, p : p }, (err, derivedKey) => {
        if (!err) {
            FuzzerOutput = JSON.stringify(derivedKey.toString('hex'));
        }
    });
}

var OpECC_PrivateToPublic = function(FuzzerInput) {
    var curveType = parseInt(FuzzerInput['curveType']);

    var curveString;
    try {
        curveString = toCurveString(curveType);
    } catch ( e ) { return; }

    var privBn = FuzzerInput["priv"];

    try {
        var ecdh = crypto.createECDH(curveString);
        ecdh.setPrivateKey(privBn, 'hex');

        var pub = ecdh.getPublicKey().toString('hex');
        var pubx = pub.substring(2, (pub.length - 2) / 2 + 2);
        var puby = pub.substring((pub.length - 2) / 2 + 2, pub.length);

        FuzzerOutput = JSON.stringify([pubx, puby]);
    } catch ( e ) { }
}

var operation = parseInt(FuzzerInput['operation']);

if ( IsDigest(operation) ) {
    OpDigest(FuzzerInput);
} else if ( IsHMAC(operation) ) {
    OpHMAC(FuzzerInput);
} else if ( IsSymmetricEncrypt(operation) ) {
    OpSymmetricEncrypt(FuzzerInput);
} else if ( IsSymmetricDecrypt(operation) ) {
    OpSymmetricDecrypt(FuzzerInput);
} else if ( IsKDF_PBKDF2(operation) ) {
    OpKDF_PBKDF2(FuzzerInput);
} else if ( IsKDF_SCRYPT(operation) ) {
    OpKDF_SCRYPT(FuzzerInput);
} else if ( IsECC_PrivateToPublic(operation) ) {
    OpECC_PrivateToPublic(FuzzerInput);
}
