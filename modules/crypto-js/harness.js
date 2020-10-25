FuzzerInput = JSON.parse(FuzzerInput);

var processMultipart = function(obj, input) {
    input.forEach(function (curInput) {
        obj.update(curInput);
    });

    return obj.finalize().toString();
}

var digest = function(hasher, input) {
    return processMultipart(hasher, input);
}

var hmac = function(hasher, input, key) {
    var hmac = CryptoJS.algo.HMAC.create(hasher, key);
    return processMultipart(hmac, input);
}

var toHasher = function(digestType) {
    if ( IsMD5(digestType) ) {
        return CryptoJS.algo.MD5.create();
    } else if ( IsRIPEMD160(digestType) ) {
        return CryptoJS.algo.RIPEMD160.create();
    } else if ( IsSHA1(digestType) ) {
        return CryptoJS.algo.SHA1.create();
    } else if ( IsSHA224(digestType) ) {
        return CryptoJS.algo.SHA224.create();
    } else if ( IsSHA256(digestType) ) {
        return CryptoJS.algo.SHA256.create();
    } else if ( IsSHA384(digestType) ) {
        return CryptoJS.algo.SHA384.create();
    } else if ( IsSHA512(digestType) ) {
        return CryptoJS.algo.SHA512.create();
    }

    return false;
}

var OpDigest = function(FuzzerInput) {
    var digestType = BigInt(FuzzerInput['digestType']);
    var cleartext = [];
    FuzzerInput['cleartext'].forEach(function (curInput) {
        cleartext.push( CryptoJS.enc.Hex.parse(curInput) );
    });

    var hasher = toHasher(digestType);
    if ( !hasher ) {
        return;
    }

    var ret = digest(hasher, cleartext);
    FuzzerOutput = JSON.stringify(ret);
}

var OpHMAC = function(FuzzerInput) {
    var digestType = BigInt(FuzzerInput['digestType']);
    var cleartext = [];
    FuzzerInput['cleartext'].forEach(function (curInput) {
        cleartext.push( CryptoJS.enc.Hex.parse(curInput) );
    });
    var key = CryptoJS.enc.Hex.parse(FuzzerInput['cipher']['key']);

    var hasher = toHasher(digestType);
    if ( !hasher ) {
        return;
    }

    var ret = hmac(hasher, cleartext, key);
    FuzzerOutput = JSON.stringify(ret);
}

var OpPBKDF2 = function(FuzzerInput) {
    var keySize = parseInt(FuzzerInput['keySize']);
    /* CryptoJS.PBKDF2 expects key size in words (4 bytes) */
    if ( keySize % 4 != 0 ) {
        return;
    }

    var digestType = BigInt(FuzzerInput['digestType']);
    var password = CryptoJS.enc.Hex.parse(FuzzerInput['password']);
    var salt = CryptoJS.enc.Hex.parse(FuzzerInput['salt']);
    var iterations = BigInt(FuzzerInput['iterations']);

    keySize /= 4;

    var hasher = toHasher(digestType);
    if ( !hasher ) {
        return;
    }

    var ret = CryptoJS.PBKDF2(password, salt, {keySize : keySize, iterations : iterations, hasher : hasher}).toString();
    FuzzerOutput = JSON.stringify(ret);
}

var processMultipartCipher = function(obj, input) {
    var ret;
    var out;
    var first = true;

    input.forEach(function (curInput) {
        if ( first == true ) {
            out = obj.process(curInput);
            first = false;
        } else {
            out.concat(obj.process(curInput));
        }
    });

    if ( first == false ) {
        out.concat(obj.finalize());
        ret = out.toString();
    } else {
        ret = obj.finalize().toString();
    }

    return ret;
}

var OpSymmetricEncrypt = function(FuzzerInput) {
    var cipherType = BigInt(FuzzerInput['cipher']['cipherType']);
    var cleartext;
    if ( IsRC4(cipherType) || IsRABBIT(cipherType) ) {
        cleartext = [];
        FuzzerInput['cleartext'].forEach(function (curInput) {
            cleartext.push( CryptoJS.enc.Hex.parse(curInput) );
        });
    } else {
        cleartext = CryptoJS.enc.Hex.parse(FuzzerInput['cleartext']);
    }

    var key = CryptoJS.enc.Hex.parse(FuzzerInput['cipher']['key']);
    var keySize = FuzzerInput['cipher']['key'].length / 2;

    var iv = CryptoJS.enc.Hex.parse(FuzzerInput['cipher']['iv']);

    var ret;

    if ( IsAES_128_ECB(cipherType) || IsAES_192_ECB(cipherType) || IsAES_256_ECB(cipherType) ) {
        /* XXX Fails to decrypt */
        //ret = CryptoJS.AES.encrypt(cleartext, key, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsAES_128_CFB(cipherType) || IsAES_192_CFB(cipherType) || IsAES_256_CFB(cipherType) ) {
        ret = CryptoJS.AES.encrypt(cleartext, key, {iv: iv, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsAES_128_CTR(cipherType) || IsAES_192_CTR(cipherType) || IsAES_256_CTR(cipherType) ) {
        /* XXX Discrepancy */
        //ret = CryptoJS.AES.encrypt(cleartext, key, {iv: iv, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsAES_128_CBC(cipherType) || IsAES_192_CBC(cipherType) || IsAES_256_CBC(cipherType) ) {
        /* XXX Padding */
        //ret = CryptoJS.AES.encrypt(cleartext, key, {iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Iso10126 }).toString();
    } else if ( IsAES_128_OFB(cipherType) || IsAES_192_OFB(cipherType) || IsAES_256_OFB(cipherType) ) {
        ret = CryptoJS.AES.encrypt(cleartext, key, {iv: iv, mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsRC4(cipherType) ) {
        var rc4 = CryptoJS.algo.RC4.createEncryptor(key);
        ret = processMultipartCipher(rc4, cleartext);
    } else if ( IsRABBIT(cipherType) ) {
        var rabbit = CryptoJS.algo.Rabbit.createEncryptor(key, {iv: iv});
        ret = processMultipartCipher(rabbit, cleartext);
    }

    if ( typeof(ret) !== 'undefined' ) {
        FuzzerOutput = JSON.stringify(ret);
    }
}

var OpSymmetricDecrypt = function(FuzzerInput) {
    var cipherType = BigInt(FuzzerInput['cipher']['cipherType']);
    var ciphertext = {};
    if ( IsRC4(cipherType) || IsRABBIT(cipherType) ) {
        ciphertext.ciphertext = [];
        FuzzerInput['ciphertext'].forEach(function (curInput) {
            ciphertext.ciphertext.push( CryptoJS.enc.Hex.parse(curInput) );
        });
    } else {
        ciphertext.ciphertext = CryptoJS.enc.Hex.parse(FuzzerInput['ciphertext']);
    }

    var key = CryptoJS.enc.Hex.parse(FuzzerInput['cipher']['key']);
    var keySize = FuzzerInput['cipher']['key'].length / 2;

    var iv = CryptoJS.enc.Hex.parse(FuzzerInput['cipher']['iv']);

    var ret;

    if ( IsAES_128_ECB(cipherType) || IsAES_192_ECB(cipherType) || IsAES_256_ECB(cipherType) ) {
        ret = CryptoJS.AES.decrypt(ciphertext, key, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsAES_128_CFB(cipherType) || IsAES_192_CFB(cipherType) || IsAES_256_CFB(cipherType) ) {
        ret = CryptoJS.AES.decrypt(ciphertext, key, {iv: iv, mode: CryptoJS.mode.CFB, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsAES_128_CTR(cipherType) || IsAES_192_CTR(cipherType) || IsAES_256_CTR(cipherType) ) {
        /* XXX Discrepancy */
        //ret = CryptoJS.AES.decrypt(ciphertext, key, {iv: iv, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsAES_128_CBC(cipherType) || IsAES_192_CBC(cipherType) || IsAES_256_CBC(cipherType) ) {
        /* XXX Padding */
        ret = CryptoJS.AES.decrypt(ciphertext, key, {iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Iso10126 }).toString();
    } else if ( IsAES_128_OFB(cipherType) || IsAES_192_OFB(cipherType) || IsAES_256_OFB(cipherType) ) {
        ret = CryptoJS.AES.decrypt(ciphertext, key, {iv: iv, mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.NoPadding }).toString();
    } else if ( IsRC4(cipherType) ) {
        var rc4 = CryptoJS.algo.RC4.createDecryptor(key);
        ret = processMultipartCipher(rc4, ciphertext.ciphertext);
    } else if ( IsRABBIT(cipherType) ) {
        var rabbit = CryptoJS.algo.Rabbit.createDecryptor(key, {iv: iv});
        ret = processMultipartCipher(rabbit, ciphertext.ciphertext);
    }

    if ( typeof(ret) !== 'undefined' ) {
        FuzzerOutput = JSON.stringify(ret);
    }
}

var operation = BigInt(FuzzerInput['operation']);

if ( IsDigest(operation) ) {
    OpDigest(FuzzerInput);
} else if ( IsHMAC(operation) ) {
    OpHMAC(FuzzerInput);
} else if ( IsKDF_PBKDF2(operation) ) {
    OpPBKDF2(FuzzerInput);
} else if ( IsSymmetricEncrypt(operation) ) {
    OpSymmetricEncrypt(FuzzerInput);
} else if ( IsSymmetricDecrypt(operation) ) {
    OpSymmetricDecrypt(FuzzerInput);
}
