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
            length += chunk.charCodeAt(0) << 16;
            length += chunk.charCodeAt(1) << 8;
            length += chunk.charCodeAt(2);

            curLength = length % (curLength+1);
            modifierPos += 3;
        }

        var slice = input.slice(pos, pos+curLength);
        ret.push(slice);
        pos += curLength;
    }

    return ret;
}

var processMultipart = function(obj, input, modifier) {
    input = toParts(modifier, input);

    input.forEach(function (curInput) {
        obj.update(curInput);
    });

    return obj.finalize().toString();
}

var digest = function(hasher, input, modifier) {
    return processMultipart(hasher, input, modifier);
}

var hmac = function(hasher, input, key, modifier) {
    var hmac = CryptoJS.algo.HMAC.create(hasher, key);
    return processMultipart(hmac, input, modifier);
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
    } /*else if ( IsSHA3(digestType) ) {
        return CryptoJS.algo.SHA3.create();
    }*/

    throw "Invalid digest type";
}

function hex2a(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2) str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

var OpDigest = function(FuzzerInput) {
    var digestType = parseInt(FuzzerInput['digestType']);
    var cleartext = hex2a(FuzzerInput['cleartext']);
    var modifier = hex2a(FuzzerInput['modifier']);

    try {
        var ret = digest(toHasher(digestType), cleartext, modifier);
        if ( (cleartext.length % 16) == 0 ) {
            FuzzerOutput = JSON.stringify(ret);
        }
    } catch ( e ) { }
}

var OpHMAC = function(FuzzerInput) {
    var digestType = parseInt(FuzzerInput['digestType']);
    var cleartext = hex2a(FuzzerInput['cleartext']);
    var key = hex2a(FuzzerInput['cipher']['key']);
    var modifier = hex2a(FuzzerInput['modifier']);

    try {
        var ret = hmac(toHasher(digestType), cleartext, key, modifier);
        //FuzzerOutput = JSON.stringify(ret);
    } catch ( e ) { }
}

var OpPBKDF2 = function(FuzzerInput) {
    var digestType = parseInt(FuzzerInput['digestType']);
    var password = hex2a(FuzzerInput['password']);
    var salt = hex2a(FuzzerInput['salt']);
    var iterations = parseInt(FuzzerInput['iterations']);
    var keySize = parseInt(FuzzerInput['keySize']);

    /* CryptoJS.PBKDF2 expects key size in words (4 bytes) */
    if ( keySize % 4 != 0 ) {
        return;
    }
    keySize /= 4;

    try {
        var ret = CryptoJS.PBKDF2(password, salt, {keySize : keySize, iterations : iterations, hasher : toHasher(digestType)}).toString();
        //FuzzerOutput = JSON.stringify(ret);
    } catch ( e ) { }
}

var operation = parseInt(FuzzerInput['operation']);

if ( IsDigest(operation) ) {
    OpDigest(FuzzerInput);
} else if ( IsHMAC(operation) ) {
    OpHMAC(FuzzerInput);
} else if ( IsKDF_PBKDF2(operation) ) {
    OpPBKDF2(FuzzerInput);
}
