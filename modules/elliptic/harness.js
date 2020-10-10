FuzzerInput = JSON.parse(FuzzerInput);

var elliptic = thiss.elliptic;
var EC = elliptic.ec;

var parseHex = function(s) {
    var ret = [];

    for (var i = 0; i < s.length; i += 2) {
        ret.push(BigInt(s.slice(i, i+2), 16))
    }

    return ret;
}

var toCurve = function(curveType) {
    curveType = BigInt(curveType);
    if ( Issecp256k1(curveType) ) {
        return elliptic.curves.secp256k1;
    } else if ( Issecp224r1(curveType) ) {
        return elliptic.curves.p224;
    } else if ( Issecp384r1(curveType) ) {
        return elliptic.curves.p384;
    } else if ( Issecp521r1(curveType) ) {
        return elliptic.curves.p521;
    } else if ( Ised25519(curveType) ) {
        return elliptic.curves.ed25519;
    } else {
        return '';
    }
}

var OpECDSA_Sign = function(FuzzerInput) {
    if ( FuzzerInput['priv'] == '0' ) {
        return;
    }
    if ( FuzzerInput['cleartext'].length == 0 ) {
        return;
    }

    var curve = toCurve(FuzzerInput['curveType']);
    if ( curve == '' ) {
        return;
    }

    var sha256 = thiss.elliptic.curves.p192.hash;
    var ec = new EC({curve: curve, hash: sha256});
    var key = ec.keyFromPrivate(FuzzerInput['priv']);
    var message = parseHex(FuzzerInput['cleartext']);
    var digest = BigInt(FuzzerInput(['digest']));
    if ( IsNULL(digest) ) {
    } else if ( IsSHA256(digest) ) {
        message = sha256().update(message).digest();
    } else {
        return;
    }
    var signature = key.sign(msgHash);
    FuzzerOutput = JSON.stringify({
        'signature' : [signature.r.toString(10), signature.s.toString(10)],
        'pub' : [key.getPublic().x.toString(10), key.getPublic().y.toString(10)]});
}

/* https://stackoverflow.com/a/34310051 */
function toHexString(byteArray) {
  return Array.from(byteArray, function(B) {
    return ('0' + (B & 0xFF).toString(16)).slice(-2);
  }).join('')
}

var OpECDSA_Verify = function(FuzzerInput) {
    if ( FuzzerInput['pub_x'] == '0' ) {
        return;
    }
    if ( FuzzerInput['pub_y'] == '0' ) {
        return;
    }
    if ( FuzzerInput['sig_r'] == '0' ) {
        return;
    }
    if ( FuzzerInput['sig_y'] == '0' ) {
        return;
    }

    var curve = toCurve(FuzzerInput['curveType']);
    if ( curve == '' ) {
        return;
    }

    var ec = new EC({curve: curve});

    var key = ec.keyFromPublic({x: FuzzerInput['pub_x'], y: FuzzerInput['pub_y']});
    var sig = {r: FuzzerInput['sig_r'], s: FuzzerInput['sig_y']};
    var message = parseHex(FuzzerInput['cleartext']);
    var verified = key.verify(message, sig);

    FuzzerOutput = JSON.stringify(verified);
}

var OpECC_PrivateToPublic = function(FuzzerInput) {
    if ( FuzzerInput['priv'] == '0' ) {
        return;
    }
    if ( FuzzerInput['priv'].length > 100 ) {
        //return;
    }

    if ( Ised25519(BigInt(FuzzerInput['curveType'])) ) {
        var privBn = FuzzerInput['priv'];

        if ( privBn.length > 64 ) {
            return;
        }
        for (var i = privBn.length; i < 64; i++) {
            privBn = "0" + privBn;
        }
        var ed25519 = new elliptic.eddsa('ed25519');
        var key = ed25519.keyFromSecret(privBn);
        FuzzerOutput = JSON.stringify([toHexString(key.getPublic()), '0']);
    } else {
        var curve = toCurve(FuzzerInput['curveType']);
        if ( curve == '' ) {
            return;
        }

        var ec = new EC({curve: curve});
        var key = ec.keyFromPrivate(FuzzerInput['priv']);

        try {
            FuzzerOutput = JSON.stringify([
                key.getPublic().x.toString(10),
                key.getPublic().y.toString(10)]);
        } catch ( e ) { }
    }
}

var operation = BigInt(FuzzerInput['operation']);

if ( IsECDSA_Sign(operation) ) {
    OpECDSA_Sign(FuzzerInput);
} else if ( IsECDSA_Verify(operation) ) {
    OpECDSA_Verify(FuzzerInput);
} else if ( IsECC_PrivateToPublic(operation) ) {
    OpECC_PrivateToPublic(FuzzerInput);
}
