
var OpECC_PrivateToPublic = function(FuzzerInput) {
    var priv = BigInt(FuzzerInput['priv']);

    try {
        var pub = exports.getPublicKey(priv);
        pub = exports.Point.fromHex(pub);
        FuzzerOutput = JSON.stringify([pub.x.toString(), pub.y.toString()]);
    } catch ( e ) { }
}

var OpECDSA_Sign = async function(FuzzerInput) {
    /* TODO */
    return;

    var msg = FuzzerInput['cleartext'];
    var priv = BigInt(FuzzerInput['priv']);

    var signature = await exports.sign(msg, priv);
}

var OpECDSA_Verify = function(FuzzerInput) {
    var msg = FuzzerInput['cleartext'];
    var x = BigInt(FuzzerInput['pub_x']);
    var y = BigInt(FuzzerInput['pub_y']);
    var r = BigInt(FuzzerInput['sig_r']);
    var s = BigInt(FuzzerInput['sig_s']);

    var pub = new exports.Point(x, y);
    var signature = new exports.Signature(r, s);

    var verified = false;

    try {
        verified = exports.verify(signature, msg, pub);
    } catch ( e ) { }

    FuzzerOutput = JSON.stringify(verified);

}

FuzzerInput = JSON.parse(FuzzerInput);
var operation = BigInt(FuzzerInput['operation']);

if ( IsECC_PrivateToPublic(operation) ) {
    OpECC_PrivateToPublic(FuzzerInput);
} else if ( IsECDSA_Sign(operation) ) {
    OpECDSA_Sign(FuzzerInput);
} else if ( IsECDSA_Verify(operation) ) {
    OpECDSA_Verify(FuzzerInput);
}
