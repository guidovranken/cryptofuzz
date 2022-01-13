
/* Simple emulation of subtle crypto using crypto-js */
window.crypto.subtle = {};
window.crypto.subtle.importKey = function(x, key) {
    key = [...key].map(x => x.toString(16).padStart(2, '0')).join('');
    key = CryptoJS.enc.Hex.parse(key);
    return CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256.create(), key);
}
window.crypto.subtle.sign = function(x, key, msg) {
    msg = [...msg].map(x => x.toString(16).padStart(2, '0')).join('');
    msg = CryptoJS.enc.Hex.parse(msg);
    key.reset();
    key.update(msg);
    var ret = key.finalize().toString()
    ret = new Uint8Array(ret.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return ret;
}

var OpECC_PrivateToPublic = function(FuzzerInput) {
    var priv = BigInt(FuzzerInput['priv']);

    try {
        var pub = exports.getPublicKey(priv);
        pub = exports.Point.fromHex(pub);
        FuzzerOutput = JSON.stringify([pub.x.toString(), pub.y.toString()]);
    } catch ( e ) { }
}

var OpECDSA_Sign = async function(FuzzerInput) {
    var msg = FuzzerInput['cleartext'];
    var priv = BigInt(FuzzerInput['priv']);

    var signature = await exports.sign(msg, priv, {canonical : true});
    signature = exports.Signature.fromHex(signature);

    var pub = exports.getPublicKey(priv);
    pub = exports.Point.fromHex(pub);

    FuzzerOutput = JSON.stringify({
        'signature' : [signature.r.toString(), signature.s.toString()],
        'pub' : [pub.x.toString(), pub.y.toString()]});
}

var OpECDSA_Verify = function(FuzzerInput) {
    var msg = FuzzerInput['cleartext'];
    var x = BigInt(FuzzerInput['pub_x']);
    var y = BigInt(FuzzerInput['pub_y']);
    var r = BigInt(FuzzerInput['sig_r']);
    var s = BigInt(FuzzerInput['sig_s']);

    var verified = false;

    var pub = new exports.Point(x, y);

    try {
        var signature = new exports.Signature(r, s);

        verified = exports.verify(signature, msg, pub, { strict: false });
    } catch ( e ) { }

    FuzzerOutput = JSON.stringify(verified);

}

var OpECC_Point_Add = function(FuzzerInput) {
    var a_x = BigInt(FuzzerInput['a_x']);
    var a_y = BigInt(FuzzerInput['a_y']);

    var b_x = BigInt(FuzzerInput['b_x']);
    var b_y = BigInt(FuzzerInput['b_y']);

    try {
        var a = new exports.Point(a_x, a_y);
        var b = new exports.Point(b_x, b_y);

        a = JacobianPoint.fromAffine(a);

        b = JacobianPoint.fromAffine(b);

        var res = a.add(b).toAffine();

        a.assertValidity();
        b.assertValidity();
        res.assertValidity();

        FuzzerOutput = JSON.stringify([res.x.toString(), res.y.toString()]);
    } catch ( e ) { }
}

var OpECC_Point_Mul = function(FuzzerInput) {
    var x = BigInt(FuzzerInput['a_x']);
    var y = BigInt(FuzzerInput['a_y']);
    var b = BigInt(FuzzerInput['b']);

    try {
        var point = new exports.Point(x, y);

        var res = JacobianPoint.fromAffine(point).multiplyUnsafe(b).toAffine();

        point.assertValidity();

        FuzzerOutput = JSON.stringify([res.x.toString(), res.y.toString()]);
    } catch ( e ) { }
}

var OpECC_Point_Neg = function(FuzzerInput) {
    var x = BigInt(FuzzerInput['a_x']);
    var y = BigInt(FuzzerInput['a_y']);

    try {
        var point = new exports.Point(x, y);

        var res = JacobianPoint.fromAffine(point).negate(b).toAffine();

        FuzzerOutput = JSON.stringify([res.x.toString(), res.y.toString()]);
    } catch ( e ) { }
}

var OpECC_Point_Dbl = function(FuzzerInput) {
    var x = BigInt(FuzzerInput['a_x']);
    var y = BigInt(FuzzerInput['a_y']);

    try {
        var point = new exports.Point(x, y);

        var res = JacobianPoint.fromAffine(point).double(b).toAffine();

        FuzzerOutput = JSON.stringify([res.x.toString(), res.y.toString()]);
    } catch ( e ) { }
}

FuzzerInput = JSON.parse(FuzzerInput);
var operation = BigInt(FuzzerInput['operation']);

if ( IsECC_PrivateToPublic(operation) ) {
    OpECC_PrivateToPublic(FuzzerInput);
} else if ( IsECDSA_Sign(operation) ) {
    FuzzerOutput = OpECDSA_Sign(FuzzerInput);
} else if ( IsECDSA_Verify(operation) ) {
    OpECDSA_Verify(FuzzerInput);
} else if ( IsECC_Point_Add(operation) ) {
    OpECC_Point_Add(FuzzerInput);
} else if ( IsECC_Point_Mul(operation) ) {
    OpECC_Point_Mul(FuzzerInput);
} else if ( IsECC_Point_Neg(operation) ) {
    OpECC_Point_Neg(FuzzerInput);
} else if ( IsECC_Point_Dbl(operation) ) {
    OpECC_Point_Dbl(FuzzerInput);
}
