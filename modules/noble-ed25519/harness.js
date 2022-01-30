/* Simple emulation of subtle crypto using crypto-js */
crypto.web = {};
crypto.web.subtle = {};
crypto.web.subtle.digest = function(alg, msg) {
    var hasher = CryptoJS.algo.SHA512.create();
    msg = new Uint8Array(msg);
    msg = [...msg].map(x => x.toString(16).padStart(2, '0')).join('');
    msg = CryptoJS.enc.Hex.parse(msg);
    hasher.update(msg);
    var ret = hasher.finalize().toString()
    ret = new Uint8Array(ret.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return ret;
}

var OpECC_PrivateToPublic = async function(FuzzerInput) {
    var priv = BigInt(FuzzerInput['priv']);

    var pub = await exports.getPublicKey(priv);
    pub = [...pub].map(x => x.toString(16).padStart(2, '0')).join('');
    pub = BigInt('0x'.concat(pub)).toString(10);

    FuzzerOutput = JSON.stringify([pub, "0"]);
}

var OpECDSA_Sign = async function(FuzzerInput) {
    var msg = FuzzerInput['cleartext'];
    var priv = BigInt(FuzzerInput['priv']);

    var signature = await exports.sign(msg, priv, {canonical : true});

    var r = signature.slice(0, 64);
    r = BigInt('0x'.concat(r)).toString(10);

    var s = signature.slice(64, 128);
    s = BigInt('0x'.concat(s)).toString(10);

    var pub = await exports.getPublicKey(priv);
    pub = [...pub].map(x => x.toString(16).padStart(2, '0')).join('');
    pub = BigInt('0x'.concat(pub)).toString(10);

    FuzzerOutput = JSON.stringify({
        'signature' : [r, s],
        'pub' : [pub.toString(), '0']});
}

var OpECDSA_Verify = async function(FuzzerInput) {
    var msg = FuzzerInput['cleartext'];
    var x = BigInt(FuzzerInput['pub_x']);
    var y = BigInt(FuzzerInput['pub_y']);
    var r = BigInt(FuzzerInput['sig_r']);
    var s = BigInt(FuzzerInput['sig_s']);

    x = x.toString(16);
    x = '0'.repeat(64 - x.length) + x;

    r = r.toString(16);
    r = '0'.repeat(64 - r.length) + r;

    s = s.toString(16);
    s = '0'.repeat(64 - s.length) + s;

    var pub = exports.Point.fromHex(x);
    var signature = exports.Signature.fromHex(r + s);

    var verified = false;

    try {
        verified = await exports.verify(signature, msg, pub);
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
