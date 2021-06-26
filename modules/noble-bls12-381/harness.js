/* Simple emulation of subtle crypto using crypto-js */
window.crypto.subtle = {};
window.crypto.subtle.digest = function(alg, msg) {
    var hasher = CryptoJS.algo.SHA256.create();
    msg = new Uint8Array(msg);
    msg = [...msg].map(x => x.toString(16).padStart(2, '0')).join('');
    msg = CryptoJS.enc.Hex.parse(msg);
    hasher.update(msg);
    var ret = hasher.finalize().toString()
    ret = new Uint8Array(ret.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return ret;
}

var HexToDec = function(hex) {
    return BigInt('0x'.concat(hex)).toString(10);
}

var HexToBytes = function(hex) {
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}

var SetDST = function(dst) {
    dst = HexToBytes(dst);
    var ret = '';
    for (var i = 0; i < dst.length; i++) {
        if ( dst[i] >= 128 ) {
            return false;
        }
        ret += String.fromCharCode(dst[i]);
    }

    try {
        exports.utils.setDSTLabel(ret);
    } catch ( e ) {
        return false;
    }

    return true;
}

var To_G1 = function(x, y) {
    var x = BigInt(x);
    var y = BigInt(y);
    return new exports.PointG1(new Fp(x), new Fp(y), new Fp(1n));
}

var From_G1 = function(g1) {
    var affine = g1.toAffine();

    var x = affine[0].value.toString(10);
    var y = affine[1].value.toString(10);

    return [x, y];
}

var To_G2 = function(x, y, v, w) {
    var x1 = BigInt(v);
    var y1 = BigInt(w);
    var x2 = BigInt(x);
    var y2 = BigInt(y);
    return new exports.PointG2(new Fp2([x1, y1]), new Fp2([x2, y2]), Fp2.ONE);
}

var From_G2 = function(g2) {
    var affine = g2.toAffine();

    var x1 = affine[0].values[0].toString(10);
    var y1 = affine[1].values[0].toString(10);
    var x2 = affine[0].values[1].toString(10);
    var y2 = affine[1].values[1].toString(10);

    return [ [x1, y1], [x2, y2] ];
}

var OpBLS_PrivateToPublic = function(FuzzerInput) {
    var priv = BigInt(FuzzerInput['priv']);

    try {
        var pub = exports.getPublicKey(priv);
        pub = exports.PointG1.fromHex(pub);

        FuzzerOutput = JSON.stringify([pub.x.value.toString(), pub.y.value.toString()]);
    } catch ( e ) { }
}

var OpBLS_HashToG1 = async function(FuzzerInput) {
    /* XXX unsupported? */
    return;
}

var OpBLS_HashToG2 = async function(FuzzerInput) {
    if ( SetDST(FuzzerInput['dest']) == false ) {
        return;
    }

    try {
        var msg = FuzzerInput['aug'] + FuzzerInput['cleartext'];

        var res = await exports.PointG2.hashToCurve(msg);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { console.log(e); }
}

var OpBLS_Sign = async function(FuzzerInput) {
    if ( SetDST(FuzzerInput['dest']) == false ) {
        return;
    }

    var msg;
    if ( FuzzerInput['hashOrPoint'] == true ) {
        msg = FuzzerInput['aug'] + FuzzerInput['cleartext'];
    } else {
        msg = To_G2(FuzzerInput['g2_v'], FuzzerInput['g2_x'], FuzzerInput['g2_w'], FuzzerInput['g2_y']);
    }

    var priv = BigInt(FuzzerInput['priv']);

    try {
        var pub = exports.getPublicKey(priv);
        pub = exports.PointG1.fromHex(pub);

        var signature = await exports.sign(msg, priv);

        if ( FuzzerInput['hashOrPoint'] == true ) {
            signature = exports.PointG2.fromSignature(signature);
        }

        var affine = signature.toAffine();

        var x1 = affine[0].values[0].toString(10);
        var y1 = affine[1].values[0].toString(10);
        var x2 = affine[0].values[1].toString(10);
        var y2 = affine[1].values[1].toString(10);

        FuzzerOutput = JSON.stringify({
            'signature' : [
                [x1, y1], [x2, y2]
            ],
            'pub' : [
                pub.x.value.toString(),
                pub.y.value.toString()]
        });
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Verify = async function(FuzzerInput) {
    if ( SetDST(FuzzerInput['dest']) == false ) {
        return;
    }

    try {
        var pub = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);
        var sig = To_G2(FuzzerInput['g2_w'], FuzzerInput['g2_y'], FuzzerInput['g2_v'], FuzzerInput['g2_x']);
        var msg = FuzzerInput['cleartext'];

        var res = await exports.verify(sig, msg, pub);

        FuzzerOutput = JSON.stringify(res);
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Compress_G1 = async function(FuzzerInput) {
    var g1 = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);

    try {
        g1.assertValidity();
    } catch ( e ) {
        return;
    }

    var compressed = g1.toHex(true);
    compressed = HexToDec(compressed);

    FuzzerOutput = JSON.stringify(compressed);
}

var OpBLS_Decompress_G1 = async function(FuzzerInput) {
    var compressed = BigInt(FuzzerInput['compressed']).toString(16);
    if ( compressed.length > 96 ) {
        return;
    }

    compressed = '0'.repeat(96 - compressed.length) + compressed;

    var g1 = exports.PointG1.fromHex(compressed);

    try {
        g1.assertValidity();
    } catch ( e ) {
        return;
    }

    return; /* XXX */
    FuzzerOutput = JSON.stringify(From_G1(g1));
}

var OpBLS_Compress_G2 = async function(FuzzerInput) {
    /* XXX not implemented by noble-bls12-381 */
}

var OpBLS_Decompress_G2 = async function(FuzzerInput) {
    var x = BigInt(FuzzerInput['g1_x']).toString(16);
    if ( x.length > 96 ) {
        return;
    }
    x = '0'.repeat(96 - x.length) + x;

    var y = BigInt(FuzzerInput['g1_y']).toString(16);
    if ( y.length > 96 ) {
        return;
    }
    y = '0'.repeat(96 - y.length) + y;

    var compressed = x + y;

    var g2 = exports.PointG2.fromHex(compressed);

    try {
        g2.assertValidity();
    } catch ( e ) {
        return;
    }

    FuzzerOutput = JSON.stringify(From_G2(g2));
}

var OpBLS_IsG1OnCurve = async function(FuzzerInput) {
    var a = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);
    var res = true;

    try {
        a.assertValidity();
    } catch ( e ) {
        res = false;
    }

    FuzzerOutput = JSON.stringify(res);
}

var OpBLS_IsG2OnCurve = async function(FuzzerInput) {
    var a = To_G2(FuzzerInput['g2_w'], FuzzerInput['g2_y'], FuzzerInput['g2_v'], FuzzerInput['g2_x']);
    var res = true;

    try {
        a.assertValidity();
    } catch ( e ) {
        res = false;
    }

    FuzzerOutput = JSON.stringify(res);
}

var OpBLS_G1_Add = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        a.assertValidity();

        var b = To_G1(FuzzerInput['b_x'], FuzzerInput['b_y']);
        b.assertValidity();

        var res = a.add(b);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G1_Mul = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        a.assertValidity();

        var b = BigInt(FuzzerInput['b']);

        var res = a.multiply(b);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G1_Neg = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        a.assertValidity();

        var res = a.negate(b);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G1_IsEq = async function(FuzzerInput) {
    try {
        var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
        var b = To_G1(FuzzerInput['b_x'], FuzzerInput['b_y']);

        var res = a.equals(b);

        FuzzerOutput = JSON.stringify(res);
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_Add = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        a.assertValidity();

        var b = To_G2(FuzzerInput['b_w'], FuzzerInput['b_y'], FuzzerInput['b_v'], FuzzerInput['b_x']);
        b.assertValidity();

        var res = a.add(b);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_Mul = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        a.assertValidity();

        var b = BigInt(FuzzerInput['b']);

        var res = a.multiply(b);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_Neg = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        a.assertValidity();

        var res = a.negate(b);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_G2_IsEq = async function(FuzzerInput) {
    try {
        var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
        var b = To_G2(FuzzerInput['b_w'], FuzzerInput['b_y'], FuzzerInput['b_v'], FuzzerInput['b_x']);

        var res = a.equals(b);

        FuzzerOutput = JSON.stringify(res);
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Aggregate_G1 = async function(FuzzerInput) {
    try {
        var points = [];
        for (var i = 0; i < FuzzerInput['points'].length; i++) {
            var point = To_G1(
                FuzzerInput['points'][i]['x'],
                FuzzerInput['points'][i]['y']);
            points.push(point);
        }

        var res = aggregatePublicKeys(points);

        FuzzerOutput = JSON.stringify(From_G1(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBLS_Aggregate_G2 = async function(FuzzerInput) {
    try {
        var points = [];
        for (var i = 0; i < FuzzerInput['points'].length; i++) {
            var point = To_G2(
                FuzzerInput['points'][i]['w'],
                FuzzerInput['points'][i]['y'],
                FuzzerInput['points'][i]['v'],
                FuzzerInput['points'][i]['x']);
            points.push(point);
        }

        var res = aggregateSignatures(points);

        FuzzerOutput = JSON.stringify(From_G2(res));
    } catch ( e ) { /* console.log(e); */ }
}

var OpBignumCalc = async function(FuzzerInput, Fx) {
    var calcOp = BigInt(FuzzerInput["calcOp"]);

    var bn1 = new Fx(BigInt(FuzzerInput['bn0']));
    var bn2 = new Fx(BigInt(FuzzerInput['bn1']));

    var res;

    if ( IsAdd(calcOp) ) {
        res = bn1.add(bn2);
    } else if ( IsSub(calcOp) ) {
        res = bn1.subtract(bn2);
    } else if ( IsMul(calcOp) ) {
        res = bn1.multiply(bn2);
    } else if ( IsDiv(calcOp) ) {
        res = bn1.div(bn2);
    } else if ( IsSqr(calcOp) ) {
        res = bn1.square();
    } else if ( IsInvMod(calcOp) ) {
        res = bn1.invert();
    } else if ( IsSqrt(calcOp) ) {
        res = bn1.sqrt();
        if (typeof res === "undefined") {
            res = new Fx(0n);
        } else {
            res = res.square();
        }
    } else if ( IsJacobi(calcOp) ) {
        res = bn1.legendre();
    } else if ( IsNeg(calcOp) ) {
        res = bn1.negate();
    } else if ( IsIsEq(calcOp) ) {
        res = bn1.equals(bn2);
    } else if ( IsIsZero(calcOp) ) {
        res = bn1.isZero();
    } else {
        return;
    }

    res = res.value.toString(10);
    FuzzerOutput = JSON.stringify(res);
}

FuzzerInput = JSON.parse(FuzzerInput);
var operation = BigInt(FuzzerInput['operation']);

if ( IsBLS_PrivateToPublic(operation) ) {
    OpBLS_PrivateToPublic(FuzzerInput);
} else if ( IsBLS_HashToG1(operation) ) {
    OpBLS_HashToG1(FuzzerInput);
} else if ( IsBLS_HashToG2(operation) ) {
    OpBLS_HashToG2(FuzzerInput);
} else if ( IsBLS_Sign(operation) ) {
    OpBLS_Sign(FuzzerInput);
} else if ( IsBLS_Verify(operation) ) {
    OpBLS_Verify(FuzzerInput);
} else if ( IsBLS_Compress_G1(operation) ) {
    OpBLS_Compress_G1(FuzzerInput);
} else if ( IsBLS_Decompress_G1(operation) ) {
    OpBLS_Decompress_G1(FuzzerInput);
} else if ( IsBLS_Compress_G2(operation) ) {
    OpBLS_Compress_G2(FuzzerInput);
} else if ( IsBLS_Decompress_G2(operation) ) {
    OpBLS_Decompress_G2(FuzzerInput);
} else if ( IsBLS_IsG1OnCurve(operation) ) {
    OpBLS_IsG1OnCurve(FuzzerInput);
} else if ( IsBLS_IsG2OnCurve(operation) ) {
    OpBLS_IsG2OnCurve(FuzzerInput);
} else if ( IsBLS_G1_Add(operation) ) {
    OpBLS_G1_Add(FuzzerInput);
} else if ( IsBLS_G1_Mul(operation) ) {
    OpBLS_G1_Mul(FuzzerInput);
} else if ( IsBLS_G1_Neg(operation) ) {
    OpBLS_G1_Neg(FuzzerInput);
} else if ( IsBLS_G1_IsEq(operation) ) {
    OpBLS_G1_IsEq(FuzzerInput);
} else if ( IsBLS_G2_Add(operation) ) {
    OpBLS_G2_Add(FuzzerInput);
} else if ( IsBLS_G2_Mul(operation) ) {
    OpBLS_G2_Mul(FuzzerInput);
} else if ( IsBLS_G2_Neg(operation) ) {
    OpBLS_G2_Neg(FuzzerInput);
} else if ( IsBLS_G2_IsEq(operation) ) {
    OpBLS_G2_IsEq(FuzzerInput);
} else if ( IsBLS_Aggregate_G1(operation) ) {
    OpBLS_Aggregate_G1(FuzzerInput);
} else if ( IsBLS_Aggregate_G2(operation) ) {
    OpBLS_Aggregate_G2(FuzzerInput);
} else if ( IsBignumCalc_Mod_BLS12_381_P(operation) ) {
    OpBignumCalc(FuzzerInput, exports.Fp);
} else if ( IsBignumCalc_Mod_BLS12_381_R(operation) ) {
    OpBignumCalc(FuzzerInput, exports.Fr);
}
