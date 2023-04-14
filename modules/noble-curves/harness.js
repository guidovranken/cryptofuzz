import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';

import { secp256r1 } from '@noble/curves/p256';
import { secp384r1 } from '@noble/curves/p384';
import { secp521r1 } from '@noble/curves/p521';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { ed448, x448 } from '@noble/curves/ed448';
import { bls12_381 } from '@noble/curves/bls12-381';

import * as ids from './ids.js';

var toCurve = function (curveType) {
  curveType = BigInt(curveType);
  if (ids.Issecp256r1(curveType)) return secp256r1;
  else if (ids.Issecp384r1(curveType)) return secp384r1;
  else if (ids.Issecp521r1(curveType)) return secp521r1;
  else if (ids.Issecp256k1(curveType)) return secp256k1;
  else if (ids.Ised25519(curveType)) return ed25519;
  else if (ids.Ised448(curveType)) return ed448;
  else if (ids.Isx25519(curveType)) return x25519;
  else if (ids.Isx448(curveType)) return x448;
  else return;
};

function toCurveECDSA(curveType, digestType) {
  if (ids.IsNULL(digestType)) {
    // No ECDSA for X... curves
    if (ids.Isx25519(curveType) || ids.Isx448(curveType)) return;
    const curve = toCurve(curveType);
    if (!curve) return;
    return { curve, prehash: false };
  }
  if (ids.IsSHA256(digestType) && ids.Issecp256r1(curveType))
    return { curve: secp256r1, prehash: true };
  if (ids.IsSHA384(digestType) && ids.Issecp384r1(curveType))
    return { curve: secp384r1, prehash: true };
  if (ids.IsSHA512(digestType) && ids.Issecp521r1(curveType))
    return { curve: secp521r1, prehash: true };
  if (ids.IsSHA256(digestType) && ids.Issecp256k1(curveType))
    return { curve: secp256k1, prehash: true };
}

function curveInfo(c) {
  // Pretty ugly, but works. Detect if curve weierstrasse (Ws) / Twisted Edwards (Ed) or X25519/X448 (X)
  return {
    isWs: c.CURVE ? c.CURVE.a !== undefined && c.CURVE.b !== undefined : false,
    isEd: c.CURVE ? c.CURVE.d !== undefined : false,
    isX: !c.CURVE,
  };
}

function getPoint(curve, x, y) {
  const p = curve.ProjectivePoint || curve.ExtendedPoint;
  if (!p) return;
  try {
    const pAff = p.fromAffine({ x: BigInt(x), y: BigInt(y) });
    pAff.assertValidity();
    return pAff;
  } catch (e) {
    return;
  }
}

function retPoint(p) {
  if (!p.is0()) p.assertValidity();
  const res = p.toAffine();
  return JSON.stringify([res.x.toString(), res.y.toString()]);
}

function toNHex(curve, priv) {
  return priv.toString(16).padStart(2 * curve.CURVE.nByteLength, '0');
}

function bytesToInt(b) {
  return BigInt('0x'.concat(bytesToHex(b))).toString(10);
}

// ECC
const OpECC_PrivateToPublic = function (FuzzerInput) {
  const priv = BigInt(FuzzerInput['priv']);
  const curve = toCurve(FuzzerInput['curveType']);
  if (!curve) return;
  const info = curveInfo(curve);
  let pub;
  if (info.isEd) {
    try {
      pub = curve.getPublicKey(toNHex(curve, priv));
    } catch (e) {
      return;
    }
    return JSON.stringify([bytesToInt(pub), '0']);
  } else if (info.isWs) {
    try {
      pub = curve.getPublicKey(priv);
    } catch (e) {
      return;
    }
    pub = curve.ProjectivePoint.fromHex(pub).toAffine();
    return JSON.stringify([pub.x.toString(), pub.y.toString()]);
  }
};

var OpECC_Point_Add = function (FuzzerInput) {
  const curve = toCurve(FuzzerInput['curveType']);
  if (!curve) return;
  const info = curveInfo(curve);
  if (info.isX) return;
  const a = getPoint(curve, FuzzerInput['a_x'], FuzzerInput['a_y']);
  const b = getPoint(curve, FuzzerInput['b_x'], FuzzerInput['b_y']);
  if (!a || !b) return;
  return retPoint(a.add(b));
};

var OpECC_Point_Dbl = function (FuzzerInput) {
  const curve = toCurve(FuzzerInput['curveType']);
  if (!curve) return;
  const info = curveInfo(curve);
  if (info.isX) return;
  const a = getPoint(curve, FuzzerInput['a_x'], FuzzerInput['a_y']);
  if (!a) return;
  return retPoint(a.double());
};

var OpECC_Point_Neg = function (FuzzerInput) {
  const curve = toCurve(FuzzerInput['curveType']);
  if (!curve) return;
  const info = curveInfo(curve);
  if (info.isX) return;
  const a = getPoint(curve, FuzzerInput['a_x'], FuzzerInput['a_y']);
  if (!a) return;
  return retPoint(a.negate());
};

var OpECC_Point_Mul = function (FuzzerInput) {
  const curve = toCurve(FuzzerInput['curveType']);
  if (!curve) return;
  const info = curveInfo(curve);
  if (info.isX) return;
  const a = getPoint(curve, FuzzerInput['a_x'], FuzzerInput['a_y']);
  if (!a) return;
  const b = BigInt(FuzzerInput['b']);
  // Need to handle exception if b > curve order
  try {
    return retPoint(a.multiply(b));
  } catch (e) {}
};

// ECDSA
var OpECDSA_Sign = function (FuzzerInput) {
  var msg = FuzzerInput['cleartext'];
  let priv = BigInt(FuzzerInput['priv']);
  const c = toCurveECDSA(FuzzerInput['curveType'], FuzzerInput['digestType']);
  if (!c) return;
  const { curve, prehash } = c;
  const info = curveInfo(curve);

  if (info.isEd) {
    priv = toNHex(curve, priv);
    let pub;
    try {
      pub = curve.getPublicKey(priv);
    } catch (e) {
      return;
    }

    const len = curve.CURVE.nByteLength;
    const signature = curve.sign(msg, priv);
    const r = signature.slice(0, len);
    const s = signature.slice(len, 2 * len);

    return JSON.stringify({
      signature: [r, s].map(bytesToInt),
      pub: [bytesToInt(pub), '0'],
    });
  } else if (info.isWs) {
    let pub;
    try {
      pub = curve.getPublicKey(priv);
    } catch (e) {
      return;
    }
    pub = curve.ProjectivePoint.fromHex(pub).toAffine();
    // Signature
    const signature = curve.sign(msg, priv, { lowS: true, prehash });
    return JSON.stringify({
      signature: [signature.r.toString(), signature.s.toString()],
      pub: [pub.x.toString(), pub.y.toString()],
    });
  }
};

var OpECDSA_Verify = function (FuzzerInput) {
  let msg = FuzzerInput['cleartext'];
  let x = BigInt(FuzzerInput['pub_x']);
  let y = BigInt(FuzzerInput['pub_y']);
  let r = BigInt(FuzzerInput['sig_r']);
  let s = BigInt(FuzzerInput['sig_s']);

  const c = toCurveECDSA(FuzzerInput['curveType'], FuzzerInput['digestType']);
  if (!c) return;
  const { curve, prehash } = c;
  const info = curveInfo(curve);
  let verified = false;
  if (info.isEd) {
    x = toNHex(curve, x);
    r = toNHex(curve, r);
    s = toNHex(curve, s);
    try {
      verified = curve.verify(r + s, msg, x);
    } catch (e) {}
  } else if (info.isWs) {
    try {
      const pub = curve.ProjectivePoint.fromAffine({ x, y }).toHex();
      const signature = new curve.Signature(r, s);
      verified = curve.verify(signature, msg, pub, { lowS: false, prehash });
    } catch (e) {}
  } else return;
  return JSON.stringify(verified);
};
// BLS
var HexToDec = function (hex) {
  return BigInt('0x'.concat(hex)).toString(10);
};

var GetDST = function (dst) {
  dst = hexToBytes(dst);
  var ret = '';
  for (var i = 0; i < dst.length; i++) {
    if (dst[i] >= 128) {
      return false;
    }
    ret += String.fromCharCode(dst[i]);
  }
  return ret;
};

var To_G1 = function (x, y) {
  var x = bls12_381.fields.Fp.create(BigInt(x));
  var y = bls12_381.fields.Fp.create(BigInt(y));
  return bls12_381.G1.ProjectivePoint.fromAffine({ x, y });
};

var From_G1 = function (g1) {
  const { x, y } = g1.toAffine();
  return [x, y].map((i) => i.toString(10));
};

var To_G2 = function (yc0, yc1, xc0, xc1) {
  const x = bls12_381.fields.Fp2.create({ c0: BigInt(xc0), c1: BigInt(xc1) });
  const y = bls12_381.fields.Fp2.create({ c0: BigInt(yc0), c1: BigInt(yc1) });
  return bls12_381.G2.ProjectivePoint.fromAffine({ x, y });
};

var From_G2 = function (g2) {
  var affine = g2.toAffine();

  var x1 = affine.x.c0.toString(10);
  var y1 = affine.y.c0.toString(10);
  var x2 = affine.x.c1.toString(10);
  var y2 = affine.y.c1.toString(10);

  return [
    [x1, y1],
    [x2, y2],
  ];
};

var OpBLS_PrivateToPublic = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  var priv = BigInt(FuzzerInput['priv']);

  try {
    var pub = bls12_381.getPublicKey(priv);
    pub = bls12_381.G1.ProjectivePoint.fromHex(pub);

    FuzzerOutput = JSON.stringify([pub.x.value.toString(), pub.y.value.toString()]);
  } catch (e) {}
};

var OpBLS_HashToG1 = function (FuzzerInput) {
  const DST = GetDST(FuzzerInput['dest']);
  if (!DST) return;
  try {
    var msg = hexToBytes(FuzzerInput['aug'] + FuzzerInput['cleartext']);
    var res = bls12_381.G1.hashToCurve(msg, { DST });
    return JSON.stringify(From_G1(res));
  } catch (e) {
    console.log(e);
  }
};

var OpBLS_HashToG2 = function (FuzzerInput) {
  const DST = GetDST(FuzzerInput['dest']);
  if (!DST) return;
  try {
    var msg = hexToBytes(FuzzerInput['aug'] + FuzzerInput['cleartext']);
    var res = bls12_381.G2.hashToCurve(msg, { DST });
    return JSON.stringify(From_G2(res));
  } catch (e) {
    console.log(e);
  }
};

var OpBLS_Sign = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  const DST = GetDST(FuzzerInput['dest']);
  if (!DST) return;

  var msg;
  if (FuzzerInput['hashOrPoint'] == true) {
    msg = FuzzerInput['aug'] + FuzzerInput['cleartext'];
  } else {
    msg = To_G2(FuzzerInput['g2_v'], FuzzerInput['g2_x'], FuzzerInput['g2_w'], FuzzerInput['g2_y']);
  }

  var priv = BigInt(FuzzerInput['priv']);

  try {
    var pub = bls12_381.getPublicKey(priv);
    pub = bls12_381.G1.ProjectivePoint.fromHex(pub);

    var signature = bls12_381.sign(msg, priv, { DST });

    if (FuzzerInput['hashOrPoint'] == true) {
      signature = bls12_381.Signature.decode(signature);
    }

    var affine = signature.toAffine();

    var x1 = affine[0].values[0].toString(10);
    var y1 = affine[1].values[0].toString(10);
    var x2 = affine[0].values[1].toString(10);
    var y2 = affine[1].values[1].toString(10);

    FuzzerOutput = JSON.stringify({
      signature: [
        [x1, y1],
        [x2, y2],
      ],
      pub: [pub.x.value.toString(), pub.y.value.toString()],
    });
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_Verify = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  const DST = GetDST(FuzzerInput['dest']);
  if (!DST) return;
  try {
    var pub = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);
    var sig = To_G2(
      FuzzerInput['g2_w'],
      FuzzerInput['g2_y'],
      FuzzerInput['g2_v'],
      FuzzerInput['g2_x']
    );
    var msg = FuzzerInput['cleartext'];
    var res = bls12_381.verify(sig, msg, pub, { DST });
    return JSON.stringify(res);
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_Compress_G1 = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var g1 = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);
    g1.assertValidity();
  } catch (e) {
    return;
  }

  var compressed = g1.toHex(true);
  compressed = HexToDec(compressed);

  return JSON.stringify(compressed);
};

var OpBLS_Decompress_G1 = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  var compressed = BigInt(FuzzerInput['compressed']).toString(16);
  if (compressed.length > 96) {
    return;
  }

  compressed = '0'.repeat(96 - compressed.length) + compressed;

  try {
    var g1 = bls12_381.G1.ProjectivePoint.fromHex(compressed);
    g1.assertValidity();
  } catch (e) {
    return;
  }

  return; /* XXX */
  return JSON.stringify(From_G1(g1));
};

var OpBLS_Compress_G2 = function (FuzzerInput) {
  /* XXX not implemented by noble-bls12-381 */
};

var OpBLS_Decompress_G2 = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  var x = BigInt(FuzzerInput['g1_x']).toString(16);
  if (x.length > 96) {
    return;
  }
  x = '0'.repeat(96 - x.length) + x;

  var y = BigInt(FuzzerInput['g1_y']).toString(16);
  if (y.length > 96) {
    return;
  }
  y = '0'.repeat(96 - y.length) + y;

  var compressed = x + y;

  try {
    var g2 = bls12_381.G2.ProjectivePoint.fromHex(compressed);
    g2.assertValidity();
  } catch (e) {
    return;
  }

  return JSON.stringify(From_G2(g2));
};

var OpBLS_IsG1OnCurve = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  var res = true;

  try {
    var a = To_G1(FuzzerInput['g1_x'], FuzzerInput['g1_y']);
    a.assertValidity();
    if (a.equals(bls12_381.G1.ProjectivePoint.ZERO)) res = false;
  } catch (e) {
    res = false;
  }

  return JSON.stringify(res);
};

var OpBLS_IsG2OnCurve = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  var res = true;

  try {
    var a = To_G2(
      FuzzerInput['g2_w'],
      FuzzerInput['g2_y'],
      FuzzerInput['g2_v'],
      FuzzerInput['g2_x']
    );
    a.assertValidity();
    if (a.equals(bls12_381.G2.ProjectivePoint.ZERO)) res = false;
  } catch (e) {
    res = false;
  }

  return JSON.stringify(res);
};

var OpBLS_G1_Add = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
    a.assertValidity();

    var b = To_G1(FuzzerInput['b_x'], FuzzerInput['b_y']);
    b.assertValidity();

    var res = a.add(b);

    return JSON.stringify(From_G1(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_G1_Mul = function (FuzzerInput) {
  try {
    var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
    a.assertValidity();

    var b = BigInt(FuzzerInput['b']);

    var res = a.multiply(b);

    return JSON.stringify(From_G1(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_G1_Neg = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
    a.assertValidity();

    var res = a.negate();

    return JSON.stringify(From_G1(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_G1_IsEq = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var a = To_G1(FuzzerInput['a_x'], FuzzerInput['a_y']);
    var b = To_G1(FuzzerInput['b_x'], FuzzerInput['b_y']);

    var res = a.equals(b);

    return JSON.stringify(res);
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_G2_Add = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
    a.assertValidity();

    var b = To_G2(FuzzerInput['b_w'], FuzzerInput['b_y'], FuzzerInput['b_v'], FuzzerInput['b_x']);
    b.assertValidity();

    var res = a.add(b);

    return JSON.stringify(From_G2(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_G2_Mul = function (FuzzerInput) {
  try {
    var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
    a.assertValidity();

    var b = BigInt(FuzzerInput['b']);

    var res = a.multiply(b);

    return JSON.stringify(From_G2(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_G2_Neg = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
    a.assertValidity();

    var res = a.negate();

    return JSON.stringify(From_G2(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_G2_IsEq = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var a = To_G2(FuzzerInput['a_w'], FuzzerInput['a_y'], FuzzerInput['a_v'], FuzzerInput['a_x']);
    var b = To_G2(FuzzerInput['b_w'], FuzzerInput['b_y'], FuzzerInput['b_v'], FuzzerInput['b_x']);

    var res = a.equals(b);

    return JSON.stringify(res);
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_Aggregate_G1 = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var points = [];
    for (var i = 0; i < FuzzerInput['points'].length; i++) {
      var point = To_G1(FuzzerInput['points'][i]['x'], FuzzerInput['points'][i]['y']);
      points.push(point);
    }

    var res = aggregatePublicKeys(points);

    return JSON.stringify(From_G1(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBLS_Aggregate_G2 = function (FuzzerInput) {
  if (!ids.IsBLS12_381(BigInt(FuzzerInput['curveType']))) return;
  try {
    var points = [];
    for (var i = 0; i < FuzzerInput['points'].length; i++) {
      var point = To_G2(
        FuzzerInput['points'][i]['w'],
        FuzzerInput['points'][i]['y'],
        FuzzerInput['points'][i]['v'],
        FuzzerInput['points'][i]['x']
      );
      points.push(point);
    }

    var res = aggregateSignatures(points);

    return JSON.stringify(From_G2(res));
  } catch (e) {
    /* console.log(e); */
  }
};

var OpBignumCalc = function (FuzzerInput, Fp) {
  var calcOp = BigInt(FuzzerInput['calcOp']);

  var bn1 = Fp.create(BigInt(FuzzerInput['bn0']));
  var bn2 = Fp.create(BigInt(FuzzerInput['bn1']));

  var res;

  if (IsAdd(calcOp)) {
    res = Fp.add(bn1, bn2);
  } else if (IsSub(calcOp)) {
    res = Fp.sub(bn1, bn2);
  } else if (IsMul(calcOp)) {
    res = Fp.mul(bn1, bn2);
  } else if (IsDiv(calcOp)) {
    res = Fp.div(bn1, bn2);
  } else if (IsSqr(calcOp)) {
    res = Fp.sqr(bn1);
  } else if (IsInvMod(calcOp)) {
    res = Fp.inv(bn1);
  } else if (IsSqrt(calcOp)) {
    try {
      res = Fp.sqrt(bn1);
    } catch (e) {}
    if (typeof res === 'undefined') {
      res = Fp.ZERO;
    } else {
      res = res.square();
    }
  } else if (IsNeg(calcOp)) {
    res = Fp.neg(bn1);
  } else if (IsIsEq(calcOp)) {
    res = Fp.eql(bn1, bn2);
  } else if (IsIsZero(calcOp)) {
    res = Fp.is0(bn1);
  } else {
    return;
  }

  res = res.value.toString(10);
  return JSON.stringify(res);
};

// Main operations routing
FuzzerInput = JSON.parse(FuzzerInput);
var operation = BigInt(FuzzerInput['operation']);

if (ids.IsECC_PrivateToPublic(operation)) {
  FuzzerOutput = OpECC_PrivateToPublic(FuzzerInput);
} else if (ids.IsECDSA_Sign(operation)) {
  FuzzerOutput = OpECDSA_Sign(FuzzerInput);
} else if (ids.IsECDSA_Verify(operation)) {
  FuzzerOutput = OpECDSA_Verify(FuzzerInput);
} else if (ids.IsECC_Point_Add(operation)) {
  FuzzerOutput = OpECC_Point_Add(FuzzerInput);
} else if (ids.IsECC_Point_Mul(operation)) {
  FuzzerOutput = OpECC_Point_Mul(FuzzerInput);
} else if (ids.IsECC_Point_Neg(operation)) {
  FuzzerOutput = OpECC_Point_Neg(FuzzerInput);
} else if (ids.IsECC_Point_Dbl(operation)) {
  FuzzerOutput = OpECC_Point_Dbl(FuzzerInput);
  // BLS
} else if (ids.IsBLS_PrivateToPublic(operation)) {
  FuzzerOutput = OpBLS_PrivateToPublic(FuzzerInput);
} else if (ids.IsBLS_HashToG1(operation)) {
  FuzzerOutput = OpBLS_HashToG1(FuzzerInput);
} else if (ids.IsBLS_HashToG2(operation)) {
  FuzzerOutput = OpBLS_HashToG2(FuzzerInput);
} else if (ids.IsBLS_Sign(operation)) {
  FuzzerOutput = OpBLS_Sign(FuzzerInput);
} else if (ids.IsBLS_Verify(operation)) {
  FuzzerOutput = OpBLS_Verify(FuzzerInput);
} else if (ids.IsBLS_Compress_G1(operation)) {
  FuzzerOutput = OpBLS_Compress_G1(FuzzerInput);
} else if (ids.IsBLS_Decompress_G1(operation)) {
  FuzzerOutput = OpBLS_Decompress_G1(FuzzerInput);
} else if (ids.IsBLS_Compress_G2(operation)) {
  FuzzerOutput = OpBLS_Compress_G2(FuzzerInput);
} else if (ids.IsBLS_Decompress_G2(operation)) {
  FuzzerOutput = OpBLS_Decompress_G2(FuzzerInput);
} else if (ids.IsBLS_IsG1OnCurve(operation)) {
  FuzzerOutput = OpBLS_IsG1OnCurve(FuzzerInput);
} else if (ids.IsBLS_IsG2OnCurve(operation)) {
  FuzzerOutput = OpBLS_IsG2OnCurve(FuzzerInput);
} else if (ids.IsBLS_G1_Add(operation)) {
  FuzzerOutput = OpBLS_G1_Add(FuzzerInput);
} else if (ids.IsBLS_G1_Mul(operation)) {
  FuzzerOutput = OpBLS_G1_Mul(FuzzerInput);
} else if (ids.IsBLS_G1_Neg(operation)) {
  FuzzerOutput = OpBLS_G1_Neg(FuzzerInput);
} else if (ids.IsBLS_G1_IsEq(operation)) {
  FuzzerOutput = OpBLS_G1_IsEq(FuzzerInput);
} else if (ids.IsBLS_G2_Add(operation)) {
  FuzzerOutput = OpBLS_G2_Add(FuzzerInput);
} else if (ids.IsBLS_G2_Mul(operation)) {
  FuzzerOutput = OpBLS_G2_Mul(FuzzerInput);
} else if (ids.IsBLS_G2_Neg(operation)) {
  FuzzerOutput = OpBLS_G2_Neg(FuzzerInput);
} else if (ids.IsBLS_G2_IsEq(operation)) {
  FuzzerOutput = OpBLS_G2_IsEq(FuzzerInput);
} else if (ids.IsBLS_Aggregate_G1(operation)) {
  FuzzerOutput = OpBLS_Aggregate_G1(FuzzerInput);
} else if (ids.IsBLS_Aggregate_G2(operation)) {
  FuzzerOutput = OpBLS_Aggregate_G2(FuzzerInput);
/*
} else if (IsBignumCalc_Mod_BLS12_381_P(operation)) {
  FuzzerOutput = OpBignumCalc(FuzzerInput, bls12_381.Fp);
} else if (IsBignumCalc_Mod_BLS12_381_R(operation)) {
  FuzzerOutput = OpBignumCalc(FuzzerInput, bls12_381.Fr);
*/
}
