var BN = module.exports.BN;

var toInt = function(s) {
    if ( s.length == 0 ) {
        return 0;
    } else {
        return parseInt(s);
    }
}

FuzzerInput = JSON.parse(FuzzerInput);

var bn = [
    new BN(FuzzerInput["bn0"], 10),
    new BN(FuzzerInput["bn1"], 10),
    new BN(FuzzerInput["bn2"], 10),
    new BN(FuzzerInput["bn3"], 10)
];

var calcOp = toInt(FuzzerInput["calcOp"]);

var NISTp192 = new BN("6277101735386680763835789423207666416083908700390324961279");
var NISTp224 = new BN("26959946667150639794667015087019630673557916260026308143510066298881", 10);
var NISTp256 = new BN("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10);
var NISTp384 = new BN("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319", 10);
var NISTp521 = new BN("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", 10);

try {
    if ( IsAdd(calcOp) ) {
        FuzzerOutput = String(bn[0].add(bn[1]));
    } else if ( IsSub(calcOp) ) {
        FuzzerOutput = String(bn[0].sub(bn[1]));
    } else if ( IsMul(calcOp) ) {
        FuzzerOutput = String(bn[0].mul(bn[1]));
    } else if ( IsDiv(calcOp) ) {
        FuzzerOutput = String(bn[0].div(bn[1]));
    } else if ( IsSqr(calcOp) ) {
        FuzzerOutput = String(bn[0].sqr());
    } else if ( IsAbs(calcOp) ) {
        FuzzerOutput = String(bn[0].abs(bn[1]));
    } else if ( IsNeg(calcOp) ) {
        FuzzerOutput = String(bn[0].neg(bn[1]));
    } else if ( IsLShift1(calcOp) ) {
        FuzzerOutput = String(bn[0].shln(1));
    } else if ( IsRShift(calcOp) ) {
        FuzzerOutput = String(bn[0].shrn(bn[1]));
    } else if ( IsXor(calcOp) ) {
        FuzzerOutput = String(bn[0].xor(bn[1]));
    } else if ( IsOr(calcOp) ) {
        FuzzerOutput = String(bn[0].or(bn[1]));
    } else if ( IsAnd(calcOp) ) {
        FuzzerOutput = String(bn[0].and(bn[1]));
    } else if ( IsGCD(calcOp) ) {
        FuzzerOutput = String(bn[0].gcd(bn[1]));
    } else if ( IsInvMod(calcOp) ) {
        /*
         * Returns wrong result
         *
         * https://github.com/indutny/bn.js/issues/217
         *
         * FuzzerOutput = String(bn[0].invm(bn[1]));
         */
    } else if ( IsSetBit(calcOp) ) {
        FuzzerOutput = String(bn[0].setn(bn[1]));
    } else if ( IsExpMod(calcOp) ) {
        var r = BN.red(bn[2]);
        FuzzerOutput = String(bn[0].toRed(r).redPow(bn[1]).fromRed());
    } else if ( IsMod_NIST_192(calcOp) ) {
        FuzzerOutput = String(bn[0].mod(NISTp192));
    } else if ( IsMod_NIST_224(calcOp) ) {
        FuzzerOutput = String(bn[0].mod(NISTp224));
    } else if ( IsMod_NIST_256(calcOp) ) {
        FuzzerOutput = String(bn[0].mod(NISTp256));
    } else if ( IsMod_NIST_384(calcOp) ) {
        FuzzerOutput = String(bn[0].mod(NISTp384));
    } else if ( IsMod_NIST_521(calcOp) ) {
        FuzzerOutput = String(bn[0].mod(NISTp521));
    } else if ( IsCmp(calcOp) ) {
        FuzzerOutput = String(bn[0].cmp(bn[1]));
    } else if ( IsAddMod(calcOp) ) {
        FuzzerOutput = String(bn[0].add(bn[1]).mod(bn[2]));
    } else if ( IsSubMod(calcOp) ) {
        FuzzerOutput = String(bn[0].sub(bn[1]).mod(bn[2]));
    } else if ( IsSqrMod(calcOp) ) {
        FuzzerOutput = String(bn[0].sqr().mod(bn[1]));
    } else if ( IsMulMod(calcOp) ) {
        FuzzerOutput = String(bn[0].mul(bn[1]).mod(bn[2]));
    } else if ( IsBit(calcOp) ) {
        FuzzerOutput = String(bn[0].testn(bn[1]));
    } else if ( IsMod(calcOp) ) {
        FuzzerOutput = String(bn[0].mod(bn[1]));
    } else if ( IsIsEq(calcOp) ) {
        FuzzerOutput = bn[0].eq(bn[1]) ? "1" : "0";
    } else if ( IsIsEven(calcOp) ) {
        FuzzerOutput = bn[0].isEven(bn[1]) ? "1" : "0";
    } else if ( IsIsOdd(calcOp) ) {
        FuzzerOutput = bn[0].isOdd(bn[1]) ? "1" : "0";
    } else if ( IsIsNeg(calcOp) ) {
        FuzzerOutput = bn[0].isNeg(bn[1]) ? "1" : "0";
    }

} catch ( e ) { }
