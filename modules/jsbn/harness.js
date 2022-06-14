var BigInteger = module.exports.BigInteger;

FuzzerInput = JSON.parse(FuzzerInput);

var bn = [
    new BigInteger(FuzzerInput["bn0"]),
    new BigInteger(FuzzerInput["bn1"]),
    new BigInteger(FuzzerInput["bn2"]),
];

var calcOp = BigInt(FuzzerInput["calcOp"]);
if ( IsAdd(calcOp) ) {
    FuzzerOutput = bn[0].add(bn[1]).toString();
} else if ( IsSub(calcOp) ) {
    FuzzerOutput = bn[0].subtract(bn[1]).toString();
} else if ( IsMul(calcOp) ) {
    FuzzerOutput = bn[0].multiply(bn[1]).toString();
} else if ( IsDiv(calcOp) ) {
    if ( FuzzerInput['bn1'] != '' && FuzzerInput['bn1'] != '0' ) {
        FuzzerOutput = bn[0].divide(bn[1]).toString();
    }
} else if ( IsMod(calcOp) ) {
    if ( FuzzerInput['bn1'] != '' && FuzzerInput['bn1'] != '0' ) {
        FuzzerOutput = bn[0].mod(bn[1]).toString();
    }
} else if ( IsInvMod(calcOp) ) {
    try {
        FuzzerOutput = bn[0].modInverse(bn[1]).toString();
    } catch ( e ) {
        FuzzerOutput = '0';
    }
} else if ( IsExpMod(calcOp) ) {
    FuzzerOutput = bn[0].modPow(bn[1], bn[2]).toString();
} else if ( IsMin(calcOp) ) {
    FuzzerOutput = bn[0].min(bn[1]).toString();
} else if ( IsMax(calcOp) ) {
    FuzzerOutput = bn[0].max(bn[1]).toString();
} else if ( IsAnd(calcOp) ) {
    FuzzerOutput = bn[0].and(bn[1]).toString();
} else if ( IsOr(calcOp) ) {
    FuzzerOutput = bn[0].or(bn[1]).toString();
} else if ( IsXor(calcOp) ) {
    FuzzerOutput = bn[0].xor(bn[1]).toString();
} else if ( IsGCD(calcOp) ) {
    FuzzerOutput = bn[0].gcd(bn[1]).toString();
}
