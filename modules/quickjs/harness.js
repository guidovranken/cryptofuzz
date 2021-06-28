FuzzerInput = JSON.parse(FuzzerInput);

var OpBignumCalc = function(FuzzerInput) {
    var bn = [
        BigInt(FuzzerInput["bn0"]),
        BigInt(FuzzerInput["bn1"]),
    ];

    var calcOp = BigInt(FuzzerInput["calcOp"]);

    var ret;
    try {
        if ( IsAdd(calcOp) ) {
            ret = bn[0] + bn[1];
        } else if ( IsSub(calcOp) ) {
            ret = bn[0] - bn[1];
        } else if ( IsMul(calcOp) ) {
            ret = bn[0] * bn[1];
        } else if ( IsDiv(calcOp) ) {
            ret = bn[0] / bn[1];
            if ( bn[0] < 0 || bn[1] < 0 ) return;
        } else if ( IsMod(calcOp) ) {
            ret = bn[0] % bn[1];
            if ( bn[0] < 0 || bn[1] < 0 ) return;
        } else if ( IsExp(calcOp) ) {
            ret = bn[0] ** bn[1];
        } else if ( IsRShift(calcOp) ) {
            ret = bn[0] >> bn[1];
            if ( bn[0] < 0 || bn[1] < 0 ) return;
        } else if ( IsLShift1(calcOp) ) {
            ret = bn[0] << 1;
            if ( bn[0] < 0 ) return;
        } else if ( IsIsEq(calcOp) ) {
            ret = bn[0] == bn[1] ? 1n : 0n;
        } else if ( IsIsGt(calcOp) ) {
            ret = bn[0] > bn[1] ? 1n : 0n;
        } else if ( IsIsGte(calcOp) ) {
            ret = bn[0] >= bn[1] ? 1n : 0n;
        } else if ( IsIsLt(calcOp) ) {
            ret = bn[0] < bn[1] ? 1n : 0n;
        } else if ( IsIsLte(calcOp) ) {
            ret = bn[0] <= bn[1] ? 1n : 0n;
        } else if ( IsIsZero(calcOp) ) {
            ret = !bn[0] ? 1n : 0n;
        } else if ( IsIsNotZero(calcOp) ) {
            ret = bn[0] ? 1n : 0n;
        } else if ( IsIsNeg(calcOp) ) {
            ret = bn[0] < 0 ? 1n : 0n;
        } else if ( IsAnd(calcOp) ) {
            ret = bn[0] & bn[1];
        } else if ( IsOr(calcOp) ) {
            ret = bn[0] | bn[1];
        } else if ( IsXor(calcOp) ) {
            ret = bn[0] ^ bn[1];
        } else if ( IsSet(calcOp) ) {
            ret = bn[0];
        } else if ( IsNeg(calcOp) ) {
            ret = -bn[0];
        } else {
            return;
        }
    } catch ( e ) {
        return;
    }

    if ( ret >= 0 && FuzzerInput['radix'] == '16' ) {
        ret = BigInt('0x' + ret.toString(16));
    } else if ( ret >= 0 && FuzzerInput['radix'] == '8' ) {
        ret = BigInt('0o' + ret.toString(8));
    } else if ( ret >= 0 && FuzzerInput['radix'] == '2' ) {
        ret = BigInt('0b' + ret.toString(2));
    } else {
        ret.toString(FuzzerInput['radix']);
    }

    FuzzerOutput = ret.toString();
}

OpBignumCalc(FuzzerInput);
