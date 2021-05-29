var toInt = function(s) {
    if ( s.length == 0 ) {
        return 0;
    } else {
        return parseInt(s);
    }
}

FuzzerInput = JSON.parse(FuzzerInput);

var BigNumber = module.exports.BigNumber;
BigNumber.config({ EXPONENTIAL_AT: 10000, ROUNDING_MODE: 1 })

var OpBignumCalc = function(FuzzerInput) {
    var bn = [
        new BigNumber(FuzzerInput["bn0"]),
        new BigNumber(FuzzerInput["bn1"]),
        new BigNumber(FuzzerInput["bn2"]),
        new BigNumber(FuzzerInput["bn3"])
    ];

    var calcOp = toInt(FuzzerInput["calcOp"]);

    var ret;
    if ( IsAdd(calcOp) ) {
        ret = bn[0].plus(bn[1]);
    } else if ( IsSub(calcOp) ) {
        ret = bn[0].minus(bn[1]);
    } else if ( IsMul(calcOp) ) {
        ret = bn[0].multipliedBy(bn[1]);
    } else if ( IsDiv(calcOp) ) {
        ret = bn[0].dividedToIntegerBy(bn[1]);
    } else if ( IsSqr(calcOp) ) {
        ret = bn[0].exponentiatedBy(2);
    } else if ( IsAbs(calcOp) ) {
        ret = bn[0].absoluteValue();
    } else if ( IsNeg(calcOp) ) {
        ret = bn[0].negated();
    } else if ( IsExpMod(calcOp) ) {
        /* Disabled due to timeouts */
        return;
        /*
        if ( bn[1].isGreaterThanOrEqualTo(new BigNumber("1000")) ) {
            return;
        }
        ret = bn[0].exponentiatedBy(bn[1]).modulo(bn[2]);
        */
    } else if ( IsCmp(calcOp) ) {
        ret = new BigNumber( bn[0].comparedTo(bn[1]) );
    } else if ( IsAddMod(calcOp) ) {
        ret = bn[0].plus(bn[1]).modulo(bn[2]);
    } else if ( IsSubMod(calcOp) ) {
        if ( !bn[0].isGreaterThanOrEqualTo(bn[1]) ) {
            return;
        }
        ret = bn[0].minus(bn[1]).modulo(bn[2]);
    } else if ( IsSqrMod(calcOp) ) {
        ret = bn[0].exponentiatedBy(2).modulo(bn[1]);
    } else if ( IsMulMod(calcOp) ) {
        ret = bn[0].multipliedBy(bn[1]).modulo(bn[2]);
    } else if ( IsMod(calcOp) ) {
        ret = bn[0].modulo(bn[1]);
    } else if ( IsIsEq(calcOp) ) {
        ret = bn[0].isEqualTo(bn[1]) ? new BigNumber(1) : new BigNumber(0);
    } else if ( IsIsNeg(calcOp) ) {
        ret = bn[0].isNegative(bn[1]) ? new BigNumber(1) : new BigNumber(0);
    } else if ( IsIsZero(calcOp) ) {
        ret = bn[0].isZero(bn[1]) ? new BigNumber(1) : new BigNumber(0);
    } else if ( IsSqrt(calcOp) ) {
        /* Prevent timeouts */
        if ( FuzzerInput['bn0'].length > 3000 ) {
            return;
        }
        ret = new BigNumber( bn[0].squareRoot().toFixed(0) );
    } else {
        return;
    }

    if ( !ret.isNaN() && ret.isFinite() ) {
        FuzzerOutput = ret.toString();
    }
}

OpBignumCalc(FuzzerInput);
