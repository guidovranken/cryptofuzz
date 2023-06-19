function loadBn(bn) {
    if ( bn == '-' ) {
        bn = '-0';
    }

    return BigInt(bn);
}

function cryptofuzz(calcop, bn0, bn1) {
    a = loadBn(bn0);
    b = loadBn(bn1);
    var res;
    if ( calcop == 'Add(A,B)' ) {
        res = a + b;
    } else if ( calcop == 'Sub(A,B)' ) {
        res = a - b;
    } else if ( calcop == 'Mul(A,B)' ) {
        res = a * b;
    } else if ( calcop == 'Div(A,B)' ) {
        if ( b == 0 ) {
            return;
        }
        res = a / b;
    } else if ( calcop == 'Mod(A,B)' ) {
        if ( a < 0 || b <= 0 ) {
            return;
        }
        res = a % b;
    } else if ( calcop == 'Exp(A,B)' ) {
        if ( b < 0 ) {
            return;
        }
        res = a ** b;
    } else if ( calcop == 'And(A,B)' ) {
        res = a & b;
    } else if ( calcop == 'Or(A,B)' ) {
        res = a | b;
    } else if ( calcop == 'Xor(A,B)' ) {
        res = a ^ b;
    } else if ( calcop == 'Rshift(A,B)' ) {
        res = a >> b;
    } else if ( calcop == 'LShift1(A,B)' ) {
        res = a << 1;
    } else if ( calcop == 'IsEq(A,B)' ) {
        res = BigInt(a == b);
    } else if ( calcop == 'IsGt(A,B)' ) {
        res = BigInt(a > b);
    } else if ( calcop == 'IsGte(A,B)' ) {
        res = BigInt(a >= b);
    } else if ( calcop == 'IsLt(A,B)' ) {
        res = BigInt(a < b);
    } else if ( calcop == 'IsLte(A,B)' ) {
        res = BigInt(a <= b);
    } else if ( calcop == 'IsZero(A)' ) {
        res = BigInt(a == 0);
    } else if ( calcop == 'IsOne(A)' ) {
        res = BigInt(a == 1);
    } else if ( calcop == 'IsNeg(A)' ) {
        res = BigInt(a < 0);
    } else {
        return;
    }
    return String(res);
}
