module cryptofuzz;

import core.stdc.stdio;
import std.string;
import std.conv;
import std.stdio;
import core.stdc.stdlib;
import core.stdc.string;

import std.bigint;

BigInt loadBn(string bn) {
    if ( bn == "" ) {
        return BigInt("0");
    } else {
        return BigInt(bn);
    }
}

extern(C) char* cryptofuzz_d_bignumcalc(
        const char* bn0str,
        const char* bn1str,
        const char* bn2str,
        ulong calcOp)
{
    const BigInt bn0 = loadBn(to!string(bn0str));
    const BigInt bn1 = loadBn(to!string(bn1str));
    const BigInt bn2 = loadBn(to!string(bn2str));
    BigInt res;

    switch ( calcOp ) {
        case    10633833424446033180:
            res = bn0 + bn1;
            break;
        case 7565474059520578463:
            res = bn0 - bn1;
            break;
        case 12211643382727132651:
            res = bn0 * bn1;
            break;
        case 13646095757308424912:
            if (bn1 != BigInt(0) ) {
                res = bn0 / bn1;
            } else {
                return null;
            }
            break;
        case 12110391648600810285:
            if (bn1 != BigInt(0) ) {
                res = bn0 % bn1;
            } else {
                return null;
            }
            break;
        case 1317996975705594123:
            if (bn1 == BigInt(0) ) {
                return null;
            }
            if (bn2 == BigInt(0) ) {
                return null;
            }
            res = powmod(bn0, bn1, bn2);
            break;
        case 2652194927012011212:
            res = bn0 | bn1;
            break;
        case 1431659550035644982:
            res = bn0 & bn1;
            break;
        case 14328566578340454326:
            res = bn0 ^ bn1;
            break;
        default:
            return null;
    }

    string s = to!string(res);
    char* str = cast(char*) malloc(s.length + 1);
    memcpy(str, s.ptr, s.length);
    str[s.length] = '\0';
    return str;
}
