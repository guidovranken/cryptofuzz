#!/usr/bin/env python3

# Convert output of --dump-json to JavaScript tests

import sys
import json

def toBigInt(v):
    if v == '-':
        v = '-0'
    elif v == '':
        v = '0'
    return 'BigInteger.Parse("{}")'.format(v)

BIGNUMCALC_ADD_TPL = '{} + {} == {}'
BIGNUMCALC_SUB_TPL = '{} - {} == {}'
BIGNUMCALC_MUL_TPL = '{} * {} == {}'
BIGNUMCALC_DIV_TPL = '{} / {} == {}'
BIGNUMCALC_MOD_TPL = '{} % {} == {}'
BIGNUMCALC_EXPMOD_TPL = 'BigInteger.ModPow({}, {}, {}) == {}'
BIGNUMCALC_GCD_TPL = 'BigInteger.GreatestCommonDivisor({}, {}) == {}'

HEADER="""
using System;
using System.Numerics;
using System.Diagnostics;

namespace BigIntegerTests
{
    class Program
    {
        static void Main(string[] args)
        {
"""

FOOTER="""
        }
    }
}
"""

def constructAssert(cond):
    return 'Trace.Assert({});'.format(cond)

with open(sys.argv[1], 'rb') as fp:
    print(HEADER)
    i = 0
    for l in fp:

        j = json.loads(l)
        op = j['operation']

        if op['operation'] == 'BignumCalc':
            if op['calcOp'] == '10633833424446033180':
                tpl = BIGNUMCALC_ADD_TPL
            elif op['calcOp'] == '7565474059520578463':
                tpl = BIGNUMCALC_SUB_TPL
            elif op['calcOp'] == '12211643382727132651':
                tpl = BIGNUMCALC_MUL_TPL
            elif op['calcOp'] == '13646095757308424912':
                tpl = BIGNUMCALC_DIV_TPL
            elif op['calcOp'] == '12110391648600810285':
                tpl = BIGNUMCALC_MOD_TPL
            elif op['calcOp'] == '1317996975705594123':
                tpl = BIGNUMCALC_EXPMOD_TPL
            elif op['calcOp'] == '5785484340816638963':
                tpl = BIGNUMCALC_GCD_TPL
            else:
                continue

            i += 1

            numArgs = tpl.count('{}')

            if numArgs == 3:
                A = toBigInt(op['bn0'])
                B = toBigInt(op['bn1'])
                R = toBigInt(j['result'])
                print(
                    'Console.WriteLine({});\n'.format(i),
                    constructAssert(
                        tpl.format(A, B, R)
                    )
                )
            elif numArgs == 4:
                A = toBigInt(op['bn0'])
                B = toBigInt(op['bn1'])
                C = toBigInt(op['bn2'])
                R = toBigInt(j['result'])
                print(
                    'Console.WriteLine({});\n'.format(i),
                    constructAssert(
                        tpl.format(A, B, C, R)
                    )
                )
            else:
                assert(False)
    print(FOOTER)
