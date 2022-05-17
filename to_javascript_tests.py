#!/usr/bin/env python3

# Convert output of --dump-json to JavaScript tests

import sys
import json

def toBigInt(v):
    if v == '-':
        v = '-0'
    return 'BigInt("{}")'.format(v)

BIGNUMCALC_ADD_TPL = '{} + {} == {}'
BIGNUMCALC_SUB_TPL = '{} - {} == {}'
BIGNUMCALC_MUL_TPL = '{} * {} == {}'
BIGNUMCALC_DIV_TPL = '{} / {} == {}'
BIGNUMCALC_MOD_TPL = '{} % {} == {}'

def constructAssert(cond):
    return 'console.assert({});'.format(cond)

with open(sys.argv[1], 'rb') as fp:
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
            else:
                continue

            print(
                constructAssert(
                    tpl.format(
                        toBigInt(op['bn0']),
                        toBigInt(op['bn1']),
                        toBigInt(j['result'])
                    )
                )
            )
