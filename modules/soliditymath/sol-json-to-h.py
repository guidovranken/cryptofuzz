#!/usr/bin/env python3

import sys
import json

def tovector(h):
    ret = []
    while h:
        ret.append('0x' + h[:2])
        h = h[2:]
    return '{' + ', '.join(ret) + '}'

s = ''
s += 'const std::vector<Contract> contracts = {\n'

for f in sys.argv[1:]:
    with open(f, 'rb') as fp:
        j = json.loads(fp.read())

        contracts = j['contracts']

        for name in contracts:
            cur = contracts[name]
            s += '    Contract{\n'
            s += '        .name = "{}",\n'.format(name)
            s += '        .hashes = {\n'

            for k, v in cur['hashes'].items():
                calcop = None

                if k == 'mulDiv(uint256,uint256,uint256)':
                    calcop = 'CF_CALCOP("MulDiv(A,B,C)")'
                elif k == 'mulDivCeil(uint256,uint256,uint256)':
                    calcop = 'CF_CALCOP("MulDivCeil(A,B,C)")'
                elif k == 'sqrt(uint256)':
                    calcop = 'CF_CALCOP("Sqrt(A)")'
                elif k == 'sqrtCeil(uint256)':
                    calcop = 'CF_CALCOP("SqrtCeil(A)")'
                elif k == 'min(uint256,uint256)':
                    calcop = 'CF_CALCOP("Min(A,B)")'
                elif k == 'max(uint256,uint256)':
                    calcop = 'CF_CALCOP("Max(A,B)")'
                elif k == 'msb(uint256)':
                    calcop = 'CF_CALCOP("MSB(A)")'
                elif k == 'lsb(uint256)':
                    calcop = 'CF_CALCOP("LSB(A)")'
                elif k == 'add(uint256,uint256)':
                    calcop = 'CF_CALCOP("Add(A,B)")'
                elif k == 'sub(uint256,uint256)':
                    calcop = 'CF_CALCOP("Sub(A,B)")'
                elif k == 'mul(uint256,uint256)':
                    calcop = 'CF_CALCOP("Mul(A,B)")'
                elif k == 'mul512(uint256,uint256)':
                    calcop = 'CF_CALCOP("Mul(A,B)")'
                elif k == 'exp(uint256,uint256)':
                    calcop = 'CF_CALCOP("Exp(A,B)")'
                elif k == 'expDiv(uint256,uint256,uint256)':
                    calcop = 'CF_CALCOP("ExpDiv(A,B,C)")'
                elif k == 'invmod(uint256,uint256)':
                    calcop = 'CF_CALCOP("InvMod(A,B)")'
                elif k == 'mulMod(uint256,uint256,uint256)':
                    calcop = 'CF_CALCOP("MulMod(A,B,C)")'
                else:
                    assert(False)

                l = []
                l += ['"{}"'.format(k)]
                l += [tovector(v)]

                s += '            '
                s += '{'
                s += calcop
                s += ', '
                s += '{'
                s += ', '.join(l)
                s += '}'
                s += '},\n'
            s += '        },\n'

            s += '        .bytecode = '
            s += tovector(cur['bin-runtime'])
            s += ',\n'
            s += '    },\n'
s += '};\n'

with open('contracts.h', 'wb') as fp:
    fp.write(s.encode('utf-8'))
