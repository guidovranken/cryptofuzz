#!/usr/bin/env python3

import json
import sys
from hashlib import sha1
from typing import List

infile = sys.argv[1]
outdir = sys.argv[2]

def Push32(val: int) -> bytes:
    ret = bytes()
    ret += bytes([0x7f])
    ret += val.to_bytes(32, 'big')
    return ret

def Store32(pos: int, val: int) -> bytes:
    ret = bytes()
    ret += Push32(val)
    ret += Push32(pos)
    ret += bytes([0x52])
    return ret

def Gas() -> bytes:
    return bytes([0x5a])

def DelegateCall() -> bytes:
    return bytes([0xf4])

def Call(argsLength: int, retLength: int, address: int) -> bytes:
    ret = bytes()
    ret += Push32(retLength) # retLength
    ret += Push32(0) # retOffset
    ret += Push32(argsLength) # argsLength
    ret += Push32(0) # argsOffset
    ret += Push32(address) # address
    ret += Gas() # gas
    ret += DelegateCall()
    return ret

def MLoad(pos: int) -> bytes:
    ret = bytes()
    ret += Push32(pos)
    ret += bytes([0x51])
    return ret

def Load(num: int) -> bytes:
    ret = bytes()
    for i in range(num):
        ret += MLoad(i * 32)
    return ret

def Precompile(address: int, params: List[int], retLength: int):
    ret = bytes()

    i = 0
    for p in params:
        ret += Store32(i, p)
        i += 32

    ret += Call(len(params) * 32, retLength * 32, address)
    ret += Load(retLength)

    fn = sha1(ret).hexdigest()
    with open('{}/{}'.format(outdir, fn), 'wb') as fp:
        fp.write(ret)

with open(infile, 'rb') as fp:
    for l in fp:

        j = json.loads(l)
        op = j['operation']

        ret = bytes()

        if 'operation' not in op.keys():
            continue

        try:
            if op['operation'] == "BLS_G1_Add":
                #if op['curveType'] != '9285907260089714809':
                #    continue
                params = [
                        int(op['a_x']),
                        int(op['a_y']),
                        int(op['b_x']),
                        int(op['b_y'])
                ]
                Precompile(6, params, 2)
            elif op['operation'] == "BLS_G1_Mul":
                #if op['curveType'] != '9285907260089714809':
                #    continue
                params = [
                        int(op['a_x']),
                        int(op['a_y']),
                        int(op['b']),
                ]
                Precompile(7, params, 2)
            else:
                continue

            fn = sha1(ret).hexdigest()
            with open('{}/{}'.format(outdir, fn), 'wb') as fp2:
                fp2.write(ret)
        except OverflowError:
            pass
