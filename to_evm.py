#!/usr/bin/env python3

import json
import sys
from hashlib import sha1
from typing import List, Union

infile = sys.argv[1]
outdir = sys.argv[2]

def ToBytes(i: int, size: int = 32) -> bytes:
    if size == 0:
        size = (len(hex(i)[2:]) + 1) // 2
    return i.to_bytes(size, 'big')

def ToInt(s: str) -> int:
    if s == '':
        s = '0'
    return int(s)

def ToLenBytes(i: int) -> bytes:
    l = (len(hex(i)[2:]) + 1) // 2
    return ToBytes(l)

def Push32(val: Union[int, bytes]) -> bytes:
    ret = bytes()
    ret += bytes([0x7f])

    if type(val) == int:
        ret += ToBytes(val)
    elif type(val) == bytes:
        assert(len(val) == 32)
        ret += val
    else:
        assert(False)

    return ret

def Store32(pos: int, val: Union[int, bytes]) -> bytes:
    ret = bytes()
    ret += Push32(val)
    ret += Push32(pos)
    ret += bytes([0x52])
    return ret

def Store(data: bytes) -> bytes:
    ret = bytes()
    num32 = len(data) // 32
    rem = len(data) % 32

    pos = 0
    for i in range(num32):
        ret += Store32(pos, data[i*32 : i*32+32])
        pos += 32

    if rem:
        remd = data[num32*32:]
        assert(len(remd) < 32)
        remd = remd + ((32 - len(remd)) * b'\x00')
        assert(len(remd) == 32)
        ret += Store32(pos, remd)
        pos += 32

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

def MSize() -> bytes:
    ret = bytes()
    ret += bytes([0x59])
    return ret

def Load(num: int) -> bytes:
    ret = bytes()
    for i in range(num):
        ret += MLoad(i * 32)
    return ret

def Precompile(
        address: int,
        params: Union[List[int], bytes],
        retLength: int) -> None:
    ret = bytes()

    if type(params) == list:
        pos = 0
        for p in params:
            ret += Store32(pos, p)
            pos += 32
        paramsLength = len(params) * 32
        retLength *= 32
    elif type(params) == bytes:
        ret += Store(params)
        paramsLength = len(params)
        retLength = 0
    else:
        assert(False)

    ret += Call(paramsLength, retLength, address)
    ret += MSize()
    ret += Load(retLength)

    fn = sha1(ret).hexdigest()
    with open('{}/{}'.format(outdir, fn), 'wb') as fp:
        fp.write(ret)

with open(infile, 'rb') as fp:
    for l in fp:

        j = json.loads(l)

        op = j['operation']

        if op == None:
            continue

        if 'operation' not in op.keys():
            continue

        try:
            if op['operation'] == "ECDSA_Recover":
                if op['curveType'] != '18393850816800450172':
                    continue
                if op['digestType'] != '7259431668663979670':
                    continue
                cleartext = op['cleartext']
                if len(cleartext) > 64:
                    continue
                cleartext = ('0' * (64 - len(cleartext))) + cleartext
                sig_r = ToInt(op['sig_r'])
                sig_s = ToInt(op['sig_s'])
                idd = (ToInt(op['id']) + 27) % 256
                ecrecover_input = bytes()
                ecrecover_input += bytes.fromhex(cleartext)
                ecrecover_input += ToBytes(idd)
                ecrecover_input += ToBytes(sig_r)
                ecrecover_input += ToBytes(sig_s)
                Precompile(1, ecrecover_input, 0)
            elif op['operation'] == "BLS_G1_Add":
                #if op['curveType'] != '9285907260089714809':
                #    continue
                params = [
                        ToInt(op['a_x']),
                        ToInt(op['a_y']),
                        ToInt(op['b_x']),
                        ToInt(op['b_y'])
                ]
                Precompile(6, params, 2)
            elif op['operation'] == "BLS_G1_Mul":
                #if op['curveType'] != '9285907260089714809':
                #    continue
                params = [
                        ToInt(op['a_x']),
                        ToInt(op['a_y']),
                        ToInt(op['b']),
                ]
                Precompile(7, params, 2)
            elif op['operation'] == "BLS_BatchVerify":
                #if op['curveType'] != '9285907260089714809':
                #    continue
                params = []
                for cur in op['bf']:
                    params += [ ToInt(cur['g1_x']) ]
                    params += [ ToInt(cur['g1_y']) ]
                    params += [ ToInt(cur['g2_x']) ]
                    params += [ ToInt(cur['g2_v']) ]
                    params += [ ToInt(cur['g2_y']) ]
                    params += [ ToInt(cur['g2_w']) ]
                Precompile(8, params, 0)

            elif op['operation'] == "BignumCalc":
                if op['calcOp'] != '1317996975705594123':
                    continue
                base = ToInt(op['bn0'])
                exp = ToInt(op['bn1'])
                mod = ToInt(op['bn2'])

                modexp_input = bytes()
                modexp_input += ToLenBytes(base)
                modexp_input += ToLenBytes(exp)
                modexp_input += ToLenBytes(mod)
                modexp_input += ToBytes(base, 0)
                modexp_input += ToBytes(exp, 0)
                modexp_input += ToBytes(mod, 0)

                modexp_input = Store(modexp_input)

                Precompile(5, modexp_input, 0)
                # TODO pop memory
            else:
                continue
        except OverflowError:
            pass
