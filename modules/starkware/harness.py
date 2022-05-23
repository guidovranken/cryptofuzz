import sys
from typing import List
import os
import json
from starkware.cairo.lang.vm.cairo_runner import CairoRunner
from starkware.cairo.lang.vm.memory_dict import MemoryDict
from starkware.cairo.lang.compiler.program import Program

MOD = 0x800000000000011000000000000000000000000000000000000000000000001
BASE = 77371252455336267181195264
BASE_MIN_ONE = BASE - 1
BASE_BITS = 86
assert(1 << BASE_BITS == BASE)

with open(os.path.dirname(sys.argv[0]) + '/ff-cairo-harness.json', 'rb') as fp:
    lib_ff_cairo = json.loads(fp.read())

with open(os.path.dirname(sys.argv[0]) + '/common-ec-cairo-harness.json', 'rb') as fp:
    common_ec_cairo = json.loads(fp.read())

with open(os.path.dirname(sys.argv[0]) + '/cairo-alt_bn128-harness.json', 'rb') as fp:
    cairo_alt_bn128 = json.loads(fp.read())

def call_func(lib, func, args, retsize):
    program = Program.load(data=lib)
    initial_memory = MemoryDict()
    runner = CairoRunner(
        program=program,
        layout='plain',
        memory=initial_memory,
        proof_mode=False,
        allow_missing_builtins=False,
    )
    runner.initialize_segments()
    runner.execution_public_memory: List[int] = []
    end = runner.initialize_function_entrypoint(entrypoint=func, args=args)
    program_input = {}
    runner.initialize_vm(hint_locals={"program_input": program_input})
    runner.run_until_pc(end)
    runner.end_run()
    ret = []
    for i in range(retsize):
        ret += [ runner.vm.run_context.memory[runner.vm.run_context.ap - (i+1)] ]
    return ret[::-1]

def to_int(s):
    if s == '':
        s = 0
    return int(s)

def pack_params(p):
    ret = [len(p)]
    ret += p
    return ret

def to_BigInt3(s):
    i = to_int(s)

    ret = []

    ret += [ i & BASE_MIN_ONE ]
    i >>= BASE_BITS

    ret += [ i & BASE_MIN_ONE ]
    i >>= BASE_BITS

    ret += [ i & BASE_MIN_ONE ]
    i >>= BASE_BITS

    if i != 0:
        raise Exception("Value too large for felt")

    return ret
def from_BigInt3(v):
    assert len(v) == 3

    ret = 0

    ret += v[0] * (BASE**0)
    ret += v[1] * (BASE**1)
    ret += v[2] * (BASE**2)

    return ret

def from_UnreducedBigInt5(v):
    assert len(v) == 5

    ret = 0

    ret += v[0] * (BASE**0)
    ret += v[1] * (BASE**1)
    ret += v[2] * (BASE**2)
    ret += v[3] * (BASE**3)
    ret += v[4] * (BASE**4)

    return ret

def from_EcPoint(v):
    assert len(v) == 6

    return (
            from_BigInt3(v[0:3]),
            from_BigInt3(v[3:6]),
    )

def return_point(p):
    p = [str(s) for s in p]
    r = json.dumps(p)
    return bytes(r, 'utf-8')

def OpBignumCalc_AddMod(arg):
    op = json.loads(arg)

    if to_int(op['bn2']) == 0:
        return

    params = []

    try:
        params += to_BigInt3(op['bn0'])
        params += to_BigInt3(op['bn1'])
        params += to_BigInt3(op['bn2'])
    except:
        return

    params = pack_params(params)

    res = from_BigInt3(
        call_func(lib_ff_cairo, 'cryptofuzz_bigint_add_mod', params, 3)
    )

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpBignumCalc_SubMod(arg):
    op = json.loads(arg)

    if to_int(op['bn0']) == 0:
        return
    if to_int(op['bn1']) == 0:
        return
    if to_int(op['bn2']) == 0:
        return

    params = []

    try:
        params += to_BigInt3(op['bn0'])
        params += to_BigInt3(op['bn1'])
        params += to_BigInt3(op['bn2'])
    except:
        return

    params = pack_params(params)

    res = from_BigInt3(
            call_func(lib_ff_cairo, 'cryptofuzz_bigint_sub_mod', params, 3)
    )

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpBignumCalc_Mul(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['bn0'])
        params += to_BigInt3(op['bn1'])
    except:
        return

    params = pack_params(params)

    res = from_UnreducedBigInt5(
            call_func(lib_ff_cairo, 'cryptofuzz_bigint_mul', params, 5)
    )

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpBignumCalc_Mul_u(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['bn0'])
        params += to_BigInt3(op['bn1'])
    except:
        return

    params = pack_params(params)

    res = from_UnreducedBigInt5(
            call_func(lib_ff_cairo, 'cryptofuzz_bigint_mul_u', params, 5)
    )

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpBignumCalc_MulMod(arg):
    op = json.loads(arg)

    if to_int(op['bn0']) == 0:
        return
    if to_int(op['bn1']) == 0:
        return
    if to_int(op['bn2']) == 0:
        return

    params = []

    try:
        params += to_BigInt3(op['bn0'])
        params += to_BigInt3(op['bn1'])
        params += to_BigInt3(op['bn2'])
    except:
        return

    params = pack_params(params)

    res = from_BigInt3(
        call_func(lib_ff_cairo, 'cryptofuzz_bigint_mul_mod', params, 3)
    )

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpECC_Point_Add(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
        params += to_BigInt3(op['b_x'])
        params += to_BigInt3(op['b_y'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_ecc_point_add', params, 6)
    )

    return_point(res)

def OpECC_Point_Mul(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
        params += to_BigInt3(op['b'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_ecc_point_mul', params, 6)
    )

    return_point(res)

def OpECC_Point_Dbl(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_ecc_point_dbl', params, 6)
    )

    return_point(res)

def OpECC_Point_Neg(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_ecc_point_neg', params, 6)
    )

    return_point(res)

def OpECC_ValidatePubkey(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_ecc_validatepubkey', params, 6)
    )

    return_point(res)

def OpBLS_G1_Add(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
        params += to_BigInt3(op['b_x'])
        params += to_BigInt3(op['b_y'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_bls_g1_add', params, 6)
    )

    return_point(res)

def OpBLS_G1_Mul(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
        params += to_BigInt3(op['b'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_bls_g1_mul', params, 6)
    )

    return_point(res)

def OpBLS_G1_Mul(arg):
    op = json.loads(arg)

    params = []

    try:
        params += to_BigInt3(op['a_x'])
        params += to_BigInt3(op['a_y'])
    except:
        return

    params = pack_params(params)

    res = from_EcPoint(
        call_func(common_ec_cairo, 'cryptofuzz_bls_g1_dbl', params, 6)
    )

    return_point(res)
