import sys
from typing import List
import os
import json
from starkware.cairo.lang.vm.cairo_runner import CairoRunner
from starkware.cairo.lang.vm.memory_dict import MemoryDict
from starkware.cairo.lang.compiler.program import Program

MOD = 0x800000000000011000000000000000000000000000000000000000000000001
BASE = 77371252455336267181195264

with open(os.path.dirname(sys.argv[0]) + '/ff-cairo-harness.json', 'rb') as fp:
    lib_ff_cairo = json.loads(fp.read())

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

    ret += [ i % BASE ]
    i //= BASE

    ret += [ i % BASE ]
    i //= BASE

    ret += [ i % BASE ]
    i //= BASE

    if i != 0:
        raise Exception("Value too large for felt")

    return ret
def from_BigInt3(s):
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

    if to_int(op['bn2']) == 0:
        return

    params = []

    try:
        params += [ to_BigInt3(op['bn0']) ]
        params += [ to_BigInt3(op['bn1']) ]
        params += [ to_BigInt3(op['bn2']) ]
    except:
        pass

    params = pack_params(params)

    res = from_BigInt3(
        call_func(lib_ff_cairo, 'cryptofuzz_bigint_mul_mod', params, 3)
    )

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')
