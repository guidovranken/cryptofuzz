import sys
import os
import json
from starkware.cairo.lang.vm.cairo_runner import CairoRunner
from starkware.cairo.lang.vm.memory_dict import MemoryDict
from starkware.cairo.lang.compiler.program import Program

with open(os.path.dirname(sys.argv[0]) + '/ff-cairo-harness.json', 'rb') as fp:
    lib_ff_cairo = json.loads(fp.read())

def call_func(lib, func, args):
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
    end = runner.initialize_function_entrypoint(entrypoint=func, args=args)
    program_input = {}
    runner.initialize_vm(hint_locals={"program_input": program_input})

def to_int(s):
    if s == '':
        s = 0
    return int(s)

def pack_params(p):
    ret = [len(p)]
    ret += p
    return ret

def to_BigInt3(s):
    # XXX
    return 0
def from_BigInt3(s):
    # XXX
    return 0
def from_UnreducedBigInt5(v):
    # XXX
    return 0

def OpBignumCalc_AddMod(arg):
    op = json.loads(arg)

    params = []
    params += [ to_BigInt3(op['bn0']) ]
    params += [ to_BigInt3(op['bn1']) ]
    params += [ to_BigInt3(op['bn2']) ]
    params = pack_params(params)
    res = from_BigInt3(
        call_func(lib_ff_cairo, 'cryptofuzz_bigint_add_mod', params)
    )

    # TODO
    return

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpBignumCalc_SubMod(arg):
    op = json.loads(arg)

    params = []
    params += [ to_BigInt3(op['bn0']) ]
    params += [ to_BigInt3(op['bn1']) ]
    params += [ to_BigInt3(op['bn2']) ]
    params = pack_params(params)
    res = from_BigInt3(
        call_func(lib_ff_cairo, 'cryptofuzz_bigint_sub_mod', params)
    )

    # TODO
    return

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpBignumCalc_Mul(arg):
    op = json.loads(arg)

    params = []
    params += [ to_BigInt3(op['bn0']) ]
    params += [ to_BigInt3(op['bn1']) ]
    params = pack_params(params)
    res = from_UnreducedBigInt5(
        call_func(lib_ff_cairo, 'cryptofuzz_bigint_mul', params)
    )

    # TODO
    return

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpBignumCalc_MulMod(arg):
    op = json.loads(arg)

    params = []
    params += [ to_BigInt3(op['bn0']) ]
    params += [ to_BigInt3(op['bn1']) ]
    params += [ to_BigInt3(op['bn2']) ]
    params = pack_params(params)
    res = from_BigInt3(
        call_func(lib_ff_cairo, 'cryptofuzz_bigint_div_mod', params)
    )
    # TODO
    return

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')
