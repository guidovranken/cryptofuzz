from typing import List

from starkware.cairo.common.math_utils import as_int

PRIME = 2 ** 251 + 17 * 2 ** 192 + 1
ALTBN_PRIME = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47

def split(num: int) -> List[int]:
    BASE = 2 ** 86
    a = []
    for _ in range(3):
        num, residue = divmod(num, BASE)
        a.append(residue)
    assert num == 0
    return a

def pack(z):
    limbs = z.d0, z.d1, z.d2
    return sum(as_int(limb, PRIME) * 2 ** (86 * i) for i, limb in enumerate(limbs)) % ALTBN_PRIME

def print_fq(name, e): 
    print(name, pack(e))

def parse_fq2(e):
    e0,e1 = pack(e.e0), pack(e.e1)
    return [e0 , e1]

def print_fq2(name, e):
    res = parse_fq2(e)
    print(name, res)

def parse_fq12(e):
    e0,e1,e2,e3 = pack(e.e0), pack(e.e1), pack(e.e2), pack(e.e3)
    e4,e5,e6,e7 = pack(e.e4), pack(e.e5), pack(e.e6), pack(e.e7)
    e8,e9,eA,eB = pack(e.e8), pack(e.e9), pack(e.eA), pack(e.eB)
    return [e0,e1,e2,e3,e4,e5,e6,e7,e8,e9,eA,eB]

def print_fq12(name, e):
    res = parse_fq12(e)
    print(name, res)

def print_g1(name, e):
    print(name)
    print_fq("  x", e.x) 
    print_fq("  y", e.y) 

def print_g2(name, e):
    print(name)
    print_fq2("  x", e.x) 
    print_fq2("  y", e.y) 

def print_g12(name, e):
    print(name)
    print_fq12("  x", e.x) 
    print_fq12("  y", e.y) 