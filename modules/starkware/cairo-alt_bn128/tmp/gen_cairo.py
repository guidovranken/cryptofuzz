import sys, os
cwd = os.getcwd()
sys.path.append(cwd)

from utils.bn128_field import FQ, FQ2, FQ12, field_modulus
from utils.bn128_curve import twist, G2, G12, add, double, multiply, curve_order, neg
from utils.bn128_pairing import log_ate_loop_count, ate_loop_count


def split(num):
    BASE = 2 ** 86
    a = []
    for _ in range(3):
        num, residue = divmod(num, BASE)
        a.append(residue)
    assert num == 0
    return a

def gen_range_checks():
    for i in range(12):
        for j in range(3):
            print(f'[range_check_ptr - {3*i+j + 1}] = res.e{i:X}.d{j}; ap++')

def gen_diff():
    print("let x_diff = FQ12(")
    for i in range(12):
        print('\tBigInt3(', end="")
        tmp = []
        for j in range(3):
            tmp.append(f'd{j}=pt0.x.e{i:X}.d{j} - pt1.x.e{i:X}.d{j}')
        print(", ".join(tmp) + "),")
    print("\t)")

def cairo_bigint3(x):
    res = 'BigInt3('
    tmp = []
    for i,x in enumerate(split(x)):
        tmp.append(f'd{i}={x}')
    res += ", ".join(tmp) + ")"
    return res

def cairo_FQ2(x):
    res = "FQ2(\n\t"
    res += cairo_bigint3(x.coeffs[0].n) 
    res += ", "
    res += cairo_bigint3(x.coeffs[1].n) 
    res += ')'
    return res

def cairo_G2(pt):
    res = "G2Point(\n"
    res += "\t" + cairo_FQ2(pt[0]) + ",\n"
    res += "\t" + cairo_FQ2(pt[1]) 
    res += ")"
    return res

def cairo_FQ12(x):
    res = "FQ12(\n\t"
    for i in range(12):

        res += cairo_bigint3(x.coeffs[i].n) 
        res += ", "
        if i % 3 == 2:
            res += '\n\t'
    res += ')'
    return res

def cairo_G12(pt):
    res = "GTPoint(\n"
    res += "\t" + cairo_FQ12(pt[0]) + ",\n"
    res += "\t" + cairo_FQ12(pt[1]) 
    res += ")"
    return res

def cairo_G12_constants():
    one, two, three = G12, double(G12), multiply(G12, 3)
    negone, negtwo, negthree = multiply(G12, curve_order - 1), multiply(G12, curve_order - 2), multiply(G12, curve_order - 3)

    for pt in [two, three, negone, negtwo, negthree]:
        print(cairo_G12(pt))

def ate_loop_count_bits():
    bits = []
    for i in range(log_ate_loop_count, -1, -1):
        if ate_loop_count & (2**i):
            bits.append(1)
        else:
            bits.append(0)
        print(i, bits[-1])
    return bits

def cairo_loop_bits():
    print(f'{ate_loop_count:b}', len(f'{ate_loop_count:b}'))
    bits = ate_loop_count_bits()
    print("".join(map(str, bits)))
    print(bits)

    for b in bits[::-1]:
        print(f'dw {b}')
    print(len(bits))

def cairo_final_exponent():
    num = (field_modulus ** 12 - 1 ) // curve_order
    BASE = 2 ** (86*3)
    a = []
    for _ in range(12):
        num, residue = divmod(num, BASE)
        a.append(residue)
    assert num == 0

    res = "FQ12(\n\t"
    for i in range(12):
        res += cairo_bigint3(a[i]) 
        res += ", "
        if i % 3 == 2:
            res += '\n\t'
    res += ')'
    return res

def gen_diff23():
    print("let x_diff = UnreducedFQ23(")
    for i in range(23):
        print('\tUnreducedBigInt5(', end="")
        tmp = []
        for j in range(5):
            tmp.append(f'pt0.x.e{i:02X}.d{j} + pt1.x.e{i:02X}.d{j}')
        print(", ".join(tmp) + "),")
    print("\t)")

def gen_diff12_23():
    print("let x_diff = UnreducedFQ23(")
    for i in range(23):
        tmp = []
        if i < 12:
            print('\tUnreducedBigInt5(', end="")
            for j in range(5):
                tmp.append(f'pt0.x.e{i:02X}.d{j} - pt1.x.e{i:X}.d{j}')
            print(", ".join(tmp) + "),")
        else: 
            print(f'\tpt0.e{i:02X},')
        
    print("\t)")

# cairo_loop_bits()
# cairo_G12_constants()
# print(cairo_final_exponent())
# print(cairo_G2(neg(G2)))
# ufq12mul()

gen_diff12_23()