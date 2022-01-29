from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls.g2_primitives import pubkey_to_G1, G2_to_signature, signature_to_G2, G1_to_pubkey, G2_to_signature, subgroup_check
from py_ecc.bls.hash_to_curve import hash_to_G2, map_to_curve_G2, clear_cofactor_G2
from py_ecc.fields import optimized_bls12_381_FQ as FQ
from py_ecc.fields import optimized_bls12_381_FQ2 as FQ2
from py_ecc.optimized_bls12_381 import is_on_curve
from py_ecc.optimized_bls12_381 import b, b2
from py_ecc.utils import prime_field_inv
from py_ecc.optimized_bls12_381.optimized_swu import sqrt_division_FQ2, iso_map_G2
from py_ecc.optimized_bls12_381.optimized_curve import add, multiply, neg
from py_ecc.bls.point_compression import decompress_G1, compress_G1, decompress_G2, compress_G2
from hashlib import sha256
import json

MOD = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
def to_int(s):
    if s == '':
        s = 0
    return int(s)
def to_int_from_binary(b):
    return int.from_bytes(b, byteorder='big')

def is_valid(v):
    for _v in v:
        if (_v%MOD) == 0 or _v >= (MOD*2):
            return False
    return True

def OpBLS_PrivateToPublic(arg):
    op = json.loads(arg)

    private_key = to_int(op['priv'])
    if private_key > 115792089237316195423570985008687907853269984665640564039457584007913129639935:
        point = ['0' ,'0']
        r = json.dumps(point)
        return bytes(r, 'utf-8')

    private_key %= 52435875175126190479447740508185965837690552500527637822603658699938581184513

    if private_key == 0:
        point = ['0' ,'0']
        r = json.dumps(point)
        return bytes(r, 'utf-8')

    public_key = bls_pop.SkToPk(private_key)
    point = pubkey_to_G1(public_key)
    point = [str(point[0]), str(point[1])]
    r = json.dumps(point)
    return bytes(r, 'utf-8')

    #except:
    #    point = ['0' ,'0']
    #    r = json.dumps(point)
    #    return bytes(r, 'utf-8')

def OpBLS_IsG1OnCurve(arg):
    op = json.loads(arg)
    x = to_int(op['g1_x'])
    y = to_int(op['g1_y'])

    g1 = [FQ(x), FQ(y), FQ.one()]

    if is_valid([x,y]) == False:
        return

    #r = json.dumps(is_on_curve(g2, b2))
    r = json.dumps(is_on_curve(g1, b) and subgroup_check(g1))
    return bytes(r, 'utf-8')

def OpBLS_IsG2OnCurve(arg):
    op = json.loads(arg)
    v = to_int(op['g2_v'])
    w = to_int(op['g2_w'])
    x = to_int(op['g2_x'])
    y = to_int(op['g2_y'])

    g2 = (FQ2((v, x)), FQ2((w, y)), FQ2.one())

    if is_valid([v,w,x,y]) == False:
        return

    r = json.dumps(is_on_curve(g2, b2) and subgroup_check(g2))
    return bytes(r, 'utf-8')

def OpBLS_HashToG2(arg):
    return
    op = json.loads(arg)

    dst = bytes.fromhex(op['dest'])
    if len(dst) > 255:
        return
    #dst = b'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_'

    cleartext = bytes.fromhex(op['cleartext'])
    aug = bytes.fromhex(op['aug'])
    msg = aug + cleartext

    point = hash_to_G2(msg, dst, sha256)

    x = point[0] / point[2]
    y = point[1] / point[2]

    point = [[str(x.coeffs[0]), str(y.coeffs[0])], [str(x.coeffs[1]), str(y.coeffs[1])]]

    r = json.dumps(point)
    return bytes(r, 'utf-8')

def OpBLS_MapToG2(arg):
    op = json.loads(arg)

    u_x = to_int(op['u_x'])
    u_y = to_int(op['u_y'])
    v_x = to_int(op['v_x'])
    v_y = to_int(op['v_y'])

    u = FQ2((u_x, u_y))
    v = FQ2((v_x, v_y))

    g2_u = map_to_curve_G2(u)
    g2_v = map_to_curve_G2(v)
    r = add(g2_u, g2_v)
    point = clear_cofactor_G2(r)

    x = point[0] / point[2]
    y = point[1] / point[2]

    point = [[str(x.coeffs[0]), str(y.coeffs[0])], [str(x.coeffs[1]), str(y.coeffs[1])]]

    r = json.dumps(point)
    return bytes(r, 'utf-8')

def OpBLS_Verify(arg):
    op = json.loads(arg)

    verified = False

    g1_x = to_int(op['g1_x'])
    g1_y = to_int(op['g1_y'])

    g1 = [FQ(g1_x), FQ(g1_y), FQ.one()]

    if is_on_curve(g1, b) == False:
        r = json.dumps(verified)
        return bytes(r, 'utf-8')

    g1 = G1_to_pubkey(g1)


    g2_v = to_int(op['g2_v'])
    g2_w = to_int(op['g2_w'])
    g2_x = to_int(op['g2_x'])
    g2_y = to_int(op['g2_y'])

    g2 = (FQ2((g2_v, g2_x)), FQ2((g2_w, g2_y)), FQ2.one())
    try:
        g2 = G2_to_signature(g2)
    except:
        r = json.dumps(verified)
        return bytes(r, 'utf-8')

    msg = bytes.fromhex(op['cleartext'])

    verified = bls_pop.Verify(g1, msg, g2)

    r = json.dumps(verified)
    return bytes(r, 'utf-8')

def OpBLS_Sign(arg):
    op = json.loads(arg)

    private_key = to_int(op['priv'])
    if private_key == 0 or private_key >= 52435875175126190479447740508185965837690552500527637822603658699938581184513:
        return

    cleartext = bytes.fromhex(op['cleartext'])
    aug = bytes.fromhex(op['aug'])
    msg = aug + cleartext

    signature = bls_pop.Sign(private_key, msg)

    signature = signature_to_G2(signature)

    x = signature[0] / signature[2]
    y = signature[1] / signature[2]

    signature = [[str(x.coeffs[0]), str(y.coeffs[0])], [str(x.coeffs[1]), str(y.coeffs[1])]]

    public_key = bls_pop.SkToPk(private_key)
    point = pubkey_to_G1(public_key)
    point = [str(point[0]), str(point[1])]

    j = {}
    j['signature'] = signature
    j['pub'] = point

    r = json.dumps(j)
    return bytes(r, 'utf-8')

def OpBignumCalc_InvMod(arg):
    op = json.loads(arg)

    a = to_int(op['a'])
    mod = to_int(op['mod'])

    res = prime_field_inv(a, mod)

    r = json.dumps(str(res))
    return bytes(r, 'utf-8')

def OpMisc_Fq2_Sqrt(arg):
    op = json.loads(arg)

    a_x = to_int_from_binary(op['a_x'])
    a_y = to_int_from_binary(op['a_y'])
    a = FQ2((a_x, a_y))

    b_x = to_int_from_binary(op['b_x'])
    b_y = to_int_from_binary(op['b_y'])
    b = FQ2((b_x, b_y))

    sqrt_division_FQ2(a, b)

def OpMisc_Iso_Map_G2(arg):
    op = json.loads(arg)

    a_x = to_int_from_binary(op['a_x'])
    a_y = to_int_from_binary(op['a_y'])
    a = FQ2((a_x, a_y))

    b_x = to_int_from_binary(op['b_x'])
    b_y = to_int_from_binary(op['b_y'])
    b = FQ2((b_x, b_y))

    c_x = to_int_from_binary(op['c_x'])
    c_y = to_int_from_binary(op['c_y'])
    c = FQ2((c_x, c_y))

    iso_map_G2(a, b, c)

def OpMisc_Multiply(arg):
    op = json.loads(arg)

    a_x = to_int_from_binary(op['a_x'])
    a_y = to_int_from_binary(op['a_y'])
    a = FQ2((a_x, a_y))

    b_x = to_int_from_binary(op['b_x'])
    b_y = to_int_from_binary(op['b_y'])
    b = FQ2((b_x, b_y))

    c_x = to_int_from_binary(op['c_x'])
    c_y = to_int_from_binary(op['c_y'])
    c = FQ2((c_x, c_y))

    multiplier = to_int_from_binary(op['multiplier'])

    x = [a, b, c]

    multiply(x, multiplier)

def OpBLS_Decompress_G1(arg):
    op = json.loads(arg)

    compressed = to_int(op['compressed'])
    try:
        point = decompress_G1(compressed)
    except ValueError:
        r = json.dumps(['0', '0'])
        return bytes(r, 'utf-8')

    point = [str(point[0]), str(point[1])]

    if point == ['1', '1']:
        point = ['0', '0']

    r = json.dumps(point)
    return bytes(r, 'utf-8')

def OpBLS_Compress_G1(arg):
    op = json.loads(arg)
    x = to_int(op['g1_x'])
    y = to_int(op['g1_y'])

    if (x % MOD, y % MOD) == (0, 0):
        return

    g1 = [FQ(x), FQ(y), FQ.one()]

    compressed = compress_G1(g1)
    if is_valid([x,y]) == True and is_on_curve(g1, b):
        decompressed = decompress_G1(compressed)
        assert g1[0] == decompressed[0] and g1[1] == decompressed[1]

    r = json.dumps(str(compressed))
    return bytes(r, 'utf-8')

def OpBLS_Decompress_G2(arg):
    op = json.loads(arg)

    compressed = [to_int(op['g1_x']), to_int(op['g1_y'])]
    try:
        point = decompress_G2(compressed)
    except ValueError:
        r = json.dumps([['0', '0'], ['0', '0']])
        return bytes(r, 'utf-8')

    x = point[0] / point[2]
    y = point[1] / point[2]

    point = [[str(x.coeffs[0]), str(y.coeffs[0])], [str(x.coeffs[1]), str(y.coeffs[1])]]

    r = json.dumps(point)
    return bytes(r, 'utf-8')

def OpBLS_Compress_G2(arg):
    op = json.loads(arg)

    v = to_int(op['g2_v'])
    w = to_int(op['g2_w'])
    x = to_int(op['g2_x'])
    y = to_int(op['g2_y'])

    g2 = (FQ2((v, x)), FQ2((w, y)), FQ2.one())

    try:
        compressed = compress_G2(g2)
    except ValueError:
        return

    point = [str(compressed[0]), str(compressed[1])]

    r = json.dumps(point)
    return bytes(r, 'utf-8')

def OpBLS_G1_Add(arg):
    op = json.loads(arg)
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])
    b_x = to_int(op['b_x'])
    b_y = to_int(op['b_y'])

    if (a_x % MOD, a_y % MOD) == (0, 0):
        return
    if (b_x % MOD, b_y % MOD) == (0, 0):
        return

    A = [FQ(a_x), FQ(a_y), FQ.one()]
    B = [FQ(b_x), FQ(b_y), FQ.one()]

    if not (is_on_curve(A, b) and subgroup_check(A)):
        return
    if not (is_on_curve(B, b) and subgroup_check(B)):
        return

    result = add(A, B)

    result = [str(result[0] / result[2]), str(result[1] / result[2])]
    r = json.dumps(result)
    return bytes(r, 'utf-8')

def OpBLS_G1_Mul(arg):
    op = json.loads(arg)
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])
    B = to_int(op['b'])

    if (a_x % MOD, a_y % MOD) == (0, 0):
        return

    A = [FQ(a_x), FQ(a_y), FQ.one()]

    if not (is_on_curve(A, b) and subgroup_check(A)):
        return

    result = multiply(A, B)

    result = [str(result[0] / result[2]), str(result[1] / result[2])]
    r = json.dumps(result)
    return bytes(r, 'utf-8')

def OpBLS_G1_IsEq(arg):
    op = json.loads(arg)
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])
    b_x = to_int(op['b_x'])
    b_y = to_int(op['b_y'])

    if (a_x % MOD, a_y % MOD) == (0, 0):
        return
    if (b_x % MOD, b_y % MOD) == (0, 0):
        return

    A = [FQ(a_x), FQ(a_y), FQ.one()]
    B = [FQ(b_x), FQ(b_y), FQ.one()]

    r = json.dumps(A == B)
    return bytes(r, 'utf-8')

def OpBLS_G1_Neg(arg):
    op = json.loads(arg)
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])

    if (a_x % MOD, a_y % MOD) == (0, 0):
        return

    A = [FQ(a_x), FQ(a_y), FQ.one()]

    result = neg(A)

    result = [str(result[0] / result[2]), str(result[1] / result[2])]
    r = json.dumps(result)
    return bytes(r, 'utf-8')

def OpBLS_G2_Add(arg):
    op = json.loads(arg)
    a_v = to_int(op['a_v'])
    a_w = to_int(op['a_w'])
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])
    b_v = to_int(op['b_v'])
    b_w = to_int(op['b_w'])
    b_x = to_int(op['b_x'])
    b_y = to_int(op['b_y'])

    A = (FQ2((a_v, a_x)), FQ2((a_w, a_y)), FQ2.one())
    B = (FQ2((b_v, b_x)), FQ2((b_w, b_y)), FQ2.one())

    if not (is_on_curve(A, b2) and subgroup_check(A)):
        return
    if not (is_on_curve(B, b2) and subgroup_check(B)):
        return

    result = add(A, B)

    x = result[0] / result[2]
    y = result[1] / result[2]

    result = [[str(x.coeffs[0]), str(y.coeffs[0])], [str(x.coeffs[1]), str(y.coeffs[1])]]

    r = json.dumps(result)
    return bytes(r, 'utf-8')

def OpBLS_G2_Mul(arg):
    op = json.loads(arg)
    a_v = to_int(op['a_v'])
    a_w = to_int(op['a_w'])
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])
    B = to_int(op['b'])

    A = (FQ2((a_v, a_x)), FQ2((a_w, a_y)), FQ2.one())

    if not (is_on_curve(A, b2) and subgroup_check(A)):
        return

    result = multiply(A, B)

    x = result[0] / result[2]
    y = result[1] / result[2]

    result = [[str(x.coeffs[0]), str(y.coeffs[0])], [str(x.coeffs[1]), str(y.coeffs[1])]]

    r = json.dumps(result)
    return bytes(r, 'utf-8')

def OpBLS_G2_IsEq(arg):
    op = json.loads(arg)
    a_v = to_int(op['a_v'])
    a_w = to_int(op['a_w'])
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])
    b_v = to_int(op['b_v'])
    b_w = to_int(op['b_w'])
    b_x = to_int(op['b_x'])
    b_y = to_int(op['b_y'])

    A = (FQ2((a_v, a_x)), FQ2((a_w, a_y)), FQ2.one())
    B = (FQ2((b_v, b_x)), FQ2((b_w, b_y)), FQ2.one())

    r = json.dumps(A == B)
    return bytes(r, 'utf-8')

def OpBLS_G2_Neg(arg):
    op = json.loads(arg)
    a_v = to_int(op['a_v'])
    a_w = to_int(op['a_w'])
    a_x = to_int(op['a_x'])
    a_y = to_int(op['a_y'])

    A = (FQ2((a_v, a_x)), FQ2((a_w, a_y)), FQ2.one())

    result = neg(A)

    x = result[0] / result[2]
    y = result[1] / result[2]

    result = [[str(x.coeffs[0]), str(y.coeffs[0])], [str(x.coeffs[1]), str(y.coeffs[1])]]

    r = json.dumps(result)
    return bytes(r, 'utf-8')
