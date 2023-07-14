import constantine/math/arithmetic
import constantine/math/extension_fields
import constantine/math/io/io_bigints
import constantine/math/io/io_fields
import constantine/platforms/abstractions
import constantine/math/ec_shortweierstrass
import constantine/math/config/curves
import constantine/math/pairings/[pairings_generic, miller_accumulators]
import constantine/hash_to_curve/hash_to_curve
import constantine/hashes
import constantine/math/constants/zoo_subgroups
import constantine/ethereum_evm_precompiles
import constantine/ethereum_eip2333_bls12381_key_derivation
import constantine/ethereum_bls_signatures
import constantine/math/elliptic/ec_multi_scalar_mul
import constantine/threadpool/threadpool
import constantine/math/elliptic/ec_multi_scalar_mul_parallel
import constantine/math/elliptic/ec_scalar_mul_vartime

func loadFp(
       dst: var Fp[BN254_Snarks],
       src: openarray[byte]): bool =
  var big {.noInit.}: BigInt[254]
  big.unmarshal(src, bigEndian)

#if not bool(big < Fp[BN254_Snarks].fieldMod()):
#    return false

  dst.fromBig(big)
  return true

func loadFp(
       dst: var Fp[BLS12_381],
       src: openarray[byte]): bool =
  var big {.noInit.}: BigInt[381]
  big.unmarshal(src, bigEndian)

#  if not bool(big < Fp[BLS12_381].fieldMod()):
#     return false

  dst.fromBig(big)
  return true

func loadFr(
       dst: var Fr[BN254_Snarks],
       src: openarray[byte]): bool =
  var big {.noInit.}: BigInt[254]
  big.unmarshal(src, bigEndian)

  if not bool(big < Fr[BN254_Snarks].fieldMod()):
    return false

  dst.fromBig(big)
  return true

func loadFr(
       dst: var Fr[BLS12_381],
       src: openarray[byte]): bool =
  var big {.noInit.}: BigInt[255]
  big.unmarshal(src, bigEndian)

  if not bool(big < Fr[BLS12_381].fieldMod()):
    return false

  dst.fromBig(big)
  return true

func fpSize(t: typedesc): int =
  if t is Fp[BN254_Snarks]:
    result = 32
  elif t is Fp[BLS12_381]:
    result = 48
  elif t is Fp2[BN254_Snarks]:
    result = 32
  elif t is Fp2[BLS12_381]:
    result = 48
  elif t is Fp12[BN254_Snarks]:
    result = 32
  elif t is Fp12[BLS12_381]:
    result = 48
  else:
    assert(false)

func saveFp[FpType](
        R: FpType,
        r_bytes: ptr uint8) =
    var r: array[48, byte]
    var size = fpSize(FpType)
    r.toOpenArray(0, size-1).marshal(R, bigEndian)
    copyMem(r_bytes, addr r, size)

func saveFr[FrType](
        R: FrType,
        r_bytes: ptr uint8) =
    var r: array[32, byte]
    r.toOpenArray(0, 31).marshal(R, bigEndian)
    copyMem(r_bytes, addr r, r.len)

# Load G1 projective
func loadG1[FpType](
       dst: var ECP_ShortW_Prj[FpType, G1],
       g1_bytes: openarray[byte]): bool =
    var size = fpSize(FpType)
    if dst.x.loadFp(g1_bytes.toOpenArray(0, size-1)) == false:
        return false
    if dst.y.loadFp(g1_bytes.toOpenArray(size, (size*2)-1)) == false:
        return false
    dst.z.setOne()
    return true

# Load G1 affine
func loadG1[FpType](
       dst: var ECP_ShortW_Aff[FpType, G1],
       g1_bytes: openarray[byte]): bool =
    var P{.noInit.}: ECP_ShortW_Prj[FpType, G1]
    if loadG1(P, g1_bytes) == false:
        return false
    dst.affine(P)
    return true

# Save G1 affine
func saveG1[FpType](
        R: ECP_ShortW_Aff[FpType, G1],
        r_bytes: ptr uint8) =
    var r: array[48 * 2, byte]
    var size = fpSize(FpType)
    r.toOpenArray(0, size-1).marshal(R.x, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R.y, bigEndian)
    copyMem(r_bytes, addr r, size * 2)

# Save G1 projective
func saveG1[FpType](
        R: var ECP_ShortW_Prj[FpType, G1],
        r_bytes: ptr uint8) =
    var R_aff{.noInit.}: ECP_ShortW_Aff[FpType, G1]
    R_aff.affine(R)

    var r: array[48 * 2, byte]
    var size = fpSize(FpType)
    r.toOpenArray(0, size-1).marshal(R_aff.x, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R_aff.y, bigEndian)
    copyMem(r_bytes, addr r, size * 2)

# Save G1 jacobian
func saveG1[FpType](
        R: var ECP_ShortW_Jac[FpType, G1],
        r_bytes: ptr uint8) =
    var R_aff{.noInit.}: ECP_ShortW_Aff[FpType, G1]
    R_aff.affine(R)

    var size = fpSize(FpType)
    var r: array[48 * 2, byte]
    r.toOpenArray(0, size-1).marshal(R_aff.x, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R_aff.y, bigEndian)
    copyMem(r_bytes, addr r, size * 2)

# Load G2 projective
func loadG2[Fp2Type](
       dst: var ECP_ShortW_Prj[Fp2Type, G2],
       g2_bytes: openarray[byte]): bool =
    var size = fpSize(Fp2Type)
    if dst.x.c0.loadFp(g2_bytes.toOpenArray(0, size-1)) == false:
        return false
    if dst.y.c0.loadFp(g2_bytes.toOpenArray(size, (size*2)-1)) == false:
        return false
    if dst.x.c1.loadFp(g2_bytes.toOpenArray(size*2, (size*3)-1)) == false:
        return false
    if dst.y.c1.loadFp(g2_bytes.toOpenArray(size*3, (size*4)-1)) == false:
        return false
    dst.z.setOne()
    return true

# Load G2 affine
func loadG2[Fp2Type](
       dst: var ECP_ShortW_Aff[Fp2Type, G2],
       g2_bytes: openarray[byte]): bool =
    var P{.noInit.}: ECP_ShortW_Prj[Fp2Type, G2]
    if loadG2(P, g2_bytes) == false:
        return false
    dst.affine(P)
    return true

# Save G2 affine
func saveG2[Fp2Type](
        R: ECP_ShortW_Aff[Fp2Type, G2],
        r_bytes: ptr uint8) =
    var r: array[48 * 4, byte]
    var size = fpSize(Fp2Type)
    r.toOpenArray(0, size-1).marshal(R.x.c0, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R.y.c0, bigEndian)
    r.toOpenArray(size*2, (size*3)-1).marshal(R.x.c1, bigEndian)
    r.toOpenArray(size*3, (size*4)-1).marshal(R.y.c1, bigEndian)
    copyMem(r_bytes, addr r, size * 4)

# Save G2 projective
func saveG2[Fp2Type](
        R: var ECP_ShortW_Prj[Fp2Type, G2],
        r_bytes: ptr uint8) =
    var R_aff{.noInit.}: ECP_ShortW_Aff[Fp2Type, G2]
    R_aff.affine(R)

    var r: array[48 * 4, byte]
    var size = fpSize(Fp2Type)
    r.toOpenArray(0, size-1).marshal(R_aff.x.c0, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R_aff.y.c0, bigEndian)
    r.toOpenArray(size*2, (size*3)-1).marshal(R_aff.x.c1, bigEndian)
    r.toOpenArray(size*3, (size*4)-1).marshal(R_aff.y.c1, bigEndian)
    copyMem(r_bytes, addr r, size * 4)

# Save G2 jacobian
func saveG2[Fp2Type](
        R: var ECP_ShortW_Jac[Fp2Type, G2],
        r_bytes: ptr uint8) =
    var R_aff{.noInit.}: ECP_ShortW_Aff[Fp2Type, G2]
    R_aff.affine(R)

    var r: array[48*4, byte]
    var size = fpSize(Fp2Type)
    r.toOpenArray(0, size-1).marshal(R_aff.x.c0, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R_aff.y.c0, bigEndian)
    r.toOpenArray(size*2, (size*3)-1).marshal(R_aff.x.c1, bigEndian)
    r.toOpenArray(size*3, (size*4)-1).marshal(R_aff.y.c1, bigEndian)
    copyMem(r_bytes, addr r, r.len)

func loadFp2[Fp2Type](
        dst: var Fp2Type,
        fp2_bytes: openarray[byte]): bool =
    var size = fpSize(Fp2Type)
    if dst.c0.loadFp(fp2_bytes.toOpenArray(0, size-1)) == false:
        return false
    if dst.c1.loadFp(fp2_bytes.toOpenArray(size, (size*2)-1)) == false:
        return false
    return true

func saveFp2[Fp2Type](
        R: var Fp2Type,
        r_bytes: ptr uint8) =
    var r: array[96, byte]
    var size = fpSize(Fp2Type)
    r.toOpenArray(0, size-1).marshal(R.c0, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R.c1, bigEndian)
    copyMem(r_bytes, addr r, size * 2)

func loadFp12[Fp12Type](
        dst: var Fp12Type,
        fp12_bytes: openarray[byte]): bool =
    var size = fpSize(Fp12Type)
    if dst.c0.c0.c0.loadFp(fp12_bytes.toOpenArray(0, size-1)) == false:
        return false
    if dst.c0.c0.c1.loadFp(fp12_bytes.toOpenArray(size, (size*2)-1)) == false:
        return false
    if dst.c2.c0.c0.loadFp(fp12_bytes.toOpenArray((size*2), (size*3)-1)) == false:
        return false
    if dst.c2.c0.c1.loadFp(fp12_bytes.toOpenArray((size*3), (size*4)-1)) == false:
        return false
    if dst.c1.c1.c0.loadFp(fp12_bytes.toOpenArray((size*4), (size*5)-1)) == false:
        return false
    if dst.c1.c1.c1.loadFp(fp12_bytes.toOpenArray((size*5), (size*6)-1)) == false:
        return false
    if dst.c1.c0.c0.loadFp(fp12_bytes.toOpenArray((size*6), (size*7)-1)) == false:
        return false
    if dst.c1.c0.c1.loadFp(fp12_bytes.toOpenArray((size*7), (size*8)-1)) == false:
        return false
    if dst.c0.c1.c0.loadFp(fp12_bytes.toOpenArray((size*8), (size*9)-1)) == false:
        return false
    if dst.c0.c1.c1.loadFp(fp12_bytes.toOpenArray((size*9), (size*10)-1)) == false:
        return false
    if dst.c2.c1.c0.loadFp(fp12_bytes.toOpenArray((size*10), (size*11)-1)) == false:
        return false
    if dst.c2.c1.c1.loadFp(fp12_bytes.toOpenArray((size*11), (size*12)-1)) == false:
        return false
    return true

func saveFp12[Fp12Type](
        R: var Fp12Type,
        r_bytes: ptr uint8) =
    var r: array[576, byte]
    var size = fpSize(Fp12Type)
    r.toOpenArray(0, size-1).marshal(R.c0.c0.c0, bigEndian)
    r.toOpenArray(size, (size*2)-1).marshal(R.c0.c0.c1, bigEndian)
    r.toOpenArray((size*2), (size*3)-1).marshal(R.c2.c0.c0, bigEndian)
    r.toOpenArray((size*3), (size*4)-1).marshal(R.c2.c0.c1, bigEndian)
    r.toOpenArray((size*4), (size*5)-1).marshal(R.c1.c1.c0, bigEndian)
    r.toOpenArray((size*5), (size*6)-1).marshal(R.c1.c1.c1, bigEndian)
    r.toOpenArray((size*6), (size*7)-1).marshal(R.c1.c0.c0, bigEndian)
    r.toOpenArray((size*7), (size*8)-1).marshal(R.c1.c0.c1, bigEndian)
    r.toOpenArray((size*8), (size*9)-1).marshal(R.c0.c1.c0, bigEndian)
    r.toOpenArray((size*9), (size*10)-1).marshal(R.c0.c1.c1, bigEndian)
    r.toOpenArray((size*10), (size*11)-1).marshal(R.c2.c1.c0, bigEndian)
    r.toOpenArray((size*11), (size*12)-1).marshal(R.c2.c1.c1, bigEndian)
    copyMem(r_bytes, addr r, size * 12)

func validate[FpType, GType](
        P: var ECP_ShortW_Prj[FpType, GType]): bool =
    return bool(isOnCurve(P.x, P.y, GType)) and bool(P.isInSubgroup())

func validateAff[FpType, GType](
        P: var ECP_ShortW_Aff[FpType, GType]): bool =
    return bool(isOnCurve(P.x, P.y, GType)) and bool(P.isInSubgroup())

func cryptofuzz_constantine_bls_isg1oncurve_impl[FpType](
        a_bytes: openarray[uint8]) : cint =
    var P{.noInit.}: ECP_ShortW_Prj[FpType, G1]
    if loadG1(P, a_bytes) == false:
        return -1

    if validate[FpType, G1](P) == true:
        return 1
    else:
        return 0

proc cryptofuzz_constantine_bls_isg1oncurve(
        curve: uint8,
        a_bytes: openarray[uint8]) : cint {.exportc.} =
    if curve == 0:
        return cryptofuzz_constantine_bls_isg1oncurve_impl[Fp[BN254_Snarks]](a_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_isg1oncurve_impl[Fp[BLS12_381]](a_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_g1_add_impl[FpType](
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint =
    var A{.noInit.}, B{.noInit}, R{.noInit}: ECP_ShortW_Prj[FpType, G1]
    if loadG1(A, a_bytes) == false:
        return -1
    if loadG1(B, b_bytes) == false:
        return -1
    R.sum(A, B)
    saveG1(R, r_bytes)
    return 0

func cryptofuzz_constantine_bls_g1_add(
        curve: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g1_add_impl[Fp[BN254_Snarks]](a_bytes, b_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g1_add_impl[Fp[BLS12_381]](a_bytes, b_bytes, r_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_g1_mul_impl[FpType, BNType](
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        which: uint8,
        r_bytes: ptr uint8) : cint =
    var fail = false

    var A{.noInit.}: ECP_ShortW_Prj[FpType, G1]
    if loadG1(A, a_bytes) == false:
        return -1

    if validate[FpType, G1](A) == false:
        fail = true

    var B{.noInit.}: BNType
    B.unmarshal(b_bytes, bigEndian)

    if which == 0:
        A.scalarMul(B)
    elif which == 1:
        A.scalarMulGeneric(B)
    elif which == 2:
        A.scalarMul_doubleAdd_vartime(B)
    elif which == 3:
        A.scalarMul_minHammingWeight_vartime(B)
    elif which == 4:
        A.scalarMul_minHammingWeight_windowed_vartime(B, window = 3)
    elif which == 5:
        A.scalarMul_minHammingWeight_windowed_vartime(B, window = 16)
    else:
        assert(false)

    if fail == true:
        return -1

    saveG1(A, r_bytes)
    return 0

func cryptofuzz_constantine_bls_g1_mul(
        curve: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        which: uint8,
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g1_mul_impl[Fp[BN254_Snarks], BigInt[256]](a_bytes, b_bytes, which, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g1_mul_impl[Fp[BLS12_381], BigInt[384]](a_bytes, b_bytes, which, r_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_g1_multiexp_impl[FpType](
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        num: uint64,
        which: uint8,
        r_bytes: ptr uint8) : cint =
    const bnbits = FpType.C.getCurveOrderBitwidth()
    const bnbytes = (int)((bnbits + 7) / 8)
    var size = fpSize(FpType)

    var points = newSeq[ECP_ShortW_Aff[FpType, G1]](num)
    var scalars = newSeq[BigInt[bnbits]](num)

    var fail = false

    var R{.noInit}: ECP_ShortW_Jac[FpType, G1]
    var R_prj{.noInit}: ECP_ShortW_Prj[FpType, G1]

    if which == 0:
        R_prj.setInf()

    for i in countup(0, (int)num - 1):
        var A{.noInit.}: ECP_ShortW_Prj[FpType, G1]
        if loadG1(A, a_bytes.toOpenArray(i * 2 * size, i * 2 * size + (size * 2) - 1)) == false:
            return -1

        if validate[FpType, G1](A) == false:
            fail = true

        scalars[i].unmarshal(b_bytes.toOpenArray(i * bnbytes, (i+1) * bnbytes - 1), bigEndian)

        if which == 0:
            A.scalarMul(scalars[i])
            R_prj += A
        else:
            points[i].affine(A)
 
    if which == 0:
        if fail == true:
            return -1

        saveG1(R_prj, r_bytes)

        return 0
    elif which == 1:
        R.multiScalarMul_reference_vartime(scalars, points)
    elif which == 2:
        R.multiScalarMul_vartime(scalars, points)
    elif which == 3:
        {.noSideEffect.}:
            var tp = Threadpool.new()
            tp.multiScalarMul_vartime_parallel(R, scalars, points)
            tp.shutdown()
    else:
        assert(false)

    if fail == true:
        return -1

    saveG1(R, r_bytes)

    return 0

func cryptofuzz_constantine_bls_g1_multiexp(
        curve: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        num: uint64,
        which: uint8,
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g1_multiexp_impl[Fp[BN254_Snarks]](a_bytes, b_bytes, num, which, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g1_multiexp_impl[Fp[BLS12_381]](a_bytes, b_bytes, num, which, r_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_g1_neg_impl[FpType](
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint =
    var A{.noInit.}, R{.noInit}: ECP_ShortW_Prj[FpType, G1]
    if loadG1(A, a_bytes) == false:
        return -1
    R.neg(A)
    saveG1(R, r_bytes)
    return 0

func cryptofuzz_constantine_bls_g1_neg(
        curve: uint8,
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g1_neg_impl[Fp[BN254_Snarks]](a_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g1_neg_impl[Fp[BLS12_381]](a_bytes, r_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_g1_iseq_impl[FpType](
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8]) : cint =
    var A{.noInit.}, B{.noInit}: ECP_ShortW_Prj[FpType, G1]

    if loadG1(A, a_bytes) == false:
        return -1
    if loadG1(B, b_bytes) == false:
        return -1

    if bool A == B:
        return 1
    else:
        return 0

func cryptofuzz_constantine_bls_g1_iseq(
        curve: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8]) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g1_iseq_impl[Fp[BN254_Snarks]](a_bytes, b_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g1_iseq_impl[Fp[BLS12_381]](a_bytes, b_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_g1_dbl_impl[FpType](
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint =
    var A{.noInit.}, R{.noInit}: ECP_ShortW_Prj[FpType, G1]
    if loadG1(A, a_bytes) == false:
        return -1
    R.double(A)
    saveG1(R, r_bytes)
    return 0

func cryptofuzz_constantine_bls_g1_dbl(
        curve: uint8,
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g1_dbl_impl[Fp[BN254_Snarks]](a_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g1_dbl_impl[Fp[BLS12_381]](a_bytes, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_isg2oncurve_impl[Fp2Type](
        a_bytes: openarray[uint8]) : cint =
    var P{.noInit.}: ECP_ShortW_Prj[Fp2Type, G2]
    if loadG2(P, a_bytes) == false:
        return -1

    if validate[Fp2Type, G2](P) == true:
        return 1
    else:
        return 0

func cryptofuzz_constantine_bls_isg2oncurve(
        curve: uint8,
        a_bytes: openarray[uint8]) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_isg2oncurve_impl[Fp2[BN254_Snarks]](a_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_isg2oncurve_impl[Fp2[BLS12_381]](a_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_g2_add_impl[Fp2Type](
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint =
    var fail = false

    var A{.noInit.}, B{.noInit}, R{.noInit}: ECP_ShortW_Prj[Fp2Type, G2]
    if loadG2(A, a_bytes) == false:
        return -1

    if validate[Fp2Type, G2](A) == false:
        fail = true

    if loadG2(B, b_bytes) == false:
        return -1

    if validate[Fp2Type, G2](B) == false:
        fail = true

    R.sum(A, B)

    if fail == true:
        return -1

    saveG2(R, r_bytes)
    return 0

func cryptofuzz_constantine_bls_g2_add(
        curve: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g2_add_impl[Fp2[BN254_Snarks]](a_bytes, b_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g2_add_impl[Fp2[BLS12_381]](a_bytes, b_bytes, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_g2_mul_impl[Fp2Type](
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        which: uint8,
        r_bytes: ptr uint8) : cint =
    var fail = false

    var A{.noInit.}: ECP_ShortW_Prj[Fp2Type, G2]
    if loadG2(A, a_bytes) == false:
        return -1

    if validate[Fp2Type, G2](A) == false:
        fail = true

    var B{.noInit.}: BigInt[256]
    B.unmarshal(b_bytes, bigEndian)
    if which == 0:
        A.scalarMul(B)
    elif which == 1:
        A.scalarMulGeneric(B)
    elif which == 2:
        A.scalarMul_doubleAdd_vartime(B)
    elif which == 3:
        A.scalarMul_minHammingWeight_vartime(B)
    elif which == 4:
        A.scalarMul_minHammingWeight_windowed_vartime(B, window = 3)
    elif which == 5:
        A.scalarMul_minHammingWeight_windowed_vartime(B, window = 16)
    else:
        assert(false)

    if fail == true:
        return -1

    saveG2(A, r_bytes)
    return 0

func cryptofuzz_constantine_bls_g2_mul(
        curve: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        which: uint8,
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g2_mul_impl[Fp2[BN254_Snarks]](a_bytes, b_bytes, which, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g2_mul_impl[Fp2[BLS12_381]](a_bytes, b_bytes, which, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_g2_neg_impl[Fp2Type](
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint =
    var A{.noInit.}, R{.noInit}: ECP_ShortW_Prj[Fp2Type, G2]
    if loadG2(A, a_bytes) == false:
        return -1
    R.neg(A)
    saveG2(R, r_bytes)
    return 0

func cryptofuzz_constantine_bls_g2_neg(
        curve: uint8,
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g2_neg_impl[Fp2[BN254_Snarks]](a_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g2_neg_impl[Fp2[BLS12_381]](a_bytes, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_g2_iseq_impl[Fp2Type](
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8]) : cint =
    var A{.noInit.}, B{.noInit}: ECP_ShortW_Prj[Fp2Type, G2]

    if loadG2(A, a_bytes) == false:
        return -1
    if loadG2(B, b_bytes) == false:
        return -1

    if bool A == B:
        return 1
    else:
        return 0

func cryptofuzz_constantine_bls_g2_iseq(
        curve: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8]) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g2_iseq_impl[Fp2[BN254_Snarks]](a_bytes, b_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g2_iseq_impl[Fp2[BLS12_381]](a_bytes, b_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_g2_dbl_impl[Fp2Type](
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint =
    var A{.noInit.}, R{.noInit}: ECP_ShortW_Prj[Fp2Type, G2]
    if loadG2(A, a_bytes) == false:
        return -1
    R.double(A)
    saveG2(R, r_bytes)
    return 0


func cryptofuzz_constantine_bls_g2_dbl(
        curve: uint8,
        a_bytes: openarray[uint8],
        r_bytes: ptr uint8) : cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_g2_dbl_impl[Fp2[BN254_Snarks]](a_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_g2_dbl_impl[Fp2[BLS12_381]](a_bytes, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_pairing_impl[FpType, Fp2Type, Fp12Type](
        g1_bytes: openarray[uint8],
        g2_bytes: openarray[uint8],
        r_bytes: ptr uint8): cint =
    var fail = false

    var A{.noInit.}: ECP_ShortW_Aff[FpType, G1]
    if loadG1(A, g1_bytes) == false:
        return -1

    if validateAff[FpType, G1](A) == false:
        fail = true

    var B{.noInit.}: ECP_ShortW_Aff[Fp2Type, G2]
    if loadG2(B, g2_bytes) == false:
        return -1

    if validateAff[Fp2Type, G2](B) == false:
        fail = true

    var acc {.noInit.}: MillerAccumulator[FpType, Fp2Type, Fp12Type]
    acc.init()
    var regular = acc.update(A, B)
    #assert(regular == true);
    if regular == false:
        return -1
    var gt {.noinit.}: Fp12Type
    acc.finish(gt)
    gt.finalExp()

    if fail == true:
        return -1

    saveFp12(gt, r_bytes)
    return 0

func cryptofuzz_constantine_bls_pairing(
        curve: uint8,
        g1_bytes: openarray[uint8],
        g2_bytes: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_pairing_impl[Fp[BN254_Snarks], Fp2[BN254_Snarks], Fp12[BN254_Snarks]](g1_bytes, g2_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_pairing_impl[Fp[BLS12_381], Fp2[BLS12_381], Fp12[BLS12_381]](g1_bytes, g2_bytes, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_finalexp_impl[Fp12Type](
        fp12_bytes: openarray[uint8],
        r_bytes: ptr uint8): cint =
    var A{.noInit.}: Fp12Type
    if loadFp12(A, fp12_bytes) == false:
        return -1
    A.finalExp()
    saveFp12(A, r_bytes)
    return 0

func cryptofuzz_constantine_bls_finalexp(
        curve: uint8,
        fp12_bytes: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_finalexp_impl[Fp12[BN254_Snarks]](fp12_bytes, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_finalexp_impl[Fp12[BLS12_381]](fp12_bytes, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bls_hashtog1_impl[FpType](
        aug: openarray[uint8],
        msg: openarray[uint8],
        dst: openarray[uint8],
        r_bytes: ptr uint8): cint =
    var R{.noInit}: ECP_ShortW_Jac[FpType, G1]
    sha256.hashToCurve(128, R, aug, msg, dst)
    saveG1(R, r_bytes)
    return 0

func cryptofuzz_constantine_bls_hashtog1(
        curve: uint8,
        aug: openarray[uint8],
        msg: openarray[uint8],
        dst: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_hashtog1_impl[Fp[BN254_Snarks]](aug, msg, dst, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_hashtog1_impl[Fp[BLS12_381]](aug, msg, dst, r_bytes)
    assert(false)

proc cryptofuzz_constantine_bls_hashtog2_impl[Fp2Type](
        aug: openarray[uint8],
        msg: openarray[uint8],
        dst: openarray[uint8],
        r_bytes: ptr uint8): cint =
    var R{.noInit}: ECP_ShortW_Jac[Fp2Type, G2]
    sha256.hashToCurve(128, R, aug, msg, dst)
    saveG2(R, r_bytes)
    return 0

func cryptofuzz_constantine_bls_hashtog2(
        curve: uint8,
        aug: openarray[uint8],
        msg: openarray[uint8],
        dst: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bls_hashtog2_impl[Fp2[BN254_Snarks]](aug, msg, dst, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bls_hashtog2_impl[Fp2[BLS12_381]](aug, msg, dst, r_bytes)
    assert(false)

func cryptofuzz_constantine_bls_generatekeypair(
        ikm: openarray[uint8],
        r_priv_bytes: ptr uint8,
        r_pub_bytes: ptr uint8): cint {.exportc.} =
    var s {.noInit.}: SecretKey
    if bool cast[ptr BigInt[255]](s.addr)[].derive_master_secretKey(ikm) == false:
        return -1

    var r: array[32, byte]
    if serialize_seckey(r, s) != cttBLS_Success:
        return -1
    copyMem(r_priv_bytes, addr r, r.len)

    var p {.noInit.}: PublicKey
    if derive_pubkey(p, s) != cttBLS_Success:
        return -1

    saveG1(cast[ECP_ShortW_Aff[Fp[BLS12_381], G1]](p), r_pub_bytes)

    return 0

func cryptofuzz_constantine_bls_decompress_g1(
        compressed: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =
    var p {.noInit.}: PublicKey
    var c: array[48, byte]
    for i in countup(0, 47):
        c[i] = compressed[i]
    if deserialize_pubkey_compressed(p, c) != cttBLS_Success:
        return -1

    saveG1(cast[ECP_ShortW_Aff[Fp[BLS12_381], G1]](p), r_bytes)

    return 0

func cryptofuzz_constantine_bls_compress_g1(
        g1_bytes: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =
    var A{.noInit.}: ECP_ShortW_Aff[Fp[BLS12_381], G1]
    if loadG1(A, g1_bytes) == false:
        return -1

    var r: array[48, byte]
    if serialize_pubkey_compressed(r, cast[PublicKey](A)) != cttBLS_Success:
        return -1
    copyMem(r_bytes, addr r, r.len)

func cryptofuzz_constantine_bls_decompress_g2(
        compressed: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =
    var p {.noInit.}: Signature
    var c: array[96, byte]
    for i in countup(0, 95):
        c[i] = compressed[i]
    if deserialize_signature_compressed(p, c) != cttBLS_Success:
        return -1

    saveG2(cast[ECP_ShortW_Aff[Fp2[BLS12_381], G2]](p), r_bytes)

    return 0

func cryptofuzz_constantine_bls_compress_g2(
        g2_bytes: openarray[uint8],
        r_bytes: ptr uint8): cint {.exportc.} =
    var A{.noInit.}: ECP_ShortW_Aff[Fp2[BLS12_381], G2]
    if loadG2(A, g2_bytes) == false:
        return -1

    var r: array[96, byte]
    if serialize_signature_compressed(r, cast[Signature](A)) != cttBLS_Success:
        return -1
    copyMem(r_bytes, addr r, r.len)

proc cryptofuzz_constantine_bignumcalc_fr_impl[FrType](
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint =
    var A{.noInit.}: FrType
    if A.loadFr(a_bytes) == false:
        return -1

    var B{.noInit.}: FrType
    if B.loadFr(b_bytes) == false:
        return -1

    if calcop == 0:
        A += B
    elif calcop == 1:
        A -= B
    elif calcop == 2:
        A *= B
    elif calcop == 3:
        if alt == 0:
            A.inv(A)
        else:
            A.inv_vartime(A)
    elif calcop == 4:
        A.square(A)
    elif calcop == 5:
        if bool A == B:
            A.setOne()
        else:
            A.setZero()
    elif calcop == 7:
        A.neg()
    elif calcop == 8:
        if bool A.isOne():
            A.setOne()
        else:
            A.setZero()
    elif calcop == 9:
        if bool A.isZero():
            A.setOne()
        else:
            A.setZero()
    elif calcop == 10:
        if alt == 0:
            A.pow(B.toBig())
        else:
            A.pow_vartime(B.toBig())
    else:
        return -1

    saveFr(A, r_bytes)
    return 0


func cryptofuzz_constantine_bignumcalc_fr(
        curve: uint8,
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bignumcalc_fr_impl[Fr[BN254_Snarks]](calcop, a_bytes, b_bytes, alt, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bignumcalc_fr_impl[Fr[BLS12_381]](calcop, a_bytes, b_bytes, alt, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bignumcalc_fp_impl[FpType](
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint =
    var A{.noInit.}: FpType
    if A.loadFp(a_bytes) == false:
        return -1

    var B{.noInit.}: FpType
    if B.loadFp(b_bytes) == false:
        return -1

    if calcop == 0:
        A += B
    elif calcop == 1:
        A -= B
    elif calcop == 2:
        A *= B
    elif calcop == 3:
        if alt == 0:
            A.inv(A)
        else:
            A.inv_vartime(A)
    elif calcop == 4:
        A.square(A)
    elif calcop == 5:
        if bool A == B:
            A.setOne()
        else:
            A.setZero()
    elif calcop == 6:
        var s: FpType = A
        s.sqrt()
        s.square()
        if bool s == A:
            A = s
        else:
            A.setZero()
    elif calcop == 7:
        A.neg()
    elif calcop == 8:
        if bool A.isOne():
            A.setOne()
        else:
            A.setZero()
    elif calcop == 9:
        if bool A.isZero():
            A.setOne()
        else:
            A.setZero()
    elif calcop == 10:
        if alt == 0:
            A.pow(B.toBig())
        else:
            A.pow_vartime(B.toBig())
    else:
        return -1

    saveFp(A, r_bytes)
    return 0


func cryptofuzz_constantine_bignumcalc_fp(
        curve: uint8,
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bignumcalc_fp_impl[Fp[BN254_Snarks]](calcop, a_bytes, b_bytes, alt, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bignumcalc_fp_impl[Fp[BLS12_381]](calcop, a_bytes, b_bytes, alt, r_bytes)
    else:
        return -1

proc cryptofuzz_constantine_bignumcalc_fp2_impl[Fp2Type](
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint =
    var A{.noInit.}: Fp2Type
    if A.loadFp2(a_bytes) == false:
        return -1

    var B{.noInit.}: Fp2Type
    if B.loadFp2(b_bytes) == false:
        return -1

    if calcop == 0:
        A += B
    elif calcop == 1:
        A -= B
    elif calcop == 2:
        A *= B
    elif calcop == 3:
        if alt == 0:
            A.inv(A)
        else:
            A.inv_vartime(A)
    elif calcop == 4:
        A.square(A)
    elif calcop == 5:
        if bool A == B:
            A.setOne()
        else:
            A.setZero()
    elif calcop == 6:
        var s: Fp2Type = A
        s.sqrt()
        s.square()
        if bool s == A:
            A = s
        else:
            A.setZero()
    elif calcop == 7:
        A.neg()
    elif calcop == 8:
        if bool A.isOne():
            A.setOne()
        else:
            A.setZero()
    elif calcop == 9:
        if bool A.isZero():
            A.setOne()
        else:
            A.setZero()
    else:
        return -1

    saveFp2(A, r_bytes)
    return 0

func cryptofuzz_constantine_bignumcalc_fp2(
        curve: uint8,
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bignumcalc_fp2_impl[Fp2[BN254_Snarks]](calcop, a_bytes, b_bytes, alt, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bignumcalc_fp2_impl[Fp2[BLS12_381]](calcop, a_bytes, b_bytes, alt, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bignumcalc_fp12_impl[Fp12Type](
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint =
    var A{.noInit.}: Fp12Type
    if A.loadFp12(a_bytes) == false:
        return -1

    var B{.noInit.}: Fp12Type
    if B.loadFp12(b_bytes) == false:
        return -1

    if calcop == 0:
        A += B
    elif calcop == 1:
        A -= B
    elif calcop == 2:
        A *= B
    elif calcop == 3:
        if alt == 0:
            A.inv(A)
        else:
            A.inv_vartime(A)
    elif calcop == 4:
        A.square(A)
    elif calcop == 5:
        if bool A == B:
            A.setOne()
        else:
            A.setZero()
    elif calcop == 7:
        A.neg()
    elif calcop == 8:
        if bool A.isOne():
            A.setOne()
        else:
            A.setZero()
    elif calcop == 9:
        if bool A.isZero():
            A.setOne()
        else:
            A.setZero()
    else:
        return -1

    saveFp12(A, r_bytes)
    return 0

func cryptofuzz_constantine_bignumcalc_fp12(
        curve: uint8,
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        alt: uint8,
        r_bytes: ptr uint8): cint {.exportc.} =

    if curve == 0:
        return cryptofuzz_constantine_bignumcalc_fp12_impl[Fp12[BN254_Snarks]](calcop, a_bytes, b_bytes, alt, r_bytes)
    elif curve == 1:
        return cryptofuzz_constantine_bignumcalc_fp12_impl[Fp12[BLS12_381]](calcop, a_bytes, b_bytes, alt, r_bytes)
    else:
        assert(false)

proc cryptofuzz_constantine_bignumcalc(
        calcop: uint8,
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        c_bytes: openarray[uint8],
        alt: uint8,
        res: ptr uint8): cint {.exportc.} =
    var a: BigInt[32768]
    a.unmarshal(a_bytes, bigEndian)

    var b: BigInt[32768]
    b.unmarshal(b_bytes, bigEndian)

    var c: BigInt[32768]
    c.unmarshal(c_bytes, bigEndian)

    if calcop == 0:
        if alt == 0:
            discard a.add(b)
        else:
            discard a.cadd(b, SecretBool true)
    elif calcop == 1:
        if bool b >= a:
            return 0
        if alt == 0:
            discard a.sub(b)
        else:
            discard a.csub(b, SecretBool true)
    elif calcop == 2:
        # Slow compilation
        return -1
        #a.mul(b)
    elif calcop == 3:
        if bool b.isEven():
            return 0
        if bool b >= a:
            return 0
        if alt != 0:
            a.invmod_vartime(a, b)
        else:
            a.invmod(a, b)
    elif calcop == 4:
        # Slow compilation
        return -1
        # XXX if b.bits >= a.bits * 2:
        #a.square(a)
    elif calcop == 5:
        if bool a == b:
            a.setOne()
        else:
            a.setZero()
    elif calcop == 6:
        if bool a > b:
            a.setOne()
        else:
            a.setZero()
    elif calcop == 7:
        if bool a >= b:
            a.setOne()
        else:
            a.setZero()
    elif calcop == 8:
        if bool a < b:
            a.setOne()
        else:
            a.setZero()
    elif calcop == 9:
        if bool a <= b:
            a.setOne()
        else:
            a.setZero()
    elif calcop == 10:
        if bool a.isZero():
            a.setOne()
        else:
            a.setZero()
    elif calcop == 11:
        if bool a.isOne():
            a.setOne()
        else:
            a.setZero()
    elif calcop == 12:
        if bool a.isOdd():
            a.setOne()
        else:
            a.setZero()
    elif calcop == 13:
        if bool a.isEven():
            a.setOne()
        else:
            a.setZero()
    elif calcop == 14:
        a.setZero()
    elif calcop == 15:
        a.setOne()
    elif calcop == 16:
        if bool a.bit0():
            a.setOne()
        else:
            a.setZero()
    else:
        return 0

    var r: array[4096, byte]
    marshal(r, a, bigEndian)
    copyMem(res, addr r, r.len)
    return 1

proc cryptofuzz_constantine_bignumcalc_modexp(
        loops: uint64,
        input: openarray[byte],
        size: int,
        res: ptr byte): cint {.exportc.} =
    var r = newSeq[byte](size)
    for i in countup((uint64)0, loops):
        let _ = eth_evm_modexp(r, input)
    let status = eth_evm_modexp(r, input)
    if status == cttEVM_Success:
        # This doesn't work
        # copyMem(res, addr r, r.len)

        # So do this
        var rr: array[4096, byte]
        for i in countup(0, size-1):
            rr[i] = r[i]
        copyMem(res, addr rr, size)

        return 1
    else:
        return 0

