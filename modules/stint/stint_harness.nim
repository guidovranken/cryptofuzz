import stint

proc cryptofuzz_stint_add(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R = a + b
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_sub(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    if b > a:
        result = -1
    else:
        var R = a - b
        var R_bytes = toByteArrayBE(R)

        copyMem(res, addr R_bytes, R_bytes.len)

        result = 0

proc cryptofuzz_stint_mul(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R = a * b
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_expmod(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        c_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var c: StUint[32768]
    initFromBytesBE(c, c_bytes)

    if c == 0:
        result = -1
    elif b == 0:
        # XXX
        result = -1
    elif a == 0:
        # XXX
        result = -1
    elif a >= c:
        # XXX
        result = -1
    elif b >= c:
        # XXX
        result = -1
    else:
        var R = powmod(a, b, c)
        var R_bytes = toByteArrayBE(R)

        copyMem(res, addr R_bytes, R_bytes.len)

        result = 0

proc cryptofuzz_stint_addmod(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        c_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var c: StUint[32768]
    initFromBytesBE(c, c_bytes)

    if c == 0:
        result = -1
    else:
        var R = addmod(a, b, c)
        var R_bytes = toByteArrayBE(R)

        copyMem(res, addr R_bytes, R_bytes.len)

        result = 0

proc cryptofuzz_stint_mulmod(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        c_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var c: StUint[32768]
    initFromBytesBE(c, c_bytes)

    if c == 0:
        result = -1
    else:
        var R = mulmod(a, b, c)
        var R_bytes = toByteArrayBE(R)

        copyMem(res, addr R_bytes, R_bytes.len)

        result = 0

proc cryptofuzz_stint_and(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R = a and b
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_or(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R = a or b
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_xor(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R = a xor b
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_iseq(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R: StUint[32768]
    if a == b:
        R = one(StUint[32768])
    else:
        R = zero(StUint[32768])
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_exp(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R = pow(a, b)
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_lshift1(
        a_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var R = a shl 1
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_isodd(
        a_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var R: StUint[32768]
    if a.isOdd():
        R = one(StUint[32768])
    else:
        R = zero(StUint[32768])
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_iseven(
        a_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var R: StUint[32768]
    if a.isEven():
        R = one(StUint[32768])
    else:
        R = zero(StUint[32768])
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_islt(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R: StUint[32768]
    if a < b:
        R = one(StUint[32768])
    else:
        R = zero(StUint[32768])
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_islte(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R: StUint[32768]
    if a <= b:
        R = one(StUint[32768])
    else:
        R = zero(StUint[32768])
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_isgt(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R: StUint[32768]
    if a > b:
        R = one(StUint[32768])
    else:
        R = zero(StUint[32768])
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0

proc cryptofuzz_stint_isgte(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a: StUint[32768]
    initFromBytesBE(a, a_bytes)

    var b: StUint[32768]
    initFromBytesBE(b, b_bytes)

    var R: StUint[32768]
    if a >= b:
        R = one(StUint[32768])
    else:
        R = zero(StUint[32768])
    var R_bytes = toByteArrayBE(R)

    copyMem(res, addr R_bytes, R_bytes.len)

    result = 0
