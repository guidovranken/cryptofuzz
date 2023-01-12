import bigints

proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc cryptofuzz_nim_bigints_add(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var r = a + b
    var r_str = r.toString()

    copyMem(res, r_str[0].addr, r_str.len)
    result = 0

proc cryptofuzz_nim_bigints_sub(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var r = a - b
    var r_str = r.toString()

    copyMem(res, r_str[0].addr, r_str.len)
    result = 0

proc cryptofuzz_nim_bigints_mul(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var r = a * b
    var r_str = r.toString()

    copyMem(res, r_str[0].addr, r_str.len)
    result = 0

proc cryptofuzz_nim_bigints_div(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    try:
        var r = a.div(b)
        var r_str = r.toString()

        copyMem(res, r_str[0].addr, r_str.len)
        result = 0
    # Remove this except once https://github.com/nim-lang/bigints/issues/123 is fixed
    except AssertionDefect:
        result = 1

proc cryptofuzz_nim_bigints_mod(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    try:
        var r = a.mod(b)
        var r_str = r.toString()

        copyMem(res, r_str[0].addr, r_str.len)
        result = 0
    # Remove this except once https://github.com/nim-lang/bigints/issues/123 is fixed
    except AssertionDefect:
        result = 1

proc cryptofuzz_nim_bigints_gcd(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var r = gcd(a, b)
    var r_str = r.toString()

    copyMem(res, r_str[0].addr, r_str.len)
    result = 0

proc cryptofuzz_nim_bigints_invmod(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    try:
        var r = invmod(a, b)
        var r_str = r.toString()

        copyMem(res, r_str[0].addr, r_str.len)
        result = 0
    except ValueError:
        var r_str = "0"
        copyMem(res, r_str[0].addr, r_str.len)
        result = 0
    except DivByZeroDefect:
        var r_str = "0"
        copyMem(res, r_str[0].addr, r_str.len)
        result = 0
    # Remove this except once https://github.com/nim-lang/bigints/issues/123 is fixed
    except AssertionDefect:
        result = 1

proc cryptofuzz_nim_bigints_expmod(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        c_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var c = initBigint(toString(c_bytes))
    try:
        var r = powmod(a, b, c)
        var r_str = r.toString()

        copyMem(res, r_str[0].addr, r_str.len)
        result = 0
    # Remove this except once https://github.com/nim-lang/bigints/issues/123 is fixed
    except AssertionDefect:
        result = 1

proc cryptofuzz_nim_bigints_and(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var r = a.and(b)
    var r_str = r.toString()

    copyMem(res, r_str[0].addr, r_str.len)
    result = 0

proc cryptofuzz_nim_bigints_or(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var r = a.or(b)
    var r_str = r.toString()

    copyMem(res, r_str[0].addr, r_str.len)
    result = 0

proc cryptofuzz_nim_bigints_xor(
        a_bytes: openarray[uint8],
        b_bytes: openarray[uint8],
        res: ptr uint8): cint {.exportc.} =
    var a = initBigint(toString(a_bytes))
    var b = initBigint(toString(b_bytes))
    var r = a.xor(b)
    var r_str = r.toString()

    copyMem(res, r_str[0].addr, r_str.len)
    result = 0
