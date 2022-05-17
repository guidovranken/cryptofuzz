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
