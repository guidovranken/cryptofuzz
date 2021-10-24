import nimcrypto

proc cryptofuzz_nimcrypto_keccak_224(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = keccak_224.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_keccak_256(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = keccak_256.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_keccak_384(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = keccak_384.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_keccak_512(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = keccak_512.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_blake2s_224(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = blake2_224.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_blake2s_256(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = blake2_256.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_blake2b_384(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = blake2_384.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_blake2b_512(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = blake2_512.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_ripemd_128(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = ripemd128.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_ripemd_160(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = ripemd160.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_ripemd_256(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = ripemd256.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
proc cryptofuzz_nimcrypto_ripemd_320(data: openarray[uint8], res: ptr uint8): cint {.exportc.} =
    var hash = ripemd320.digest(data).data
    copyMem(res, addr hash, hash.len)
    result = cast[cint](hash.len)
