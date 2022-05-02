# The domain paramters of elliptic curve.

# The base of the representation.
const BASE = 2 ** 86

# P = sum(P_i * BASE^i)
    # Secp256 K1
    const P0 = 0x3ffffffffffffefffffc2f
    const P1 = 0x3fffffffffffffffffffff
    const P2 = 0xfffffffffffffffffffff

# N = sum(N_i * BASE^i)
    # Secp256 K1
    const N0 = 0x8a03bbfd25e8cd0364141
    const N1 = 0x3ffffffffffaeabb739abd
    const N2 = 0xfffffffffffffffffffff

# A = sum(A_i * BASE^i)
    # Secp256 K1
    const A0 = 0
    const A1 = 0
    const A2 = 0

# Gx = sum(Gx_i * BASE^i)
    # Secp256 K1
    const GX0 = 0xe28d959f2815b16f81798
    const GX1 = 0xa573a1c2c1c0a6ff36cb7
    const GX2 = 0x79be667ef9dcbbac55a06

# Gy = sum(Gy_i * BASE^i)
    # Secp256 K1
    const GY0 = 0x554199c47d08ffb10d4b8
    const GY1 = 0x2ff0384422a3f45ed1229a
    const GY2 = 0x483ada7726a3c4655da4f

# Some popular elliptic curve's domain parameters.
# |--------------------------------------------------------------|
# | curves | Secp256k1                | NIST P-256               |
# | ------ | ------------------------ | ------------------------ |
# | P0     | 0x3ffffffffffffefffffc2f | 0x3fffffffffffffffffffff |
# | P1     | 0x3fffffffffffffffffffff | 0x3ff                    |
# | p2     | 0xfffffffffffffffffffff  | 0xffffffff0000000100000  |
# | N0     | 0x8a03bbfd25e8cd0364141  | 0x179e84f3b9cac2fc632551 |
# | N1     | 0x3ffffffffffaeabb739abd | 0x3ffffffffffef39beab69c |
# | N2     | 0xfffffffffffffffffffff  | 0xffffffff00000000fffff  |
# | A0     | 0                        | -3                       |
# | A1     | 0                        | 0                        |
# | A2     | 0                        | 0                        |
# | GX0    | 0xe28d959f2815b16f81798  | 0x2b33a0f4a13945d898c296 |
# | GX1    | 0xa573a1c2c1c0a6ff36cb7  | 0x1b958e9103c9dc0df604b7 |
# | GX2    | 0x79be667ef9dcbbac55a06  | 0x6b17d1f2e12c4247f8bce  |
# | GY0    | 0x554199c47d08ffb10d4b8  | 0x315ececbb6406837bf51f5 |
# | GY1    | 0x2ff0384422a3f45ed1229a | 0x2d29f03e7858af38cd5dac |
# | GY2    | 0x483ada7726a3c4655da4f  | 0x4fe342e2fe1a7f9b8ee7e  |
# |--------------------------------------------------------------|