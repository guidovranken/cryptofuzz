%builtins range_check

from bigint import BigInt3
from ec import EcPoint
from ecdsa import verify_ecdsa

# Verify a ECDSA signature.
func main{range_check_ptr}():
    # NIST P-256
    # let public_key_pt = EcPoint(
    #     BigInt3(0x3fb12f3c59ff46c271bf83,0x3e89236e3f334d5977a52e,0x1ccbe91c075fc7f4f033b),
    #     BigInt3(0x4e78dc7ccd5ca89a4ca9,0x2cb039844f81b6df2a4edd,0xce4014c68811f9a21a1fd))
    # let r = BigInt3(0x155a7acabb5e6f79c8c2ac,0xf598a549fb4abf5ac7da9,0xf3ac8061b514795b8843e)
    # let s = BigInt3(0x2f175a3ccdda2acc058903,0x1898afdcdc73be5ec863a5,0x8bf77819ca05a6b2786c7)
    # let msg_hash = BigInt3(0x100377dbc4e7a6a133ec56,0x25c813f825413878bbec6a,0x44acf6b7e36c1342c2c58)

    #Secp256 K1
    let public_key_pt = EcPoint(
        BigInt3(0x35dec240d9f76e20b48b41, 0x27fcb378b533f57a6b585, 0xbff381888b165f92dd33d),
        BigInt3(0x1711d8fb6fbbf53986b57f, 0x2e56f964d38cb8dbdeb30b, 0xe4be2a8547d802dc42041))
    let r = BigInt3(0x2e6c77fee73f3ac9be1217, 0x3f0c0b121ac1dc3e5c03c6, 0xeee3e6f50c576c07d7e4a)
    let s = BigInt3(0x20a4b46d3c5e24cda81f22, 0x967bf895824330d4273d0, 0x541e10c21560da25ada4c)
    let msg_hash = BigInt3(
        0x38a23ca66202c8c2a72277, 0x6730e765376ff17ea8385, 0xca1ad489ab60ea581e6c1)
    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s)
    return ()
end
