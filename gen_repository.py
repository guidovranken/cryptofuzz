#!/usr/bin/python3

from __future__ import print_function

import re

# Python2 <-> Python3 shim to make range behave like range on Python3
try:
    range = xrange
except NameError:
    pass

def ToCryptofuzzID(prefix, item):
    return 'fuzzing::datasource::ID("Cryptofuzz/{}/{}")'.format(prefix, item)

class ModeOfOperation(object):
    def __init__(self, cipher):
        self.modeDict = {}
        regexDict = {
                'CBC' : r'_?CBC',
                'CCM' : r'_?CCM',
                'CFB' : r'_?CFB[18]?',
                'CTR' : r'_?CTR',
                'ECB' : r'_?ECB',
                'GCM' : r'_?GCM',
                'OCB' : r'_?OCB',
                'OFB' : r'_?OFB',
                'XTS' : r'_?XTS',
        }

        for name, regex in regexDict.items():
            if bool(re.search(regex, cipher)):
                self.modeDict[name] = True

        if len(self.modeDict.keys()) > 1:
            print("Tried setting more than 1 mode, exiting")
            exit(1)

# Components
class Component(object):
    def __init__(self, name):
        self.name = name

class Module(Component):
    def __init__(self, module):
        super(Module, self).__init__(module)

class Operation(Component):
    def __init__(self, operation):
        super(Operation, self).__init__(operation)

class Cipher(Component):
    def __init__(self, cipher, isAEAD = False):
        super(Cipher, self).__init__(cipher)

        self.operation = ModeOfOperation(cipher)
        self.isAEAD = isAEAD
        self.isWRAP = bool(re.search(r'_WRAP', cipher))
        self.isAES = bool(re.search(r'^AES_', cipher))

class Digest(Component):
    def __init__(self, digest, size = None):
        super(Digest, self).__init__( digest)

        if size == None:
            self.size = "std::nullopt"
        else:
            self.size = str(size)

class ECC_Curve(Component):
    def __init__(self,
            name,
            bits = None,
            prime = None,
            a = None,
            b = None,
            x = None,
            y = None,
            order_min_1 = None,
            order = None):
        super(ECC_Curve, self).__init__(name)

        self.bits = str(bits) if bits else 'std::nullopt'
        self.prime = '"' + prime + '"' if prime else 'std::nullopt'
        self.a = '"' + a + '"' if a else 'std::nullopt'
        self.b = '"' + b + '"' if b else 'std::nullopt'
        self.x = '"' + x + '"' if x else 'std::nullopt'
        self.y = '"' + y + '"' if y else 'std::nullopt'
        self.order_min_1 = '"' + order_min_1 + '"' if order_min_1 else 'std::nullopt'
        self.order = '"' + order + '"' if order else 'std::nullopt'

class CalcOp(Component):
    def __init__(self, operation):
        super(CalcOp, self).__init__(operation)

# Tables
class Table(object):
    def __init__(self, prefix, tableDecl):
        self.table = []
        self.prefix = prefix
        self.tableDecl = ['uint64_t id', 'const char* name']
        self.tableDecl.extend(tableDecl)
    def checkDuplicates(self):
        # Sanity check to assert that no duplicate items are added
        nameList = [obj.name for obj in self.table]
        if len(set(nameList)) != len(nameList):
            print("Duplicate entry: {}, exiting".format(self.table[-1].name))
            exit(1)
    def Add(self, obj):
        self.table += [ obj ]
        self.checkDuplicates()
    def getStructName(self, asType):
        return "{}LUT{}".format(self.prefix, "_t" if asType else "")
    def GetTableDecl(self):
        outStr = ""
        outStr += "struct " + self.getStructName(True) + "{\n"
        for part in self.tableDecl:
            outStr += '    ' + part + ';\n'
        outStr += "};\n"
        return outStr
    def getTableEntryList(self):
        raise NotImplementedError()
    def ToCPPTable(self):
        outStr = ""
        outStr += "constexpr " + self.getStructName(True) + " " + self.getStructName(False) + "[] = {\n"
        for index in range(len(self.table)):
            outTableEntry = [ ToCryptofuzzID(self.prefix, self.table[index].name), "\"" + self.table[index].name + "\"" ]
            outTableEntry.extend( self.getTableEntryList(index) )

            if len(outTableEntry) != len(self.tableDecl):
                print("Size of table declaration and size of table entry doesn't match, exiting")
                exit(1)

            outStr += '    {' + ", ".join( outTableEntry ) + '},\n'

        outStr += '};\n\n'

        return outStr
    def ToCPPMap(self):
        outStr = ""
        outStr += "std::map<uint64_t, " + self.getStructName(True) + ">" + " " + self.getStructName(False) + "Map = {\n";
        for index in range(len(self.table)):
            outTableEntry = [ ToCryptofuzzID(self.prefix, self.table[index].name), "\"" + self.table[index].name + "\""]
            outTableEntry.extend( self.getTableEntryList(index) )

            if len(outTableEntry) != len(self.tableDecl):
                print("Size of table declaration and size of table entry doesn't match, exiting")
                exit(1)

            outStr += '    {' + outTableEntry[0] + ", {" + ", ".join( outTableEntry ) + '} },\n'

        outStr += '};\n\n'

        return outStr

class CipherTable(Table):
    def __init__(self):
        tableDecl = [
                "bool CBC",
                "bool CCM",
                "bool CFB",
                "bool CTR",
                "bool ECB",
                "bool GCM",
                "bool OCB",
                "bool OFB",
                "bool XTS",
                "bool AEAD",
                "bool WRAP",
                "bool AES",
        ]

        super(CipherTable, self).__init__('Cipher', tableDecl)
    def getTableEntryList(self, index):
        tableEntry = []

        tableEntry += [ 'true' if 'CBC' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'CCM' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'CFB' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'CTR' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'ECB' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'GCM' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'OCB' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'OFB' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if 'XTS' in self.table[index].operation.modeDict else 'false' ]
        tableEntry += [ 'true' if self.table[index].isAEAD else 'false' ]
        tableEntry += [ 'true' if self.table[index].isWRAP else 'false' ]
        tableEntry += [ 'true' if self.table[index].isAES else 'false' ]

        return tableEntry

class DigestTable(Table):
    def __init__(self):
        tableDecl = [
                "std::optional<size_t> size",
        ]

        super(DigestTable, self).__init__('Digest', tableDecl)
    def getTableEntryList(self, index):
        tableEntry = []

        tableEntry += [ self.table[index].size ]
        
        return tableEntry

class ModuleTable(Table):
    def __init__(self):
        tableDecl = [
        ]

        super(ModuleTable, self).__init__('Module', tableDecl)
    def getTableEntryList(self, index):
        tableEntry = []

        return tableEntry

class OperationTable(Table):
    def __init__(self):
        tableDecl = [
        ]

        super(OperationTable, self).__init__('Operation', tableDecl)
    def getTableEntryList(self, index):
        tableEntry = []

        return tableEntry

class ECC_CurveTable(Table):
    def __init__(self):
        tableDecl = [
                "std::optional<size_t> bits",
                "std::optional<const char*> prime",
                "std::optional<const char*> a",
                "std::optional<const char*> b",
                "std::optional<const char*> x",
                "std::optional<const char*> y",
                "std::optional<const char*> order_min_1",
                "std::optional<const char*> order",
        ]

        super(ECC_CurveTable, self).__init__('ECC_Curve', tableDecl)
    def getTableEntryList(self, index):
        tableEntry = []

        tableEntry += [ self.table[index].bits ]
        tableEntry += [ self.table[index].prime ]
        tableEntry += [ self.table[index].a ]
        tableEntry += [ self.table[index].b ]
        tableEntry += [ self.table[index].x ]
        tableEntry += [ self.table[index].y ]
        tableEntry += [ self.table[index].order_min_1 ]
        tableEntry += [ self.table[index].order ]

        return tableEntry

class CalcOpTable(Table):
    def __init__(self):
        tableDecl = [
        ]

        super(CalcOpTable, self).__init__('CalcOp', tableDecl)
    def getTableEntryList(self, index):
        tableEntry = []

        return tableEntry

modules = ModuleTable()
modules.Add( Module("BearSSL") )
modules.Add( Module("Beast") )
modules.Add( Module("Bitcoin") )
modules.Add( Module("Boost") )
modules.Add( Module("Botan") )
modules.Add( Module("CPPCrypto") )
modules.Add( Module("Crypto++") )
modules.Add( Module("EverCrypt") )
modules.Add( Module("Golang") )
modules.Add( Module("Linux") )
modules.Add( Module("Monero") )
modules.Add( Module("Monocypher") )
modules.Add( Module("NSS") )
modules.Add( Module("Nettle") )
modules.Add( Module("OpenSSL") )
modules.Add( Module("QuickJS") )
modules.Add( Module("Reference implementations") )
modules.Add( Module("Ring") )
modules.Add( Module("SymCrypt") )
modules.Add( Module("Veracrypt") )
modules.Add( Module("bignumber.js") )
modules.Add( Module("blst") )
modules.Add( Module("bn.js") )
modules.Add( Module("chia_bls") )
modules.Add( Module("cifra") )
modules.Add( Module("crypto-js") )
modules.Add( Module("elliptic") )
modules.Add( Module("k256") )
modules.Add( Module("kilic-bls12-381") )
modules.Add( Module("libecc") )
modules.Add( Module("libgcrypt") )
modules.Add( Module("libgmp") )
modules.Add( Module("libsodium") )
modules.Add( Module("libtomcrypt") )
modules.Add( Module("libtommath") )
modules.Add( Module("mbed TLS") )
modules.Add( Module("mcl") )
modules.Add( Module("micro-ecc") )
modules.Add( Module("mpdecimal") )
modules.Add( Module("noble-bls12-381") )
modules.Add( Module("noble-ed25519") )
modules.Add( Module("noble-secp256k1") )
modules.Add( Module("py_ecc") )
modules.Add( Module("relic") )
modules.Add( Module("rust_libsecp256k1") )
modules.Add( Module("schnorr_fun") )
modules.Add( Module("schnorrkel") )
modules.Add( Module("secp256k1") )
modules.Add( Module("sjcl") )
modules.Add( Module("trezor-firmware") )
modules.Add( Module("wolfCrypt") )
modules.Add( Module("wolfCrypt-OpenSSL") )

operations = OperationTable()
operations.Add( Operation("BLS_Aggregate_G1") )
operations.Add( Operation("BLS_Aggregate_G2") )
operations.Add( Operation("BLS_Compress_G1") )
operations.Add( Operation("BLS_Compress_G2") )
operations.Add( Operation("BLS_Decompress_G1") )
operations.Add( Operation("BLS_Decompress_G2") )
operations.Add( Operation("BLS_G1_Add") )
operations.Add( Operation("BLS_G1_IsEq") )
operations.Add( Operation("BLS_G1_Mul") )
operations.Add( Operation("BLS_G1_Neg") )
operations.Add( Operation("BLS_G2_Add") )
operations.Add( Operation("BLS_G2_IsEq") )
operations.Add( Operation("BLS_G2_Mul") )
operations.Add( Operation("BLS_G2_Neg") )
operations.Add( Operation("BLS_GenerateKeyPair") )
operations.Add( Operation("BLS_HashToG1") )
operations.Add( Operation("BLS_HashToG2") )
operations.Add( Operation("BLS_IsG1OnCurve") )
operations.Add( Operation("BLS_IsG2OnCurve") )
operations.Add( Operation("BLS_Pairing") )
operations.Add( Operation("BLS_PrivateToPublic") )
operations.Add( Operation("BLS_PrivateToPublic_G2") )
operations.Add( Operation("BLS_Sign") )
operations.Add( Operation("BLS_Verify") )
operations.Add( Operation("BignumCalc") )
operations.Add( Operation("BignumCalc_Mod_2Exp256") )
operations.Add( Operation("BignumCalc_Mod_BLS12_381_P") )
operations.Add( Operation("BignumCalc_Mod_BLS12_381_R") )
operations.Add( Operation("BignumCalc_Mod_SECP256K1") )
operations.Add( Operation("CMAC") )
operations.Add( Operation("DH_Derive") )
operations.Add( Operation("DH_GenerateKeyPair") )
operations.Add( Operation("Digest") )
operations.Add( Operation("ECC_GenerateKeyPair") )
operations.Add( Operation("ECC_Point_Add") )
operations.Add( Operation("ECC_Point_Mul") )
operations.Add( Operation("ECC_PrivateToPublic") )
operations.Add( Operation("ECC_ValidatePubkey") )
operations.Add( Operation("ECDH_Derive") )
operations.Add( Operation("ECDSA_Recover") )
operations.Add( Operation("ECDSA_Sign") )
operations.Add( Operation("ECDSA_Verify") )
operations.Add( Operation("ECGDSA_Sign") )
operations.Add( Operation("ECGDSA_Verify") )
operations.Add( Operation("ECIES_Decrypt") )
operations.Add( Operation("ECIES_Encrypt") )
operations.Add( Operation("ECRDSA_Sign") )
operations.Add( Operation("ECRDSA_Verify") )
operations.Add( Operation("HMAC") )
operations.Add( Operation("KDF_ARGON2") )
operations.Add( Operation("KDF_BCRYPT") )
operations.Add( Operation("KDF_HKDF") )
operations.Add( Operation("KDF_PBKDF") )
operations.Add( Operation("KDF_PBKDF1") )
operations.Add( Operation("KDF_PBKDF2") )
operations.Add( Operation("KDF_SCRYPT") )
operations.Add( Operation("KDF_SP_800_108") )
operations.Add( Operation("KDF_SSH") )
operations.Add( Operation("KDF_TLS1_PRF") )
operations.Add( Operation("KDF_X963") )
operations.Add( Operation("Misc") )
operations.Add( Operation("SR25519_Verify") )
operations.Add( Operation("Schnorr_Sign") )
operations.Add( Operation("Schnorr_Verify") )
operations.Add( Operation("SymmetricDecrypt") )
operations.Add( Operation("SymmetricEncrypt") )

ciphers = CipherTable()

ciphers.Add( Cipher("AES") )
ciphers.Add( Cipher("AES_128_CBC") )
ciphers.Add( Cipher("AES_128_CBC_HMAC_SHA1") )
ciphers.Add( Cipher("AES_128_CBC_HMAC_SHA256") )
ciphers.Add( Cipher("AES_128_CCM") )
ciphers.Add( Cipher("AES_128_CFB") )
ciphers.Add( Cipher("AES_128_CFB1") )
ciphers.Add( Cipher("AES_128_CFB128") )
ciphers.Add( Cipher("AES_128_CFB8") )
ciphers.Add( Cipher("AES_128_CTR") )
ciphers.Add( Cipher("AES_128_ECB") )
ciphers.Add( Cipher("AES_128_OCB") )
ciphers.Add( Cipher("AES_128_OFB") )
ciphers.Add( Cipher("AES_128_WRAP") )
ciphers.Add( Cipher("AES_128_WRAP_PAD") )
ciphers.Add( Cipher("AES_128_XTS") )
ciphers.Add( Cipher("AES_192_CBC") )
ciphers.Add( Cipher("AES_192_CCM") )
ciphers.Add( Cipher("AES_192_CFB") )
ciphers.Add( Cipher("AES_192_CFB1") )
ciphers.Add( Cipher("AES_192_CFB128") )
ciphers.Add( Cipher("AES_192_CFB8") )
ciphers.Add( Cipher("AES_192_CTR") )
ciphers.Add( Cipher("AES_192_ECB") )
ciphers.Add( Cipher("AES_192_OFB") )
ciphers.Add( Cipher("AES_192_WRAP") )
ciphers.Add( Cipher("AES_192_WRAP_PAD") )
ciphers.Add( Cipher("AES_192_XTS") )
ciphers.Add( Cipher("AES_256_CBC") )
ciphers.Add( Cipher("AES_256_CBC_HMAC_SHA1") )
ciphers.Add( Cipher("AES_256_CCM") )
ciphers.Add( Cipher("AES_256_CFB") )
ciphers.Add( Cipher("AES_256_CFB1") )
ciphers.Add( Cipher("AES_256_CFB128") )
ciphers.Add( Cipher("AES_256_CFB8") )
ciphers.Add( Cipher("AES_256_CTR") )
ciphers.Add( Cipher("AES_256_ECB") )
ciphers.Add( Cipher("AES_256_OCB") )
ciphers.Add( Cipher("AES_256_OFB") )
ciphers.Add( Cipher("AES_256_WRAP") )
ciphers.Add( Cipher("AES_256_WRAP_PAD") )
ciphers.Add( Cipher("AES_256_XTS") )
ciphers.Add( Cipher("AES_512_XTS") )
ciphers.Add( Cipher("ANUBIS_CBC") )
ciphers.Add( Cipher("ANUBIS_CFB") )
ciphers.Add( Cipher("ANUBIS_CTR") )
ciphers.Add( Cipher("ANUBIS_ECB") )
ciphers.Add( Cipher("ANUBIS_OFB") )
ciphers.Add( Cipher("ARIA_128_CBC") )
ciphers.Add( Cipher("ARIA_128_CCM") )
ciphers.Add( Cipher("ARIA_128_CFB") )
ciphers.Add( Cipher("ARIA_128_CFB1") )
ciphers.Add( Cipher("ARIA_128_CFB128") )
ciphers.Add( Cipher("ARIA_128_CFB8") )
ciphers.Add( Cipher("ARIA_128_CTR") )
ciphers.Add( Cipher("ARIA_128_ECB") )
ciphers.Add( Cipher("ARIA_128_OFB") )
ciphers.Add( Cipher("ARIA_192_CBC") )
ciphers.Add( Cipher("ARIA_192_CCM") )
ciphers.Add( Cipher("ARIA_192_CFB") )
ciphers.Add( Cipher("ARIA_192_CFB1") )
ciphers.Add( Cipher("ARIA_192_CFB128") )
ciphers.Add( Cipher("ARIA_192_CFB8") )
ciphers.Add( Cipher("ARIA_192_CTR") )
ciphers.Add( Cipher("ARIA_192_ECB") )
ciphers.Add( Cipher("ARIA_192_OFB") )
ciphers.Add( Cipher("ARIA_256_CBC") )
ciphers.Add( Cipher("ARIA_256_CCM") )
ciphers.Add( Cipher("ARIA_256_CFB") )
ciphers.Add( Cipher("ARIA_256_CFB1") )
ciphers.Add( Cipher("ARIA_256_CFB128") )
ciphers.Add( Cipher("ARIA_256_CFB8") )
ciphers.Add( Cipher("ARIA_256_CTR") )
ciphers.Add( Cipher("ARIA_256_ECB") )
ciphers.Add( Cipher("ARIA_256_OFB") )
ciphers.Add( Cipher("BF_CBC") )
ciphers.Add( Cipher("BF_CFB") )
ciphers.Add( Cipher("BF_ECB") )
ciphers.Add( Cipher("BF_OFB") )
ciphers.Add( Cipher("BLOWFISH_CBC") )
ciphers.Add( Cipher("BLOWFISH_CFB") )
ciphers.Add( Cipher("BLOWFISH_CFB64") )
ciphers.Add( Cipher("BLOWFISH_CTR") )
ciphers.Add( Cipher("BLOWFISH_ECB") )
ciphers.Add( Cipher("BLOWFISH_OFB") )
ciphers.Add( Cipher("CAMELLIA_128_CBC") )
ciphers.Add( Cipher("CAMELLIA_128_CFB") )
ciphers.Add( Cipher("CAMELLIA_128_CFB1") )
ciphers.Add( Cipher("CAMELLIA_128_CFB128") )
ciphers.Add( Cipher("CAMELLIA_128_CFB8") )
ciphers.Add( Cipher("CAMELLIA_128_CTR") )
ciphers.Add( Cipher("CAMELLIA_128_ECB") )
ciphers.Add( Cipher("CAMELLIA_128_OFB") )
ciphers.Add( Cipher("CAMELLIA_192_CBC") )
ciphers.Add( Cipher("CAMELLIA_192_CFB") )
ciphers.Add( Cipher("CAMELLIA_192_CFB1") )
ciphers.Add( Cipher("CAMELLIA_192_CFB128") )
ciphers.Add( Cipher("CAMELLIA_192_CFB8") )
ciphers.Add( Cipher("CAMELLIA_192_CTR") )
ciphers.Add( Cipher("CAMELLIA_192_ECB") )
ciphers.Add( Cipher("CAMELLIA_192_OFB") )
ciphers.Add( Cipher("CAMELLIA_256_CBC") )
ciphers.Add( Cipher("CAMELLIA_256_CFB") )
ciphers.Add( Cipher("CAMELLIA_256_CFB1") )
ciphers.Add( Cipher("CAMELLIA_256_CFB128") )
ciphers.Add( Cipher("CAMELLIA_256_CFB8") )
ciphers.Add( Cipher("CAMELLIA_256_CTR") )
ciphers.Add( Cipher("CAMELLIA_256_ECB") )
ciphers.Add( Cipher("CAMELLIA_256_OFB") )
ciphers.Add( Cipher("CAST5_CBC") )
ciphers.Add( Cipher("CAST5_CFB") )
ciphers.Add( Cipher("CAST5_CTR") )
ciphers.Add( Cipher("CAST5_ECB") )
ciphers.Add( Cipher("CAST5_OFB") )
ciphers.Add( Cipher("CHACHA20") )
ciphers.Add( Cipher("CHAM128_CBC") )
ciphers.Add( Cipher("CHAM128_CFB") )
ciphers.Add( Cipher("CHAM128_CTR") )
ciphers.Add( Cipher("CHAM128_ECB") )
ciphers.Add( Cipher("CHAM128_OFB") )
ciphers.Add( Cipher("CHAM64_CBC") )
ciphers.Add( Cipher("CHAM64_CFB") )
ciphers.Add( Cipher("CHAM64_CTR") )
ciphers.Add( Cipher("CHAM64_ECB") )
ciphers.Add( Cipher("CHAM64_OFB") )
# DESX_A/DESX_B: See https://github.com/openssl/openssl/issues/9703#issuecomment-526197301
ciphers.Add( Cipher("DES3_CBC") )
ciphers.Add( Cipher("DESX_A_CBC") )
ciphers.Add( Cipher("DESX_B_CBC") )
ciphers.Add( Cipher("DES_CBC") )
ciphers.Add( Cipher("DES_CFB") )
ciphers.Add( Cipher("DES_CFB1") )
ciphers.Add( Cipher("DES_CFB8") )
ciphers.Add( Cipher("DES_CTR") )
ciphers.Add( Cipher("DES_ECB") )
ciphers.Add( Cipher("DES_EDE") )
ciphers.Add( Cipher("DES_EDE3") )
ciphers.Add( Cipher("DES_EDE3_CBC") )
ciphers.Add( Cipher("DES_EDE3_CFB") )
ciphers.Add( Cipher("DES_EDE3_CFB1") )
ciphers.Add( Cipher("DES_EDE3_CFB8") )
ciphers.Add( Cipher("DES_EDE3_ECB") )
ciphers.Add( Cipher("DES_EDE3_OFB") )
ciphers.Add( Cipher("DES_EDE3_WRAP") )
ciphers.Add( Cipher("DES_EDE_CBC") )
ciphers.Add( Cipher("DES_EDE_CFB") )
ciphers.Add( Cipher("DES_EDE_ECB") )
ciphers.Add( Cipher("DES_EDE_OFB") )
ciphers.Add( Cipher("DES_OFB") )
ciphers.Add( Cipher("GMAC_128") )
ciphers.Add( Cipher("GMAC_192") )
ciphers.Add( Cipher("GMAC_256") )
ciphers.Add( Cipher("GOST-28147-89") )
ciphers.Add( Cipher("GOST-28147-89_CBC") )
ciphers.Add( Cipher("HC128") )
ciphers.Add( Cipher("HIGHT_CBC") )
ciphers.Add( Cipher("HIGHT_CFB") )
ciphers.Add( Cipher("HIGHT_CTR") )
ciphers.Add( Cipher("HIGHT_ECB") )
ciphers.Add( Cipher("HIGHT_OFB") )
ciphers.Add( Cipher("IDEA_CBC") )
ciphers.Add( Cipher("IDEA_CFB") )
ciphers.Add( Cipher("IDEA_CTR") )
ciphers.Add( Cipher("IDEA_ECB") )
ciphers.Add( Cipher("IDEA_OFB") )
ciphers.Add( Cipher("KALYNA128_CBC") )
ciphers.Add( Cipher("KALYNA128_CFB") )
ciphers.Add( Cipher("KALYNA128_CFB8") )
ciphers.Add( Cipher("KALYNA128_CTR") )
ciphers.Add( Cipher("KALYNA128_ECB") )
ciphers.Add( Cipher("KALYNA128_OFB") )
ciphers.Add( Cipher("KALYNA256_CBC") )
ciphers.Add( Cipher("KALYNA256_CFB") )
ciphers.Add( Cipher("KALYNA256_CFB8") )
ciphers.Add( Cipher("KALYNA256_CTR") )
ciphers.Add( Cipher("KALYNA256_ECB") )
ciphers.Add( Cipher("KALYNA256_OFB") )
ciphers.Add( Cipher("KALYNA512_CBC") )
ciphers.Add( Cipher("KALYNA512_CFB") )
ciphers.Add( Cipher("KALYNA512_CFB8") )
ciphers.Add( Cipher("KALYNA512_CTR") )
ciphers.Add( Cipher("KALYNA512_ECB") )
ciphers.Add( Cipher("KALYNA512_OFB") )
ciphers.Add( Cipher("KASUMI_CBC") )
ciphers.Add( Cipher("KASUMI_CFB") )
ciphers.Add( Cipher("KASUMI_CTR") )
ciphers.Add( Cipher("KASUMI_ECB") )
ciphers.Add( Cipher("KASUMI_OFB") )
ciphers.Add( Cipher("KASUMI_XTS") )
ciphers.Add( Cipher("KHAZAD_CBC") )
ciphers.Add( Cipher("KHAZAD_CFB") )
ciphers.Add( Cipher("KHAZAD_CTR") )
ciphers.Add( Cipher("KHAZAD_ECB") )
ciphers.Add( Cipher("KHAZAD_OFB") )
ciphers.Add( Cipher("KUZNYECHIK") )
ciphers.Add( Cipher("LEA_CBC") )
ciphers.Add( Cipher("LEA_CFB") )
ciphers.Add( Cipher("LEA_CTR") )
ciphers.Add( Cipher("LEA_ECB") )
ciphers.Add( Cipher("LEA_OFB") )
ciphers.Add( Cipher("MISTY1_CBC") )
ciphers.Add( Cipher("MISTY1_CTR") )
ciphers.Add( Cipher("MISTY1_OFB") )
ciphers.Add( Cipher("MISTY1_XTS") )
ciphers.Add( Cipher("NOEKEON_CBC") )
ciphers.Add( Cipher("NOEKEON_CFB") )
ciphers.Add( Cipher("NOEKEON_CTR") )
ciphers.Add( Cipher("NOEKEON_DIRECT_CBC") )
ciphers.Add( Cipher("NOEKEON_DIRECT_CFB") )
ciphers.Add( Cipher("NOEKEON_DIRECT_CTR") )
ciphers.Add( Cipher("NOEKEON_DIRECT_ECB") )
ciphers.Add( Cipher("NOEKEON_DIRECT_OFB") )
ciphers.Add( Cipher("NOEKEON_DIRECT_XTS") )
ciphers.Add( Cipher("NOEKEON_ECB") )
ciphers.Add( Cipher("NOEKEON_OFB") )
ciphers.Add( Cipher("NOEKEON_XTS") )
ciphers.Add( Cipher("RABBIT") )
ciphers.Add( Cipher("RC2_40_CBC") )
ciphers.Add( Cipher("RC2_64_CBC") )
ciphers.Add( Cipher("RC2_CBC") )
ciphers.Add( Cipher("RC2_CFB") )
ciphers.Add( Cipher("RC2_CTR") )
ciphers.Add( Cipher("RC2_ECB") )
ciphers.Add( Cipher("RC2_OFB") )
ciphers.Add( Cipher("RC4") )
ciphers.Add( Cipher("RC4_40") )
ciphers.Add( Cipher("RC4_HMAC_MD5") )
ciphers.Add( Cipher("RC5_32_12_16_CBC") )
ciphers.Add( Cipher("RC5_32_12_16_CFB") )
ciphers.Add( Cipher("RC5_32_12_16_ECB") )
ciphers.Add( Cipher("RC5_32_12_16_OFB") )
ciphers.Add( Cipher("RC5_CBC") )
ciphers.Add( Cipher("RC5_CFB") )
ciphers.Add( Cipher("RC5_CTR") )
ciphers.Add( Cipher("RC5_ECB") )
ciphers.Add( Cipher("RC5_OFB") )
ciphers.Add( Cipher("RC6_CBC") )
ciphers.Add( Cipher("RC6_CFB") )
ciphers.Add( Cipher("RC6_CTR") )
ciphers.Add( Cipher("RC6_ECB") )
ciphers.Add( Cipher("RC6_OFB") )
ciphers.Add( Cipher("SAFER_K_CBC") )
ciphers.Add( Cipher("SAFER_K_CFB") )
ciphers.Add( Cipher("SAFER_K_CTR") )
ciphers.Add( Cipher("SAFER_K_ECB") )
ciphers.Add( Cipher("SAFER_K_OFB") )
ciphers.Add( Cipher("SAFER_SK_CBC") )
ciphers.Add( Cipher("SAFER_SK_CFB") )
ciphers.Add( Cipher("SAFER_SK_CTR") )
ciphers.Add( Cipher("SAFER_SK_ECB") )
ciphers.Add( Cipher("SAFER_SK_OFB") )
ciphers.Add( Cipher("SALSA20_128") )
ciphers.Add( Cipher("SALSA20_12_128") )
ciphers.Add( Cipher("SALSA20_12_256") )
ciphers.Add( Cipher("SALSA20_256") )
ciphers.Add( Cipher("SEED_CBC") )
ciphers.Add( Cipher("SEED_CFB") )
ciphers.Add( Cipher("SEED_CTR") )
ciphers.Add( Cipher("SEED_ECB") )
ciphers.Add( Cipher("SEED_OFB") )
ciphers.Add( Cipher("SERPENT") )
ciphers.Add( Cipher("SERPENT_CBC") )
ciphers.Add( Cipher("SERPENT_CFB") )
ciphers.Add( Cipher("SERPENT_CTR") )
ciphers.Add( Cipher("SERPENT_ECB") )
ciphers.Add( Cipher("SERPENT_OFB") )
ciphers.Add( Cipher("SERPENT_XTS") )
ciphers.Add( Cipher("SHACAL2_CBC") )
ciphers.Add( Cipher("SHACAL2_CFB") )
ciphers.Add( Cipher("SHACAL2_CTR") )
ciphers.Add( Cipher("SHACAL2_OFB") )
ciphers.Add( Cipher("SHACAL2_XTS") )
ciphers.Add( Cipher("SHARK_CBC") )
ciphers.Add( Cipher("SHARK_CFB") )
ciphers.Add( Cipher("SHARK_CTR") )
ciphers.Add( Cipher("SHARK_ECB") )
ciphers.Add( Cipher("SHARK_OFB") )
ciphers.Add( Cipher("SIMECK32_CBC") )
ciphers.Add( Cipher("SIMECK32_CFB") )
ciphers.Add( Cipher("SIMECK32_CTR") )
ciphers.Add( Cipher("SIMECK32_ECB") )
ciphers.Add( Cipher("SIMECK32_OFB") )
ciphers.Add( Cipher("SIMECK64_CBC") )
ciphers.Add( Cipher("SIMECK64_CFB") )
ciphers.Add( Cipher("SIMECK64_CTR") )
ciphers.Add( Cipher("SIMECK64_ECB") )
ciphers.Add( Cipher("SIMECK64_OFB") )
ciphers.Add( Cipher("SIMON128_CBC") )
ciphers.Add( Cipher("SIMON128_CFB") )
ciphers.Add( Cipher("SIMON128_CTR") )
ciphers.Add( Cipher("SIMON128_ECB") )
ciphers.Add( Cipher("SIMON128_OFB") )
ciphers.Add( Cipher("SIMON64_CBC") )
ciphers.Add( Cipher("SIMON64_CFB") )
ciphers.Add( Cipher("SIMON64_CTR") )
ciphers.Add( Cipher("SIMON64_ECB") )
ciphers.Add( Cipher("SIMON64_OFB") )
ciphers.Add( Cipher("SKIPJACK_CBC") )
ciphers.Add( Cipher("SKIPJACK_CFB") )
ciphers.Add( Cipher("SKIPJACK_CTR") )
ciphers.Add( Cipher("SKIPJACK_ECB") )
ciphers.Add( Cipher("SKIPJACK_OFB") )
ciphers.Add( Cipher("SM4_CBC") )
ciphers.Add( Cipher("SM4_CFB") )
ciphers.Add( Cipher("SM4_CTR") )
ciphers.Add( Cipher("SM4_ECB") )
ciphers.Add( Cipher("SM4_OFB") )
ciphers.Add( Cipher("SOBER128") )
ciphers.Add( Cipher("SOSEMANUK") )
ciphers.Add( Cipher("SPECK128_CBC") )
ciphers.Add( Cipher("SPECK128_CFB") )
ciphers.Add( Cipher("SPECK128_CTR") )
ciphers.Add( Cipher("SPECK128_ECB") )
ciphers.Add( Cipher("SPECK128_OFB") )
ciphers.Add( Cipher("SPECK64_CBC") )
ciphers.Add( Cipher("SPECK64_CFB") )
ciphers.Add( Cipher("SPECK64_CTR") )
ciphers.Add( Cipher("SPECK64_ECB") )
ciphers.Add( Cipher("SPECK64_OFB") )
ciphers.Add( Cipher("SQUARE_CBC") )
ciphers.Add( Cipher("SQUARE_CFB") )
ciphers.Add( Cipher("SQUARE_CTR") )
ciphers.Add( Cipher("SQUARE_ECB") )
ciphers.Add( Cipher("SQUARE_OFB") )
ciphers.Add( Cipher("TEA_CBC") )
ciphers.Add( Cipher("TEA_CFB") )
ciphers.Add( Cipher("TEA_CTR") )
ciphers.Add( Cipher("TEA_ECB") )
ciphers.Add( Cipher("TEA_OFB") )
ciphers.Add( Cipher("THREEFISH_512_CBC") )
ciphers.Add( Cipher("THREEFISH_512_CFB") )
ciphers.Add( Cipher("THREEFISH_512_CTR") )
ciphers.Add( Cipher("THREEFISH_512_OFB") )
ciphers.Add( Cipher("THREEFISH_512_XTS") )
ciphers.Add( Cipher("TWOFISH") )
ciphers.Add( Cipher("TWOFISH_CBC") )
ciphers.Add( Cipher("TWOFISH_CFB") )
ciphers.Add( Cipher("TWOFISH_CTR") )
ciphers.Add( Cipher("TWOFISH_ECB") )
ciphers.Add( Cipher("TWOFISH_OFB") )
ciphers.Add( Cipher("TWOFISH_XTS") )
ciphers.Add( Cipher("XTEA_CBC") )
ciphers.Add( Cipher("XTEA_CFB") )
ciphers.Add( Cipher("XTEA_CTR") )
ciphers.Add( Cipher("XTEA_ECB") )
ciphers.Add( Cipher("XTEA_OFB") )
ciphers.Add( Cipher("XTEA_XTS") )

# AEAD ciphers
ciphers.Add( Cipher("AES_128_EAX", True) )
ciphers.Add( Cipher("AES_128_CBC_SHA1_TLS", True) )
ciphers.Add( Cipher("AES_128_CBC_SHA1_TLS_IMPLICIT_IV", True) )
ciphers.Add( Cipher("AES_128_CBC_SHA256_TLS", True) )
ciphers.Add( Cipher("AES_128_CCM_BLUETOOTH", True) )
ciphers.Add( Cipher("AES_128_CCM_BLUETOOTH_8", True) )
ciphers.Add( Cipher("AES_128_CTR_HMAC_SHA256", True) )
ciphers.Add( Cipher("AES_128_GCM", True) )
ciphers.Add( Cipher("AES_128_GCM_SIV", True) )
ciphers.Add( Cipher("AES_128_GCM_TLS12", True) )
ciphers.Add( Cipher("AES_128_GCM_TLS13", True) )
ciphers.Add( Cipher("AES_192_GCM", True) )
ciphers.Add( Cipher("AES_256_CBC_HMAC_SHA256", True) )
ciphers.Add( Cipher("AES_256_CBC_SHA1_TLS", True) )
ciphers.Add( Cipher("AES_256_CBC_SHA1_TLS_IMPLICIT_IV", True) )
ciphers.Add( Cipher("AES_256_CBC_SHA256_TLS", True) )
ciphers.Add( Cipher("AES_256_CBC_SHA384_TLS", True) )
ciphers.Add( Cipher("AES_256_CTR_HMAC_SHA256", True) )
ciphers.Add( Cipher("AES_256_GCM", True) )
ciphers.Add( Cipher("AES_256_GCM_SIV", True) )
ciphers.Add( Cipher("AES_256_GCM_TLS12", True) )
ciphers.Add( Cipher("AES_256_GCM_TLS13", True) )
ciphers.Add( Cipher("ARIA_128_GCM", True) )
ciphers.Add( Cipher("ARIA_192_GCM", True) )
ciphers.Add( Cipher("ARIA_256_GCM", True) )
ciphers.Add( Cipher("CAMELLIA_128_GCM", True) )
ciphers.Add( Cipher("CAMELLIA_192_GCM", True) )
ciphers.Add( Cipher("CAMELLIA_256_GCM", True) )
ciphers.Add( Cipher("CAMELLIA_128_CCM", True) )
ciphers.Add( Cipher("CAMELLIA_192_CCM", True) )
ciphers.Add( Cipher("CAMELLIA_256_CCM", True) )
ciphers.Add( Cipher("CHACHA20_POLY1305", True) )
ciphers.Add( Cipher("CHACHA20_POLY1305_LIBSODIUM", True) )
ciphers.Add( Cipher("DES_EDE3_CBC_SHA1_TLS", True) )
ciphers.Add( Cipher("DES_EDE3_CBC_SHA1_TLS_IMPLICIT_IV", True) )
ciphers.Add( Cipher("NULL_SHA1_TLS", True) )
ciphers.Add( Cipher("XCHACHA20_POLY1305", True) )

digests = DigestTable()

digests.Add( Digest("ADLER32", 4) )
digests.Add( Digest("BLAKE2B160", 20) )
digests.Add( Digest("BLAKE2B256", 32) )
digests.Add( Digest("BLAKE2B384", 48) )
digests.Add( Digest("BLAKE2B512", 64) )
digests.Add( Digest("BLAKE2B_MAC", 64) )
digests.Add( Digest("BLAKE2S128") )
digests.Add( Digest("BLAKE2S160") )
digests.Add( Digest("BLAKE2S224") )
digests.Add( Digest("BLAKE2S256", 32) )
digests.Add( Digest("BLAKE2S_MAC", 64) )
digests.Add( Digest("BLAKE3") )
digests.Add( Digest("CITYHASH128") )
digests.Add( Digest("CITYHASH128SEED16") )
digests.Add( Digest("CITYHASH32") )
digests.Add( Digest("CITYHASH64") )
digests.Add( Digest("CITYHASH64SEED16") )
digests.Add( Digest("CITYHASH64SEED8") )
digests.Add( Digest("CITYHASHCRC128") )
digests.Add( Digest("CITYHASHCRC128SEED16") )
digests.Add( Digest("CITYHASHCRC256") )
digests.Add( Digest("CRC32", 4) )
digests.Add( Digest("CRC32-RFC1510") )
digests.Add( Digest("CRC32-RFC2440") )
digests.Add( Digest("GOST-28147-89") )
digests.Add( Digest("GOST-R-34.11-94", 32) )
digests.Add( Digest("GOST-R-34.11-94-NO-CRYPTOPRO") )
digests.Add( Digest("GROESTL_224") )
digests.Add( Digest("GROESTL_256") )
digests.Add( Digest("GROESTL_384") )
digests.Add( Digest("GROESTL_512") )
digests.Add( Digest("JH_224") )
digests.Add( Digest("JH_256") )
digests.Add( Digest("JH_384") )
digests.Add( Digest("JH_512") )
digests.Add( Digest("KECCAK_224", 28) )
digests.Add( Digest("KECCAK_256", 32) )
digests.Add( Digest("KECCAK_384", 48) )
digests.Add( Digest("KECCAK_512", 64) )
digests.Add( Digest("MD2", 16) )
digests.Add( Digest("MD4", 16) )
digests.Add( Digest("MD5", 16) )
digests.Add( Digest("MD5_SHA1", 36) )
digests.Add( Digest("MDC2") )
digests.Add( Digest("NULL") )
digests.Add( Digest("PANAMA", 32) )
digests.Add( Digest("RIPEMD128", 16) )
digests.Add( Digest("RIPEMD160", 20) )
digests.Add( Digest("RIPEMD256", 32) )
digests.Add( Digest("RIPEMD320", 40) )
digests.Add( Digest("SHA1", 20) )
digests.Add( Digest("SHA224", 28) )
digests.Add( Digest("SHA256", 32) )
digests.Add( Digest("SHA3-224", 28) )
digests.Add( Digest("SHA3-256", 32) )
digests.Add( Digest("SHA3-384", 48) )
digests.Add( Digest("SHA3-512", 64) )
digests.Add( Digest("SHA384", 48) )
digests.Add( Digest("SHA512", 64) )
digests.Add( Digest("SHA512-224", 28) )
digests.Add( Digest("SHA512-256", 32) )
digests.Add( Digest("SHAKE128") )
digests.Add( Digest("SHAKE256") )
digests.Add( Digest("SIPHASH128") )
digests.Add( Digest("SIPHASH64") )
digests.Add( Digest("SKEIN_1024") )
digests.Add( Digest("SKEIN_256") )
digests.Add( Digest("SKEIN_512", 64) )
digests.Add( Digest("SM3", 32) )
digests.Add( Digest("STREEBOG-256", 32) )
digests.Add( Digest("STREEBOG-512", 64) )
digests.Add( Digest("T1HA-128") )
digests.Add( Digest("T1HA-64") )
digests.Add( Digest("TIGER", 24) )
digests.Add( Digest("WHIRLPOOL", 64) )
digests.Add( Digest("XXHASH32") )
digests.Add( Digest("XXHASH64") )

ecc_curves = ECC_CurveTable()

ecc_curves.Add( ECC_Curve("secp112r2",
                          bits=112,
                          prime="4451685225093714772084598273548427",
                          a="1970543761890640310119143205433388",
                          b="1660538572255285715897238774208265",
                          x="1534098225527667214992304222930499",
                          y="3525120595527770847583704454622871",
                          order_min_1="1112921306273428674967732714786890",
                          order="1112921306273428674967732714786891"
) )
ecc_curves.Add( ECC_Curve("secp256r1",
                          bits=256,
                          prime="115792089210356248762697446949407573530086143415290314195533631308867097853951",
                          a="115792089210356248762697446949407573530086143415290314195533631308867097853948",
                          b="41058363725152142129326129780047268409114441015993725554835256314039467401291",
                          x="48439561293906451759052585252797914202762949526041747995844080717082404635286",
                          y="36134250956749795798585127919587881956611106672985015071877198253568414405109",
                          order_min_1="115792089210356248762697446949407573529996955224135760342422259061068512044368",
                          order="115792089210356248762697446949407573529996955224135760342422259061068512044369"
) )
ecc_curves.Add( ECC_Curve("secp256k1",
                          bits=256,
                          prime="115792089237316195423570985008687907853269984665640564039457584007908834671663",
                          a="0",
                          b="7",
                          x="55066263022277343669578718895168534326250603453777594175500187360389116729240",
                          y="32670510020758816978083085130507043184471273380659243275938904335757337482424",
                          order_min_1="115792089237316195423570985008687907852837564279074904382605163141518161494336",
                          order="115792089237316195423570985008687907852837564279074904382605163141518161494337"
) )
ecc_curves.Add( ECC_Curve("brainpool160r1",
                          bits=160,
                          prime="1332297598440044874827085558802491743757193798159",
                          a="297190522446607939568481567949428902921613329152",
                          b="173245649450172891208247283053495198538671808088",
                          x="1089473557631435284577962539738532515920566082499",
                          y="127912481829969033206777085249718746721365418785",
                          order_min_1="1332297598440044874827085038830181364212942568456",
                          order="1332297598440044874827085038830181364212942568457"
) )
ecc_curves.Add( ECC_Curve("brainpool160t1",
                          bits=160,
                          prime="1332297598440044874827085558802491743757193798159",
                          a="1332297598440044874827085558802491743757193798156",
                          b="698401795719474705027684479972917623041381757824",
                          x="1013918819608769552616977083272059630517089149816",
                          y="992437653978037713070561264469524978381944905901",
                          order_min_1="1332297598440044874827085038830181364212942568456",
                          order="1332297598440044874827085038830181364212942568457"
) )
ecc_curves.Add( ECC_Curve("sect131r2",
                          bits=131,
                          prime=None,
                          a="1326115398407399413153688921458524648370",
                          b="1605906881731264989575575750236800229778",
                          x="1136307413960044250856528209221675869864",
                          y="2138646989904939494838997255870994916367",
                          order_min_1="1361129467683753853879535043412812867982",
                          order="1361129467683753853879535043412812867983"
) )
ecc_curves.Add( ECC_Curve("sect131r1",
                          bits=131,
                          prime=None,
                          a="2596122663589129733642851280761649459384",
                          b="712135644338826294893527440087695610689",
                          x="172441231517205131123746450595941417881",
                          y="2568642209052024897328995836629039571280",
                          order_min_1="1361129467683753853893932755685365560652",
                          order="1361129467683753853893932755685365560653"
) )
ecc_curves.Add( ECC_Curve("secp160r2",
                          bits=161,
                          prime="1461501637330902918203684832716283019651637554291",
                          a="1461501637330902918203684832716283019651637554288",
                          b="1032640608390511495214075079957864673410201913530",
                          x="473058756663038503608844550604547710019657059949",
                          y="1454008495369951658060798698479395908327453245230",
                          order_min_1="1461501637330902918203685083571792140653176136042",
                          order="1461501637330902918203685083571792140653176136043"
) )
ecc_curves.Add( ECC_Curve("secp160k1",
                          bits=161,
                          prime="1461501637330902918203684832716283019651637554291",
                          a="0",
                          b="7",
                          x="338530205676502674729549372677647997389429898939",
                          y="842365456698940303598009444920994870805149798382",
                          order_min_1="1461501637330902918203686915170869725397159163570",
                          order="1461501637330902918203686915170869725397159163571"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls9",
                          bits=160,
                          prime="1461501637330902918203684832716283019655932313743",
                          a="0",
                          b="3",
                          x="1",
                          y="2",
                          order_min_1="1461501637330902918203687013445034429194588307250",
                          order="1461501637330902918203687013445034429194588307251"
) )
ecc_curves.Add( ECC_Curve("secp160r1",
                          bits=161,
                          prime="1461501637330902918203684832716283019653785059327",
                          a="1461501637330902918203684832716283019653785059324",
                          b="163235791306168110546604919403271579530548345413",
                          x="425826231723888350446541592701409065913635568770",
                          y="203520114162904107873991457957346892027982641970",
                          order_min_1="1461501637330902918203687197606826779884643492438",
                          order="1461501637330902918203687197606826779884643492439"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls7",
                          bits=161,
                          prime="1461501637330902918203684832716283019653785059327",
                          a="1461501637330902918203684832716283019653785059324",
                          b="163235791306168110546604919403271579530548345413",
                          x="425826231723888350446541592701409065913635568770",
                          y="203520114162904107873991457957346892027982641970",
                          order_min_1="1461501637330902918203687197606826779884643492438",
                          order="1461501637330902918203687197606826779884643492439"
) )
ecc_curves.Add( ECC_Curve("brainpool320r1",
                          bits=320,
                          prime="1763593322239166354161909842446019520889512772719515192772960415288640868802149818095501499903527",
                          a="524709318439392693105919717518043758943240164412117372990311331314771510648804065756354311491252",
                          b="684460840191207052139729091116995410883497412720006364295713596062999867796741135919289734394278",
                          x="565203972584199378547773331021708157952136817703497461781479793049434111597020229546183313458705",
                          y="175146432689526447697480803229621572834859050903464782210773312572877763380340633688906597830369",
                          order_min_1="1763593322239166354161909842446019520889512772717686063760686124016784784845843468355685258203920",
                          order="1763593322239166354161909842446019520889512772717686063760686124016784784845843468355685258203921"
) )
ecc_curves.Add( ECC_Curve("brainpool320t1",
                          bits=320,
                          prime="1763593322239166354161909842446019520889512772719515192772960415288640868802149818095501499903527",
                          a="1763593322239166354161909842446019520889512772719515192772960415288640868802149818095501499903524",
                          b="1401395435032847536924656852322353441447762422733674743806973258207878888547540276867732868432723",
                          x="1221175819973001316491038958226563119032598033059331804921649457916311604176688737745420093746514",
                          y="832095900618272253462376182163435186143818309959785348829039065198217071225345202726924484399811",
                          order_min_1="1763593322239166354161909842446019520889512772717686063760686124016784784845843468355685258203920",
                          order="1763593322239166354161909842446019520889512772717686063760686124016784784845843468355685258203921"
) )
ecc_curves.Add( ECC_Curve("sect571k1",
                          bits=571,
                          prime=None,
                          a="0",
                          b="1",
                          x="2350112116304015523482377231684766626496228526415123964355167346023168453994712131915750801804327368697642410358740900984083649787136749901162917044657353481320802543241586",
                          y="3177153047892284027955092820645594290840691892110463136294318330308675645046690871624329737215785097835850661950174873195667225591921644089615520604151251098277510177212323",
                          order_min_1="1932268761508629172347675945465993672149463664853217499328617625725759571144780212268133978522706711834706712800825351461273674974066617311929682421617092503555733685276672",
                          order="1932268761508629172347675945465993672149463664853217499328617625725759571144780212268133978522706711834706712800825351461273674974066617311929682421617092503555733685276673"
) )
ecc_curves.Add( ECC_Curve("brainpool384r1",
                          bits=384,
                          prime="21659270770119316173069236842332604979796116387017648600081618503821089934025961822236561982844534088440708417973331",
                          a="19048979039598244295279281525021548448223459855185222892089532512446337024935426033638342846977861914875721218402342",
                          b="717131854892629093329172042053689661426642816397448020844407951239049616491589607702456460799758882466071646850065",
                          x="4480579927441533893329522230328287337018133311029754539518372936441756157459087304048546502931308754738349656551198",
                          y="21354446258743982691371413536748675410974765754620216137225614281636810686961198361153695003859088327367976229294869",
                          order_min_1="21659270770119316173069236842332604979796116387017648600075645274821611501358515537962695117368903252229601718723940",
                          order="21659270770119316173069236842332604979796116387017648600075645274821611501358515537962695117368903252229601718723941"
) )
ecc_curves.Add( ECC_Curve("brainpool384t1",
                          bits=384,
                          prime="21659270770119316173069236842332604979796116387017648600081618503821089934025961822236561982844534088440708417973331",
                          a="21659270770119316173069236842332604979796116387017648600081618503821089934025961822236561982844534088440708417973328",
                          b="19596161053329239268181228455226581162286252326261019516900162717091837027531392576647644262320816848087868142547438",
                          x="3827769047710394604076870463731979903132904572714069494181204655675960538951736634566672590576020545838501853661388",
                          y="5797643717699939326787282953388004860198302425468870641753455602553471777319089854136002629714659021021358409132328",
                          order_min_1="21659270770119316173069236842332604979796116387017648600075645274821611501358515537962695117368903252229601718723940",
                          order="21659270770119316173069236842332604979796116387017648600075645274821611501358515537962695117368903252229601718723941"
) )
ecc_curves.Add( ECC_Curve("sect239k1",
                          bits=233,
                          prime=None,
                          a="0",
                          b="1",
                          x="287304427851433003189509051221031978591368025490899286200762613294446044",
                          y="815727950839377703994180670110555770834903050527325106707102047979958474",
                          order_min_1="220855883097298041197912187592864814948216561321709848887480219215362212",
                          order="220855883097298041197912187592864814948216561321709848887480219215362213"
) )
ecc_curves.Add( ECC_Curve("brainpool224r1",
                          bits=224,
                          prime="22721622932454352787552537995910928073340732145944992304435472941311",
                          a="11020725272625742361946480833014344015343456918668456061589001510723",
                          b="3949606626053374030787926457695139766118442946052311411513528958987",
                          x="1428364927244201726431498207475486496993067267318520844137448783997",
                          y="9337555360448823227812410753177468631215558779020518084752618816205",
                          order_min_1="22721622932454352787552537995910923612567546342330757191396560966558",
                          order="22721622932454352787552537995910923612567546342330757191396560966559"
) )
ecc_curves.Add( ECC_Curve("brainpool224t1",
                          bits=224,
                          prime="22721622932454352787552537995910928073340732145944992304435472941311",
                          a="22721622932454352787552537995910928073340732145944992304435472941308",
                          b="7919603849831377222129533323916957959225380016698795812027476510861",
                          x="11236281700362234642592534287151572422539408672654616227474732012928",
                          y="364032462118593425315751587028126980694396626774408344039871404876",
                          order_min_1="22721622932454352787552537995910923612567546342330757191396560966558",
                          order="22721622932454352787552537995910923612567546342330757191396560966559"
) )
ecc_curves.Add( ECC_Curve("secp224r1",
                          bits=224,
                          prime="26959946667150639794667015087019630673557916260026308143510066298881",
                          a="26959946667150639794667015087019630673557916260026308143510066298878",
                          b="18958286285566608000408668544493926415504680968679321075787234672564",
                          x="19277929113566293071110308034699488026831934219452440156649784352033",
                          y="19926808758034470970197974370888749184205991990603949537637343198772",
                          order_min_1="26959946667150639794667015087019625940457807714424391721682722368060",
                          order="26959946667150639794667015087019625940457807714424391721682722368061"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls12",
                          bits=224,
                          prime="26959946667150639794667015087019630673557916260026308143510066298881",
                          a="26959946667150639794667015087019630673557916260026308143510066298878",
                          b="18958286285566608000408668544493926415504680968679321075787234672564",
                          x="19277929113566293071110308034699488026831934219452440156649784352033",
                          y="19926808758034470970197974370888749184205991990603949537637343198772",
                          order_min_1="26959946667150639794667015087019625940457807714424391721682722368060",
                          order="26959946667150639794667015087019625940457807714424391721682722368061"
) )
ecc_curves.Add( ECC_Curve("secp224k1",
                          bits=225,
                          prime="26959946667150639794667015087019630673637144422540572481099315275117",
                          a="0",
                          b="5",
                          x="16983810465656793445178183341822322175883642221536626637512293983324",
                          y="13272896753306862154536785447615077600479862871316829862783613755813",
                          order_min_1="26959946667150639794667015087019640346510327083120074548994958668278",
                          order="26959946667150639794667015087019640346510327083120074548994958668279"
) )
ecc_curves.Add( ECC_Curve("sect409k1",
                          bits=409,
                          prime=None,
                          a="0",
                          b="1",
                          x="250320606379109783324043328573944955992891736106680352671677389786222910027088291741834878773922859231376787355260678190918",
                          y="1248286015820357801871250692732381479576954307085883348044850800154576601694946857655762823838587314348501053191643883120747",
                          order_min_1="330527984395124299475957654016385519914202341482140609642324395022880711289249191050673258457777458014096366590617731358670",
                          order="330527984395124299475957654016385519914202341482140609642324395022880711289249191050673258457777458014096366590617731358671"
) )
ecc_curves.Add( ECC_Curve("secp128r1",
                          bits=128,
                          prime="340282366762482138434845932244680310783",
                          a="340282366762482138434845932244680310780",
                          b="308990863222245658030922601041482374867",
                          x="29408993404948928992877151431649155974",
                          y="275621562871047521857442314737465260675",
                          order_min_1="340282366762482138443322565580356624660",
                          order="340282366762482138443322565580356624661"
) )
ecc_curves.Add( ECC_Curve("sect233k1",
                          bits=233,
                          prime=None,
                          a="0",
                          b="1",
                          x="9980522611481012342443087688797002679043489582926858424680330554073382",
                          y="12814767389816757102953168016268660157166792010263439198493421287958179",
                          order_min_1="3450873173395281893717377931138512760570940988862252126328087024741342",
                          order="3450873173395281893717377931138512760570940988862252126328087024741343"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls10",
                          bits=233,
                          prime=None,
                          a="0",
                          b="1",
                          x="9980522611481012342443087688797002679043489582926858424680330554073382",
                          y="12814767389816757102953168016268660157166792010263439198493421287958179",
                          order_min_1="3450873173395281893717377931138512760570940988862252126328087024741342",
                          order="3450873173395281893717377931138512760570940988862252126328087024741343"
) )
ecc_curves.Add( ECC_Curve("sect571r1",
                          bits=571,
                          prime=None,
                          a="1",
                          b="2853329245261343535560086964181551296889298776106832980891560850944180011701123307905326019642652653533003482753023669016842884108172514870944140611113679225347419720217210",
                          x="2909726711393360238997027325079981094903293083416277207163191533186952179846948691035435651273252692731060457249729605513129233502615507099213961913121214831097565254790425",
                          y="3366174731810125753087813209708676894833150358595778752145226712858102783612277607950241452090192525005883890170639174605150394168627448707126811848455102037101825665712475",
                          order_min_1="3864537523017258344695351890931987344298927329706434998657235251451519142289560424536143999389415773083133881121926944486246872462816813070234528288303332411393191105285702",
                          order="3864537523017258344695351890931987344298927329706434998657235251451519142289560424536143999389415773083133881121926944486246872462816813070234528288303332411393191105285703"
) )
ecc_curves.Add( ECC_Curve("sect283k1",
                          bits=283,
                          prime=None,
                          a="0",
                          b="1",
                          x="9737095673315832344313391497449387731784428326114441977662399932694280557468376967222",
                          y="3497201781826516614681192670485202061196189998012192335594744939847890291586353668697",
                          order_min_1="3885337784451458141838923813647037813284811733793061324295874997529815829704422603872",
                          order="3885337784451458141838923813647037813284811733793061324295874997529815829704422603873"
) )
ecc_curves.Add( ECC_Curve("secp384r1",
                          bits=384,
                          prime="39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",
                          a="39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316",
                          b="27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575",
                          x="26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087",
                          y="8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871",
                          order_min_1="39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942642",
                          order="39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"
) )
ecc_curves.Add( ECC_Curve("secp112r1",
                          bits=112,
                          prime="4451685225093714772084598273548427",
                          a="4451685225093714772084598273548424",
                          b="2061118396808653202902996166388514",
                          x="188281465057972534892223778713752",
                          y="3419875491033170827167861896082688",
                          order_min_1="4451685225093714776491891542548932",
                          order="4451685225093714776491891542548933"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls6",
                          bits=112,
                          prime="4451685225093714772084598273548427",
                          a="4451685225093714772084598273548424",
                          b="2061118396808653202902996166388514",
                          x="188281465057972534892223778713752",
                          y="3419875491033170827167861896082688",
                          order_min_1="4451685225093714776491891542548932",
                          order="4451685225093714776491891542548933"
) )
ecc_curves.Add( ECC_Curve("brainpool192r1",
                          bits=192,
                          prime="4781668983906166242955001894344923773259119655253013193367",
                          a="2613009377683017747869391908421543348309181741502784219375",
                          b="1731160591135112004210203499537764623771657619977468323273",
                          x="4723188856514392935399337699153522173525168621081341681622",
                          y="507884783101387741749746950209061101579755255809652136847",
                          order_min_1="4781668983906166242955001894269038308119863659119834868928",
                          order="4781668983906166242955001894269038308119863659119834868929"
) )
ecc_curves.Add( ECC_Curve("brainpool192t1",
                          bits=192,
                          prime="4781668983906166242955001894344923773259119655253013193367",
                          a="4781668983906166242955001894344923773259119655253013193364",
                          b="486321888066950067394881041525590797530120076120499518329",
                          x="1444558712667280506885530592978306040338136913835324440873",
                          y="232764348904945951820395534722141373682806994795615748553",
                          order_min_1="4781668983906166242955001894269038308119863659119834868928",
                          order="4781668983906166242955001894269038308119863659119834868929"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls1",
                          bits=113,
                          prime=None,
                          a="1",
                          b="1",
                          x="7270726891776529038903590073665047",
                          y="4954873249839491011382670248365077",
                          order_min_1="5192296858534827627896703833467506",
                          order="5192296858534827627896703833467507"
) )
ecc_curves.Add( ECC_Curve("sect113r1",
                          bits=113,
                          prime=None,
                          a="984342157317881800509153672175863",
                          b="4720643197658441292834747278018339",
                          x="3193479700953970059711257944178959",
                          y="3349781614104721427986676261787782",
                          order_min_1="5192296858534827689835882578830702",
                          order="5192296858534827689835882578830703"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls4",
                          bits=113,
                          prime=None,
                          a="984342157317881800509153672175863",
                          b="4720643197658441292834747278018339",
                          x="3193479700953970059711257944178959",
                          y="3349781614104721427986676261787782",
                          order_min_1="5192296858534827689835882578830702",
                          order="5192296858534827689835882578830703"
) )
ecc_curves.Add( ECC_Curve("sect113r2",
                          bits=113,
                          prime=None,
                          a="2121500201156255644417183296673223",
                          b="3040591781815807764515357141309519",
                          x="8548593233256193383924583779157911",
                          y="3644320092943472267836480028326429",
                          order_min_1="5192296858534827702972497909952402",
                          order="5192296858534827702972497909952403"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls8",
                          bits=113,
                          prime="5192296858534827628530496329219559",
                          a="0",
                          b="3",
                          x="1",
                          y="2",
                          order_min_1="5192296858534827767273836114360296",
                          order="5192296858534827767273836114360297"
) )
ecc_curves.Add( ECC_Curve("sect163r1",
                          bits=163,
                          prime=None,
                          a="11272584574060402170600355401469405585559711656674",
                          b="10341149448350347985759700389662805134872097107929",
                          x="4987329473907365857178124865428460464972118795860",
                          y="384617752061712164277996110850745784319273334915",
                          order_min_1="5846006549323611672814738465098798981304420411290",
                          order="5846006549323611672814738465098798981304420411291"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls5",
                          bits=163,
                          prime=None,
                          a="10443320962232641889919257604546406114902811759170",
                          b="1149324396657421150694884172923012442275218052313",
                          x="11231939716319002641657718190438797246676750304203",
                          y="2809606869339171705995869785003496413002248735391",
                          order_min_1="5846006549323611672814741626226392056573832638400",
                          order="5846006549323611672814741626226392056573832638401"
) )
ecc_curves.Add( ECC_Curve("sect163k1",
                          bits=163,
                          prime=None,
                          a="1",
                          b="1",
                          x="4373527398576640063579304354969275615843559206632",
                          y="3705292482178961271312284701371585420180764402649",
                          order_min_1="5846006549323611672814741753598448348329118574062",
                          order="5846006549323611672814741753598448348329118574063"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls3",
                          bits=163,
                          prime=None,
                          a="1",
                          b="1",
                          x="4373527398576640063579304354969275615843559206632",
                          y="3705292482178961271312284701371585420180764402649",
                          order_min_1="5846006549323611672814741753598448348329118574062",
                          order="5846006549323611672814741753598448348329118574063"
) )
ecc_curves.Add( ECC_Curve("sect163r2",
                          bits=163,
                          prime=None,
                          a="1",
                          b="2982236234343851336267446656627785008148015875581",
                          x="5759917430716753942228907521556834309477856722486",
                          y="1216722771297916786238928618659324865903148082417",
                          order_min_1="5846006549323611672814742442876390689256843201586",
                          order="5846006549323611672814742442876390689256843201587"
) )
ecc_curves.Add( ECC_Curve("secp192k1",
                          bits=192,
                          prime="6277101735386680763835789423207666416102355444459739541047",
                          a="0",
                          b="3",
                          x="5377521262291226325198505011805525673063229037935769709693",
                          y="3805108391982600717572440947423858335415441070543209377693",
                          order_min_1="6277101735386680763835789423061264271957123915200845512076",
                          order="6277101735386680763835789423061264271957123915200845512077"
) )
ecc_curves.Add( ECC_Curve("secp192r1",
                          bits=192,
                          prime="6277101735386680763835789423207666416083908700390324961279",
                          a="6277101735386680763835789423207666416083908700390324961276",
                          b="2455155546008943817740293915197451784769108058161191238065",
                          x="602046282375688656758213480587526111916698976636884684818",
                          y="174050332293622031404857552280219410364023488927386650641",
                          order_min_1="6277101735386680763835789423176059013767194773182842284080",
                          order="6277101735386680763835789423176059013767194773182842284081"
) )
ecc_curves.Add( ECC_Curve("sect193r1",
                          bits=193,
                          prime=None,
                          a="576751075026818752436662854952381179295973340004111842049",
                          b="6227610566229294112017936480812099737256078134172818311188",
                          x="12272390550309971036302743370064453956929989632374098413025",
                          y="929037239281491062957629204723061153948896755298992003845",
                          order_min_1="6277101735386680763835789423269548053691575186051040197192",
                          order="6277101735386680763835789423269548053691575186051040197193"
) )
ecc_curves.Add( ECC_Curve("sect193r2",
                          bits=193,
                          prime=None,
                          a="8727883239842844933732220251183800395075376381527050055835",
                          b="4946476016329916785216072668156805272487483199688540362414",
                          x="5338303459516340642470631733027504050881957481257426321039",
                          y="11342401828932489703393760444197037534175341100765106065260",
                          order_min_1="6277101735386680763835789423314955362437298222279840143828",
                          order="6277101735386680763835789423314955362437298222279840143829"
) )
ecc_curves.Add( ECC_Curve("sect409r1",
                          bits=409,
                          prime=None,
                          a="1",
                          b="86886261634090707672817770640384425264505829479043641824438658614111870471004564988634410809058207142318571212147935892575",
                          x="901935279919555460519938020229627704409149556251441963587868715440518797594851300277260702073828731983206453567757135484583",
                          y="252271804478663965520986398892908223486048997352743726687083769858460083134230324190507814191768191984593727083669152319238",
                          order_min_1="661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526770",
                          order="661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526771"
) )
ecc_curves.Add( ECC_Curve("secp521r1",
                          bits=521,
                          prime="6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151",
                          a="6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148",
                          b="1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984",
                          x="2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846",
                          y="3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784",
                          order_min_1="6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005448",
                          order="6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"
) )
ecc_curves.Add( ECC_Curve("sect233r1",
                          bits=233,
                          prime=None,
                          a="1",
                          b="2760497980029204187078845502377898520307707256259003964398570147123373",
                          x="6761246501583409083997096882159824046681246465812468867444643442021771",
                          y="6912913004411390932094889411904587007871508723951293564567204383952978",
                          order_min_1="6901746346790563787434755862277025555839812737345013555379383634485462",
                          order="6901746346790563787434755862277025555839812737345013555379383634485463"
) )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls11",
                          bits=233,
                          prime=None,
                          a="1",
                          b="2760497980029204187078845502377898520307707256259003964398570147123373",
                          x="6761246501583409083997096882159824046681246465812468867444643442021771",
                          y="6912913004411390932094889411904587007871508723951293564567204383952978",
                          order_min_1="6901746346790563787434755862277025555839812737345013555379383634485462",
                          order="6901746346790563787434755862277025555839812737345013555379383634485463"
) )
ecc_curves.Add( ECC_Curve("brainpool256r1",
                          bits=256,
                          prime="76884956397045344220809746629001649093037950200943055203735601445031516197751",
                          a="56698187605326110043627228396178346077120614539475214109386828188763884139993",
                          b="17577232497321838841075697789794520262950426058923084567046852300633325438902",
                          x="63243729749562333355292243550312970334778175571054726587095381623627144114786",
                          y="38218615093753523893122277964030810387585405539772602581557831887485717997975",
                          order_min_1="76884956397045344220809746629001649092737531784414529538755519063063536359078",
                          order="76884956397045344220809746629001649092737531784414529538755519063063536359079"
) )
ecc_curves.Add( ECC_Curve("brainpool256t1",
                          bits=256,
                          prime="76884956397045344220809746629001649093037950200943055203735601445031516197751",
                          a="76884956397045344220809746629001649093037950200943055203735601445031516197748",
                          b="46214326585032579593829631435610129746736367449296220983687490401182983727876",
                          x="74138526386500101787937404544159543470173440588427591213843535686338908194292",
                          y="20625154686056605250529482107801269759951443923312408063441227608803066104254",
                          order_min_1="76884956397045344220809746629001649092737531784414529538755519063063536359078",
                          order="76884956397045344220809746629001649092737531784414529538755519063063536359079"
) )
ecc_curves.Add( ECC_Curve("sect283r1",
                          bits=283,
                          prime=None,
                          a="1",
                          b="4821813576056072374006997780399081180312270030300601270120450341205914644378616963829",
                          x="11604587487407003699882500449177537465719784002620028212980871291231978603047872962643",
                          y="6612720053854191978412609357563545875491153188501906352980899759345275170452624446196",
                          order_min_1="7770675568902916283677847627294075626569625924376904889109196526770044277787378692870",
                          order="7770675568902916283677847627294075626569625924376904889109196526770044277787378692871"
) )
ecc_curves.Add( ECC_Curve("secp128r2",
                          bits=128,
                          prime="340282366762482138434845932244680310783",
                          a="284470887156368047300405921324061011681",
                          b="126188322377389722996253562430093625949",
                          x="164048790688614013222215505581242564928",
                          y="52787839253935625605232456597451787076",
                          order_min_1="85070591690620534603955721926813660578",
                          order="85070591690620534603955721926813660579"
) )
ecc_curves.Add( ECC_Curve("brainpool512r1",
                          bits=512,
                          prime="8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947",
                          a="6294860557973063227666421306476379324074715770622746227136910445450301914281276098027990968407983962691151853678563877834221834027439718238065725844264138",
                          b="3245789008328967059274849584342077916531909009637501918328323668736179176583263496463525128488282611559800773506973771797764811498834995234341530862286627",
                          x="6792059140424575174435640431269195087843153390102521881468023012732047482579853077545647446272866794936371522410774532686582484617946013928874296844351522",
                          y="6592244555240112873324748381429610341312712940326266331327445066687010545415256461097707483288650216992613090185042957716318301180159234788504307628509330",
                          order_min_1="8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544168",
                          order="8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169"
) )
ecc_curves.Add( ECC_Curve("brainpool512t1",
                          bits=512,
                          prime="8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947",
                          a="8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816944",
                          b="6532815740455945129522030162820444801309011444717674409730083343052139800841847092116476221316466234404847931899409316558007222582458822004777353814164030",
                          x="5240454105373391383446315535930423532243726242869439206480578543706358506399554673205583372921814351137736817888782671966171301927338369930113338349467098",
                          y="4783098043208509222858478731459039446855297686825168822962919559100076900387655035060042118755576220187973470126780576052258118403094460341772613532037938",
                          order_min_1="8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544168",
                          order="8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169"
) )
ecc_curves.Add( ECC_Curve("frp256v1",
                          bits=256,
                          prime="109454571331697278617670725030735128145969349647868738157201323556196022393859",
                          a="109454571331697278617670725030735128145969349647868738157201323556196022393856",
                          b="107744541122042688792155207242782455150382764043089114141096634497567301547839",
                          x="82638672503301278923015998535776227331280144783487139112686874194432446389503",
                          y="43992510890276411535679659957604584722077886330284298232193264058442323471611",
                          order_min_1="109454571331697278617670725030735128146004546811402412653072203207726079563232",
                          order="109454571331697278617670725030735128146004546811402412653072203207726079563233"
) )
ecc_curves.Add( ECC_Curve("ed25519",
                          bits=255,
                          prime="57896044618658097711785492504343953926634992332820282019728792003956564819949",
                          a="57896044618658097711785492504343953926634992332820282019728792003956564819948",
                          b="37095705934669439343138083508754565189542113879843219016388785533085940283555",
                          x="15112221349535400772501151409588531511454012693041857206046113283949847762202",
                          y="46316835694926478169428394003475163141307993866256225615783033603165251855960",
                          order_min_1="7237005577332262213973186563042994240857116359379907606001950938285454250988",
                          order="7237005577332262213973186563042994240857116359379907606001950938285454250989"
) )
ecc_curves.Add( ECC_Curve("ed448",
                          bits=448,
                          prime="726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439",
                          a="1",
                          b="726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018326358",
                          x="484559149530404593699549205258669689569094240458212040187660132787056912146709081364401144455726350866276831544947397859048262938744149",
                          y="494088759867433727674302672526735089350544552303727723746126484473087719117037293890093462157703888342865036477787453078312060500281069",
                          order_min_1="181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649778",
                          order="181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779"
) )
ecc_curves.Add( ECC_Curve("BLS12_381",
                          bits=381,
                          prime="4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
                          a="0",
                          b="4",
                          x="3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507",
                          y="1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569",
                          order_min_1="52435875175126190479447740508185965837690552500527637822603658699938581184512",
                          order="52435875175126190479447740508185965837690552500527637822603658699938581184513"
) )

# TODO specify curve parameters for these remaining curves
ecc_curves.Add( ECC_Curve("gost_256A") )
ecc_curves.Add( ECC_Curve("gost_512A") )
ecc_curves.Add( ECC_Curve("gostr3410_2001_cryptopro_a") )
ecc_curves.Add( ECC_Curve("gostr3410_2001_cryptopro_b") )
ecc_curves.Add( ECC_Curve("gostr3410_2001_cryptopro_c") )
ecc_curves.Add( ECC_Curve("gostr3410_2001_cryptopro_xcha") )
ecc_curves.Add( ECC_Curve("gostr3410_2001_cryptopro_xchb") )
ecc_curves.Add( ECC_Curve("gostr3410_2001_test") )
ecc_curves.Add( ECC_Curve("ipsec3") )
ecc_curves.Add( ECC_Curve("ipsec4") )
ecc_curves.Add( ECC_Curve("numsp256t1", order="28948022309329048855892746252171976963230320855948034936185801359597441823917") )
ecc_curves.Add( ECC_Curve("numsp384t1", order="9850501549098619803069760025035903451269934817616361666986603623638432032256865558780541454083219163250604218936869") )
ecc_curves.Add( ECC_Curve("numsp512t1", order="3351951982485649274893506249551461531869841455148098344430890360930441007518346893020404367996870882777121262593078152830179243535023501253454245088133513") )
ecc_curves.Add( ECC_Curve("sm2p256v1", order="115792089210356248756420345214020892766061623724957744567843809356293439045923") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_a") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_b") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_c") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_d") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_a") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_b") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_c") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_test") )
ecc_curves.Add( ECC_Curve("x25519") )
ecc_curves.Add( ECC_Curve("x448") )
ecc_curves.Add( ECC_Curve("x962_c2pnb163v1", order="5846006549323611672814741626226392056573832638401") )
ecc_curves.Add( ECC_Curve("x962_c2pnb163v2", order="5846006549323611672814736867226446213508588572839") )
ecc_curves.Add( ECC_Curve("x962_c2pnb163v3", order="5846006549323611672814737040186791886263374189321") )
ecc_curves.Add( ECC_Curve("x962_c2pnb176v1", order="1464764815784035076424479112383122688505483765421") )
ecc_curves.Add( ECC_Curve("x962_c2pnb208w1", order="6319530221984476934661765632900719012846431750114578083741") )
ecc_curves.Add( ECC_Curve("x962_c2pnb272w1", order="116235492452543488393823301680748870034491124166583946466668991869818652235041") )
ecc_curves.Add( ECC_Curve("x962_c2pnb304w1", order="500884825900595933307132795674658837818095809137913478977332553047879960661308247049501") )
ecc_curves.Add( ECC_Curve("x962_c2pnb368w1", order="9194196556002283250851893699199753471497656173851998515361706855000304737080699826013007012009780734318951") )
ecc_curves.Add( ECC_Curve("x962_c2tnb191v1", order="1569275433846670190958947355803350458831205595451630533029") )
ecc_curves.Add( ECC_Curve("x962_c2tnb191v2", order="784637716923335095479473677925814481401065348266378101107") )
ecc_curves.Add( ECC_Curve("x962_c2tnb191v3", order="523091811282223396986315785270930752647646535584668335779") )
ecc_curves.Add( ECC_Curve("x962_c2tnb239v1", order="220855883097298041197912187592864814557886993776713230936715041207411783") )
ecc_curves.Add( ECC_Curve("x962_c2tnb239v2", order="147237255398198694131941458395243209523006695456232690299263349237764653") )
ecc_curves.Add( ECC_Curve("x962_c2tnb239v3", order="88342353238919216479164875037145925622548965147075144322778604225055999") )
ecc_curves.Add( ECC_Curve("x962_c2tnb359v1", order="15450938044564692288746582873614059390629490453344209663962540632677447295745316740045672843724365195742523") )
ecc_curves.Add( ECC_Curve("x962_c2tnb431r1", order="550132875817621995948098052409342004650086721304725510946523726312246334661592590780763978563125341997711919748453208343530129") )
ecc_curves.Add( ECC_Curve("x962_p192v1", order="6277101735386680763835789423176059013767194773182842284081") )
ecc_curves.Add( ECC_Curve("x962_p192v2", order="6277101735386680763835789423078825936192100537584385056049") )
ecc_curves.Add( ECC_Curve("x962_p192v3", order="6277101735386680763835789423166314882687165660350679936019") )
ecc_curves.Add( ECC_Curve("x962_p239v1", order="883423532389192164791648750360308884807550341691627752275345424702807307") )
ecc_curves.Add( ECC_Curve("x962_p239v2", order="883423532389192164791648750360308886392687657546993855147765732451295331") )
ecc_curves.Add( ECC_Curve("x962_p239v3", order="883423532389192164791648750360308884771190369765922550517967171058034001") )
ecc_curves.Add( ECC_Curve("x962_p256v1", order="115792089210356248762697446949407573529996955224135760342422259061068512044369") )

ecc_curves.Add( ECC_Curve("BN256") )
ecc_curves.Add( ECC_Curve("BN384") )
ecc_curves.Add( ECC_Curve("BN512") )

calcops = CalcOpTable()
calcops.Add( CalcOp("Abs(A)") )
calcops.Add( CalcOp("Add(A,B)") )
calcops.Add( CalcOp("AddMod(A,B,C)") )
calcops.Add( CalcOp("And(A,B)") )
calcops.Add( CalcOp("Bit(A,B)") )
calcops.Add( CalcOp("ClearBit(A,B)") )
calcops.Add( CalcOp("Cmp(A,B)") )
calcops.Add( CalcOp("CmpAbs(A,B)") )
calcops.Add( CalcOp("CondSet(A,B)") )
calcops.Add( CalcOp("Div(A,B)") )
calcops.Add( CalcOp("Exp(A,B)") )
calcops.Add( CalcOp("Exp2(A)") )
calcops.Add( CalcOp("ExpMod(A,B,C)") )
calcops.Add( CalcOp("GCD(A,B)") )
calcops.Add( CalcOp("InvMod(A,B)") )
calcops.Add( CalcOp("IsCoprime(A,B)") )
calcops.Add( CalcOp("IsEq(A,B)") )
calcops.Add( CalcOp("IsEven(A)") )
calcops.Add( CalcOp("IsGt(A,B)") )
calcops.Add( CalcOp("IsGte(A,B)") )
calcops.Add( CalcOp("IsLt(A,B)") )
calcops.Add( CalcOp("IsLte(A,B)") )
calcops.Add( CalcOp("IsNeg(A)") )
calcops.Add( CalcOp("IsNotZero(A)") )
calcops.Add( CalcOp("IsOdd(A)") )
calcops.Add( CalcOp("IsOne(A)") )
calcops.Add( CalcOp("IsPow2(A)") )
calcops.Add( CalcOp("IsPrime(A)") )
calcops.Add( CalcOp("IsZero(A)") )
calcops.Add( CalcOp("Jacobi(A,B)") )
calcops.Add( CalcOp("LCM(A,B)") )
calcops.Add( CalcOp("LShift1(A)") )
calcops.Add( CalcOp("Log10(A)") )
calcops.Add( CalcOp("MSB(A)") )
calcops.Add( CalcOp("Mask(A,B)") )
calcops.Add( CalcOp("Max(A,B)") )
calcops.Add( CalcOp("Min(A,B)") )
calcops.Add( CalcOp("Mod(A,B)") )
calcops.Add( CalcOp("ModLShift(A,B,C)") )
calcops.Add( CalcOp("Mod_NIST_192(A)") )
calcops.Add( CalcOp("Mod_NIST_224(A)") )
calcops.Add( CalcOp("Mod_NIST_256(A)") )
calcops.Add( CalcOp("Mod_NIST_384(A)") )
calcops.Add( CalcOp("Mod_NIST_521(A)") )
calcops.Add( CalcOp("Mul(A,B)") )
calcops.Add( CalcOp("MulAdd(A,B,C)") )
calcops.Add( CalcOp("MulMod(A,B,C)") )
calcops.Add( CalcOp("Neg(A)") )
calcops.Add( CalcOp("Not(A)") )
calcops.Add( CalcOp("NumBits(A)") )
calcops.Add( CalcOp("NumLSZeroBits(A)") )
calcops.Add( CalcOp("Or(A,B)") )
calcops.Add( CalcOp("RShift(A,B)") )
calcops.Add( CalcOp("Rand()") )
calcops.Add( CalcOp("Ressol(A,B)") )
calcops.Add( CalcOp("Set(A)") )
calcops.Add( CalcOp("SetBit(A,B)") )
calcops.Add( CalcOp("Sqr(A)") )
calcops.Add( CalcOp("SqrMod(A,B)") )
calcops.Add( CalcOp("Sqrt(A)") )
calcops.Add( CalcOp("SqrtMod(A,B)") )
calcops.Add( CalcOp("Sub(A,B)") )
calcops.Add( CalcOp("SubMod(A,B,C)") )
calcops.Add( CalcOp("Xor(A,B)") )

tables = [modules, operations, ciphers, digests, ecc_curves, calcops]

with open('repository_tbl.h', 'w') as fp:
    for table in tables:
        fp.write(table.GetTableDecl())
        fp.write(table.ToCPPTable())
with open('repository_map.h', 'w') as fp:
    for table in tables:
        fp.write(table.GetTableDecl())
        fp.write(table.ToCPPMap())
