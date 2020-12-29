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
    def __init__(self, operation, order = None):
        super(ECC_Curve, self).__init__(operation)

        if order == None:
            self.order = "std::nullopt"
        else:
            self.order = '"' + order + '"'

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
                "std::optional<const char*> order",
        ]

        super(ECC_CurveTable, self).__init__('ECC_Curve', tableDecl)
    def getTableEntryList(self, index):
        tableEntry = []

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
modules.Add( Module("Reference implementations") )
modules.Add( Module("SymCrypt") )
modules.Add( Module("Veracrypt") )
modules.Add( Module("bignumber.js") )
modules.Add( Module("bn.js") )
modules.Add( Module("crypto-js") )
modules.Add( Module("elliptic") )
modules.Add( Module("libgcrypt") )
modules.Add( Module("libgmp") )
modules.Add( Module("libsodium") )
modules.Add( Module("libtomcrypt") )
modules.Add( Module("libtommath") )
modules.Add( Module("mbed TLS") )
modules.Add( Module("micro-ecc") )
modules.Add( Module("mpdecimal") )
modules.Add( Module("rust_libsecp256k1") )
modules.Add( Module("secp256k1") )
modules.Add( Module("sjcl") )
modules.Add( Module("trezor-firmware") )
modules.Add( Module("wolfCrypt") )
modules.Add( Module("wolfCrypt-OpenSSL") )

operations = OperationTable()
operations.Add( Operation("BignumCalc") )
operations.Add( Operation("CMAC") )
operations.Add( Operation("DH_Derive") )
operations.Add( Operation("DH_GenerateKeyPair") )
operations.Add( Operation("Digest") )
operations.Add( Operation("ECC_GenerateKeyPair") )
operations.Add( Operation("ECC_PrivateToPublic") )
operations.Add( Operation("ECC_ValidatePubkey") )
operations.Add( Operation("ECDH_Derive") )
operations.Add( Operation("ECDSA_Sign") )
operations.Add( Operation("ECDSA_Verify") )
operations.Add( Operation("ECIES_Encrypt") )
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
ecc_curves.Add( ECC_Curve("brainpool160r1", "1332297598440044874827085038830181364212942568457") )
ecc_curves.Add( ECC_Curve("brainpool160t1", "1332297598440044874827085038830181364212942568457") )
ecc_curves.Add( ECC_Curve("brainpool192r1", "4781668983906166242955001894269038308119863659119834868929") )
ecc_curves.Add( ECC_Curve("brainpool192t1", "4781668983906166242955001894269038308119863659119834868929") )
ecc_curves.Add( ECC_Curve("brainpool224r1", "22721622932454352787552537995910923612567546342330757191396560966559") )
ecc_curves.Add( ECC_Curve("brainpool224t1", "22721622932454352787552537995910923612567546342330757191396560966559") )
ecc_curves.Add( ECC_Curve("brainpool256r1", "76884956397045344220809746629001649092737531784414529538755519063063536359079") )
ecc_curves.Add( ECC_Curve("brainpool256t1", "76884956397045344220809746629001649092737531784414529538755519063063536359079") )
ecc_curves.Add( ECC_Curve("brainpool320r1", "1763593322239166354161909842446019520889512772717686063760686124016784784845843468355685258203921") )
ecc_curves.Add( ECC_Curve("brainpool320t1", "1763593322239166354161909842446019520889512772717686063760686124016784784845843468355685258203921") )
ecc_curves.Add( ECC_Curve("brainpool384r1", "21659270770119316173069236842332604979796116387017648600075645274821611501358515537962695117368903252229601718723941") )
ecc_curves.Add( ECC_Curve("brainpool384t1", "21659270770119316173069236842332604979796116387017648600075645274821611501358515537962695117368903252229601718723941") )
ecc_curves.Add( ECC_Curve("brainpool512r1", "8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169") )
ecc_curves.Add( ECC_Curve("brainpool512t1", "8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169") )
ecc_curves.Add( ECC_Curve("ed25519") )
ecc_curves.Add( ECC_Curve("ed448") )
ecc_curves.Add( ECC_Curve("frp256v1") )
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
ecc_curves.Add( ECC_Curve("numsp256t1", "28948022309329048855892746252171976963230320855948034936185801359597441823917") )
ecc_curves.Add( ECC_Curve("numsp384t1", "9850501549098619803069760025035903451269934817616361666986603623638432032256865558780541454083219163250604218936869") )
ecc_curves.Add( ECC_Curve("numsp512t1", "3351951982485649274893506249551461531869841455148098344430890360930441007518346893020404367996870882777121262593078152830179243535023501253454245088133513") )
ecc_curves.Add( ECC_Curve("secp112r1", "4451685225093714776491891542548933") )
ecc_curves.Add( ECC_Curve("secp112r2", "1112921306273428674967732714786891") )
ecc_curves.Add( ECC_Curve("secp128r1", "340282366762482138443322565580356624661") )
ecc_curves.Add( ECC_Curve("secp128r2", "85070591690620534603955721926813660579") )
ecc_curves.Add( ECC_Curve("secp160k1", "1461501637330902918203686915170869725397159163571") )
ecc_curves.Add( ECC_Curve("secp160r1", "1461501637330902918203687197606826779884643492439") )
ecc_curves.Add( ECC_Curve("secp160r2", "1461501637330902918203685083571792140653176136043") )
ecc_curves.Add( ECC_Curve("secp192k1", "6277101735386680763835789423061264271957123915200845512077") )
ecc_curves.Add( ECC_Curve("secp192r1") )
ecc_curves.Add( ECC_Curve("secp224k1", "26959946667150639794667015087019640346510327083120074548994958668279") )
ecc_curves.Add( ECC_Curve("secp224r1", "26959946667150639794667015087019625940457807714424391721682722368061") )
ecc_curves.Add( ECC_Curve("secp256k1", "115792089237316195423570985008687907852837564279074904382605163141518161494337") )
ecc_curves.Add( ECC_Curve("secp256r1", "115792089210356248762697446949407573529996955224135760342422259061068512044369") )
ecc_curves.Add( ECC_Curve("secp384r1", "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643") )
ecc_curves.Add( ECC_Curve("secp521r1", "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449") )
ecc_curves.Add( ECC_Curve("sect113r1", "5192296858534827689835882578830703") )
ecc_curves.Add( ECC_Curve("sect113r2", "5192296858534827702972497909952403") )
ecc_curves.Add( ECC_Curve("sect131r1", "1361129467683753853893932755685365560653") )
ecc_curves.Add( ECC_Curve("sect131r2", "1361129467683753853879535043412812867983") )
ecc_curves.Add( ECC_Curve("sect163k1", "5846006549323611672814741753598448348329118574063") )
ecc_curves.Add( ECC_Curve("sect163r1", "5846006549323611672814738465098798981304420411291") )
ecc_curves.Add( ECC_Curve("sect163r2", "5846006549323611672814742442876390689256843201587") )
ecc_curves.Add( ECC_Curve("sect193r1", "6277101735386680763835789423269548053691575186051040197193") )
ecc_curves.Add( ECC_Curve("sect193r2", "6277101735386680763835789423314955362437298222279840143829") )
ecc_curves.Add( ECC_Curve("sect233k1", "3450873173395281893717377931138512760570940988862252126328087024741343") )
ecc_curves.Add( ECC_Curve("sect233r1", "6901746346790563787434755862277025555839812737345013555379383634485463") )
ecc_curves.Add( ECC_Curve("sect239k1", "220855883097298041197912187592864814948216561321709848887480219215362213") )
ecc_curves.Add( ECC_Curve("sect283k1", "3885337784451458141838923813647037813284811733793061324295874997529815829704422603873") )
ecc_curves.Add( ECC_Curve("sect283r1", "7770675568902916283677847627294075626569625924376904889109196526770044277787378692871") )
ecc_curves.Add( ECC_Curve("sect409k1", "330527984395124299475957654016385519914202341482140609642324395022880711289249191050673258457777458014096366590617731358671") )
ecc_curves.Add( ECC_Curve("sect409r1", "661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526771") )
ecc_curves.Add( ECC_Curve("sect571k1", "1932268761508629172347675945465993672149463664853217499328617625725759571144780212268133978522706711834706712800825351461273674974066617311929682421617092503555733685276673") )
ecc_curves.Add( ECC_Curve("sect571r1", "3864537523017258344695351890931987344298927329706434998657235251451519142289560424536143999389415773083133881121926944486246872462816813070234528288303332411393191105285703") )
ecc_curves.Add( ECC_Curve("sm2p256v1", "115792089210356248756420345214020892766061623724957744567843809356293439045923") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_a") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_b") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_c") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_256_d") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_a") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_b") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_c") )
ecc_curves.Add( ECC_Curve("tc26_gost_3410_12_512_test") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls1", "5192296858534827627896703833467507") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls10", "3450873173395281893717377931138512760570940988862252126328087024741343") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls11", "6901746346790563787434755862277025555839812737345013555379383634485463") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls12", "26959946667150639794667015087019625940457807714424391721682722368061") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls3", "5846006549323611672814741753598448348329118574063") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls4", "5192296858534827689835882578830703") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls5", "5846006549323611672814741626226392056573832638401") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls6", "4451685225093714776491891542548933") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls7", "1461501637330902918203685083571792140653176136043") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls8", "5192296858534827767273836114360297") )
ecc_curves.Add( ECC_Curve("wap_wsg_idm_ecid_wtls9", "1461501637330902918203687013445034429194588307251") )
ecc_curves.Add( ECC_Curve("x25519") )
ecc_curves.Add( ECC_Curve("x448") )
ecc_curves.Add( ECC_Curve("x962_c2pnb163v1", "5846006549323611672814741626226392056573832638401") )
ecc_curves.Add( ECC_Curve("x962_c2pnb163v2", "5846006549323611672814736867226446213508588572839") )
ecc_curves.Add( ECC_Curve("x962_c2pnb163v3", "5846006549323611672814737040186791886263374189321") )
ecc_curves.Add( ECC_Curve("x962_c2pnb176v1", "1464764815784035076424479112383122688505483765421") )
ecc_curves.Add( ECC_Curve("x962_c2pnb208w1", "6319530221984476934661765632900719012846431750114578083741") )
ecc_curves.Add( ECC_Curve("x962_c2pnb272w1", "116235492452543488393823301680748870034491124166583946466668991869818652235041") )
ecc_curves.Add( ECC_Curve("x962_c2pnb304w1", "500884825900595933307132795674658837818095809137913478977332553047879960661308247049501") )
ecc_curves.Add( ECC_Curve("x962_c2pnb368w1", "9194196556002283250851893699199753471497656173851998515361706855000304737080699826013007012009780734318951") )
ecc_curves.Add( ECC_Curve("x962_c2tnb191v1", "1569275433846670190958947355803350458831205595451630533029") )
ecc_curves.Add( ECC_Curve("x962_c2tnb191v2", "784637716923335095479473677925814481401065348266378101107") )
ecc_curves.Add( ECC_Curve("x962_c2tnb191v3", "523091811282223396986315785270930752647646535584668335779") )
ecc_curves.Add( ECC_Curve("x962_c2tnb239v1", "220855883097298041197912187592864814557886993776713230936715041207411783") )
ecc_curves.Add( ECC_Curve("x962_c2tnb239v2", "147237255398198694131941458395243209523006695456232690299263349237764653") )
ecc_curves.Add( ECC_Curve("x962_c2tnb239v3", "88342353238919216479164875037145925622548965147075144322778604225055999") )
ecc_curves.Add( ECC_Curve("x962_c2tnb359v1", "15450938044564692288746582873614059390629490453344209663962540632677447295745316740045672843724365195742523") )
ecc_curves.Add( ECC_Curve("x962_c2tnb431r1", "550132875817621995948098052409342004650086721304725510946523726312246334661592590780763978563125341997711919748453208343530129") )
ecc_curves.Add( ECC_Curve("x962_p192v1", "6277101735386680763835789423176059013767194773182842284081") )
ecc_curves.Add( ECC_Curve("x962_p192v2", "6277101735386680763835789423078825936192100537584385056049") )
ecc_curves.Add( ECC_Curve("x962_p192v3", "6277101735386680763835789423166314882687165660350679936019") )
ecc_curves.Add( ECC_Curve("x962_p239v1", "883423532389192164791648750360308884807550341691627752275345424702807307") )
ecc_curves.Add( ECC_Curve("x962_p239v2", "883423532389192164791648750360308886392687657546993855147765732451295331") )
ecc_curves.Add( ECC_Curve("x962_p239v3", "883423532389192164791648750360308884771190369765922550517967171058034001") )
ecc_curves.Add( ECC_Curve("x962_p256v1", "115792089210356248762697446949407573529996955224135760342422259061068512044369") )


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
calcops.Add( CalcOp("IsNeg(A)") )
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
