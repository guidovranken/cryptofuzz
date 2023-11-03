#if defined(JAVA_WITH_ECDSA)
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#endif

#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <jni.h>
#if defined(JAVA_OSS_FUZZ)
#include "CryptofuzzJavaHarness.class.h"
#include <libgen.h>
#endif

namespace cryptofuzz {
namespace module {

namespace Java_detail {

    JavaVM* jvm = nullptr;
    JNIEnv* env = nullptr;
    jclass jclazz;
    jmethodID method_Digest;
    jmethodID method_HMAC;
    jmethodID method_ECDSA_Verify;
    jmethodID method_PBKDF2;
    jmethodID method_BignumCalc;

    static JNIEnv* create_vm(JavaVM ** jvm) {
#if defined(JAVA_OSS_FUZZ)
        char exepath[PATH_MAX];
        memset(exepath, 0, sizeof(exepath));
        CF_ASSERT(
                readlink(
                    "/proc/self/exe",
                    exepath,
                    sizeof(exepath)) != -1, "Cannot resolve executable path");
        const char* classpath = dirname(exepath);
        std::string option_string = "-Djava.class.path=" + std::string(classpath);
#else
        std::string option_string = "-Djava.class.path=" + std::string(CLASS_PATH);
#endif

        JNIEnv* env;
        JavaVMOption options;
        JavaVMInitArgs vm_args;

        options.optionString = (char*)option_string.c_str();

        vm_args.version = JNI_VERSION_1_6;
        vm_args.nOptions = 1;
        vm_args.options = &options;
        vm_args.ignoreUnrecognized = 0;

        CF_ASSERT(JNI_CreateJavaVM(jvm, (void**)&env, &vm_args) >= 0, "Cannot instantiate JVM");

        return env;
    }

    static void initialize(void) {
        env = create_vm(&jvm);

        CF_ASSERT(env != nullptr, "Cannot instantiate JVM");

#if defined(JAVA_OSS_FUZZ)
        jclazz = env->DefineClass(
                "CryptofuzzJavaHarness",
                nullptr,
                (const jbyte*)CryptofuzzJavaHarness_class,
                CryptofuzzJavaHarness_class_len);
#else
        /* This fails:
         * https://github.com/google/oss-fuzz/issues/9255
         */
        jclazz = env->FindClass("CryptofuzzJavaHarness");
#endif
        CF_ASSERT(jclazz != nullptr, "Cannot find class");

        method_Digest = env->GetStaticMethodID(jclazz, "Digest", "(Ljava/lang/String;[B[I)[B");
        CF_ASSERT(method_Digest != nullptr, "Cannot find method");

        method_HMAC = env->GetStaticMethodID(jclazz, "HMAC", "(Ljava/lang/String;[B[B[I)[B");
        CF_ASSERT(method_HMAC != nullptr, "Cannot find method");

        method_ECDSA_Verify = env->GetStaticMethodID(jclazz, "ECDSA_Verify", "(Ljava/lang/String;[B[B[B[I)Z");
        CF_ASSERT(method_ECDSA_Verify != nullptr, "Cannot find method");

        //method_PBKDF2 = env->GetStaticMethodID(jclazz, "PBKDF2", "(Ljava/lang/String;[C[BII)[B");
        method_PBKDF2 = env->GetStaticMethodID(jclazz, "PBKDF2", "(Ljava/lang/String;[B[BII)[B");
        CF_ASSERT(method_PBKDF2 != nullptr, "Cannot find method");

        method_BignumCalc = env->GetStaticMethodID(jclazz, "BignumCalc", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;");
        CF_ASSERT(method_BignumCalc != nullptr, "Cannot find method");

    }

#if defined(JAVA_WITH_ECDSA)
    static std::optional<std::vector<uint8_t>> PubkeyToX509(const component::BignumPair& pub, const int nid)
    {
        std::optional<std::vector<uint8_t>> ret = std::nullopt;

        EC_GROUP* group = nullptr;
        EC_POINT* point = nullptr;
        EC_KEY* key = nullptr;
        BIGNUM *pub_x = nullptr, *pub_y = nullptr;
        uint8_t* encoded = nullptr;

        CF_CHECK_NE(key = EC_KEY_new(), nullptr);
        CF_CHECK_NE(group = EC_GROUP_new_by_curve_name(nid), nullptr);
        CF_CHECK_EQ(EC_KEY_set_group(key, group), 1);

        CF_CHECK_NE(point = EC_POINT_new(group), nullptr);
        CF_CHECK_NE(BN_dec2bn(&pub_x, pub.first.ToTrimmedString().c_str()), 0);
        CF_CHECK_NE(BN_dec2bn(&pub_y, pub.second.ToTrimmedString().c_str()), 0);
        CF_CHECK_NE(EC_POINT_set_affine_coordinates_GFp(group, point, pub_x, pub_y, nullptr), 0);
        CF_CHECK_EQ(EC_KEY_set_public_key(key, point), 1);

        {
            const auto size = i2d_EC_PUBKEY(key, &encoded);
            CF_CHECK_GT(size, 0);

            ret = std::vector<uint8_t>(encoded, encoded + size);
        }

end:
        EC_GROUP_free(group);
        EC_POINT_free(point);
        EC_KEY_free(key);
        BN_free(pub_x);
        BN_free(pub_y);
        OPENSSL_free(encoded);

        return ret;
    }

    static std::optional<std::vector<uint8_t>> SignatureToX509(const component::BignumPair& sig)
    {
        std::optional<std::vector<uint8_t>> ret = std::nullopt;

        ECDSA_SIG* signature = nullptr;
        BIGNUM *sig_r = nullptr, *sig_s = nullptr;
        uint8_t* encoded = nullptr;

        CF_CHECK_NE(signature = ECDSA_SIG_new(), nullptr);
        CF_CHECK_NE(BN_dec2bn(&sig_r, sig.first.ToTrimmedString().c_str()), 0);
        CF_CHECK_NE(BN_dec2bn(&sig_s, sig.second.ToTrimmedString().c_str()), 0);
        CF_CHECK_EQ(ECDSA_SIG_set0(signature, sig_r, sig_s), 1);
        sig_r = nullptr;
        sig_s = nullptr;

        {
            const auto size = i2d_ECDSA_SIG(signature, &encoded);
            CF_CHECK_GT(size, 0);

            ret = std::vector<uint8_t>(encoded, encoded + size);
        }

end:
        ECDSA_SIG_free(signature);
        BN_free(sig_r);
        BN_free(sig_s);
        OPENSSL_free(encoded);

        return ret;
    }
#endif
}

Java::Java(void) :
    Module("Java") {
    Java_detail::initialize();
}

std::optional<component::Digest> Java::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool initialized = false;
    std::vector<int> parts;
    jstring hash;
    jbyteArray msg;
    jintArray chunks;
    jbyteArray rv;

    switch ( op.digestType.Get() ) {
        case    CF_DIGEST("MD2"):
            hash = Java_detail::env->NewStringUTF("MD2");
            break;
        case    CF_DIGEST("MD5"):
            hash = Java_detail::env->NewStringUTF("MD5");
            break;
        case    CF_DIGEST("SHA1"):
            hash = Java_detail::env->NewStringUTF("SHA-1");
            break;
        case    CF_DIGEST("SHA224"):
            hash = Java_detail::env->NewStringUTF("SHA-224");
            break;
        case    CF_DIGEST("SHA256"):
            hash = Java_detail::env->NewStringUTF("SHA-256");
            break;
        case    CF_DIGEST("SHA384"):
            hash = Java_detail::env->NewStringUTF("SHA-384");
            break;
        case    CF_DIGEST("SHA512"):
            hash = Java_detail::env->NewStringUTF("SHA-512");
            break;
        case    CF_DIGEST("SHA3-224"):
            hash = Java_detail::env->NewStringUTF("SHA3-224");
            break;
        case    CF_DIGEST("SHA3-256"):
            hash = Java_detail::env->NewStringUTF("SHA3-256");
            break;
        case    CF_DIGEST("SHA3-384"):
            hash = Java_detail::env->NewStringUTF("SHA3-384");
            break;
        case    CF_DIGEST("SHA3-512"):
            hash = Java_detail::env->NewStringUTF("SHA3-512");
            break;
        default:
            return ret;

    }
    CF_ASSERT(hash != nullptr, "Cannot create string argument");

    msg = Java_detail::env->NewByteArray(op.cleartext.GetSize());
    CF_ASSERT(msg != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetByteArrayRegion(msg, 0, op.cleartext.GetSize(), (const jbyte*)op.cleartext.GetPtr());

    for (const auto& part : util::ToParts(ds, op.cleartext)) {
        parts.push_back(part.second);
    }
    chunks = Java_detail::env->NewIntArray(parts.size());
    CF_ASSERT(chunks != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetIntArrayRegion(chunks, 0, parts.size(), parts.data());

    initialized = true;

    rv = static_cast<jbyteArray>(
            Java_detail::env->CallStaticObjectMethod(
                Java_detail::jclazz,
                Java_detail::method_Digest,
                hash, msg, chunks));

    CF_ASSERT(rv != nullptr, "Expected result");

    {
        const auto size = Java_detail::env->GetArrayLength(rv);
        const auto data = Java_detail::env->GetPrimitiveArrayCritical(rv, nullptr);

        ret = component::Digest((const uint8_t*)data, size);

        Java_detail::env->ReleasePrimitiveArrayCritical(rv, data, 0);
    }

    if ( initialized ) {
        Java_detail::env->DeleteLocalRef(msg);
        Java_detail::env->DeleteLocalRef(hash);
        Java_detail::env->DeleteLocalRef(rv);
    }

    return ret;
}

std::optional<component::MAC> Java::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool initialized = false;
    std::vector<int> parts;
    jstring hash;
    jbyteArray msg;
    jbyteArray key;
    jintArray chunks;
    jbyteArray rv;

    switch ( op.digestType.Get() ) {
        case    CF_DIGEST("MD5"):
            hash = Java_detail::env->NewStringUTF("MD5");
            break;
        case    CF_DIGEST("SHA1"):
            hash = Java_detail::env->NewStringUTF("SHA1");
            break;
        case    CF_DIGEST("SHA224"):
            hash = Java_detail::env->NewStringUTF("SHA224");
            break;
        case    CF_DIGEST("SHA256"):
            hash = Java_detail::env->NewStringUTF("SHA256");
            break;
        case    CF_DIGEST("SHA384"):
            hash = Java_detail::env->NewStringUTF("SHA384");
            break;
        case    CF_DIGEST("SHA512"):
            hash = Java_detail::env->NewStringUTF("SHA512");
            break;
        case    CF_DIGEST("SHA3-224"):
            hash = Java_detail::env->NewStringUTF("SHA3-224");
            break;
        case    CF_DIGEST("SHA3-256"):
            hash = Java_detail::env->NewStringUTF("SHA3-256");
            break;
        case    CF_DIGEST("SHA3-384"):
            hash = Java_detail::env->NewStringUTF("SHA3-384");
            break;
        case    CF_DIGEST("SHA3-512"):
            hash = Java_detail::env->NewStringUTF("SHA3-512");
            break;
        default:
            return ret;

    }
    CF_ASSERT(hash != nullptr, "Cannot create string argument");

    key = Java_detail::env->NewByteArray(op.cipher.key.GetSize());
    CF_ASSERT(key != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetByteArrayRegion(key, 0, op.cipher.key.GetSize(), (const jbyte*)op.cipher.key.GetPtr());

    msg = Java_detail::env->NewByteArray(op.cleartext.GetSize());
    CF_ASSERT(msg != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetByteArrayRegion(msg, 0, op.cleartext.GetSize(), (const jbyte*)op.cleartext.GetPtr());

    for (const auto& part : util::ToParts(ds, op.cleartext)) {
        parts.push_back(part.second);
    }
    chunks = Java_detail::env->NewIntArray(parts.size());
    CF_ASSERT(chunks != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetIntArrayRegion(chunks, 0, parts.size(), parts.data());

    initialized = true;

    rv = static_cast<jbyteArray>(
            Java_detail::env->CallStaticObjectMethod(
                Java_detail::jclazz,
                Java_detail::method_HMAC,
                hash, key, msg, chunks));

    CF_CHECK_NE(rv, nullptr);

    {
        const auto size = Java_detail::env->GetArrayLength(rv);
        const auto data = Java_detail::env->GetPrimitiveArrayCritical(rv, nullptr);

        if ( size > 0 ) {
            ret = component::MAC((const uint8_t*)data, size);
        }

        Java_detail::env->ReleasePrimitiveArrayCritical(rv, data, 0);
    }

end:
    if ( initialized ) {
        Java_detail::env->DeleteLocalRef(msg);
        Java_detail::env->DeleteLocalRef(hash);
        Java_detail::env->DeleteLocalRef(rv);
    }

    return ret;
}

#if defined(JAVA_WITH_ECDSA)
std::optional<bool> Java::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<bool> ret = std::nullopt;

    std::vector<int> parts;
    jstring hash = nullptr;
    jbyteArray pub = nullptr;
    jbyteArray sig = nullptr;
    jbyteArray msg = nullptr;
    jintArray chunks = nullptr;
    int nid = -1;

    std::optional<std::vector<uint8_t>> pub_encoded = std::nullopt;
    std::optional<std::vector<uint8_t>> sig_encoded = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("NULL"):
            hash = Java_detail::env->NewStringUTF("NONE");
            break;
        case CF_DIGEST("SHA1"):
            hash = Java_detail::env->NewStringUTF("SHA1");
            break;
        case CF_DIGEST("SHA256"):
            hash = Java_detail::env->NewStringUTF("SHA256");
            break;
        default:
            goto end;
    }

    switch ( op.curveType.Get() ) {
        case CF_ECC_CURVE("secp192r1"):
            nid = NID_X9_62_prime192v1;
            break;
        case CF_ECC_CURVE("secp256r1"):
            if ( op.cleartext.GetSize() != 32 ) {
                goto end;
            }
            nid = NID_X9_62_prime256v1;
            break;
        case CF_ECC_CURVE("secp384r1"):
            nid = NID_secp384r1;
            break;
        case CF_ECC_CURVE("secp256k1"):
            nid = NID_secp256k1;
            break;
        default:
            goto end;
    }

    {
        pub_encoded = Java_detail::PubkeyToX509(op.signature.pub, nid);
        CF_CHECK_NE(pub_encoded, std::nullopt);

        pub = Java_detail::env->NewByteArray(pub_encoded->size());
        CF_ASSERT(pub != nullptr, "Cannot create byte array argument");
        Java_detail::env->SetByteArrayRegion(pub, 0, pub_encoded->size(), (const jbyte*)pub_encoded->data());
    }

    {
        sig_encoded = Java_detail::SignatureToX509(op.signature.signature);
        CF_CHECK_NE(sig_encoded, std::nullopt);

        sig = Java_detail::env->NewByteArray(sig_encoded->size());
        CF_ASSERT(sig != nullptr, "Cannot create byte array argument");
        Java_detail::env->SetByteArrayRegion(sig, 0, sig_encoded->size(), (const jbyte*)sig_encoded->data());
    }

    for (const auto& part : util::ToParts(ds, op.cleartext)) {
        parts.push_back(part.second);
    }
    chunks = Java_detail::env->NewIntArray(parts.size());
    CF_ASSERT(chunks != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetIntArrayRegion(chunks, 0, parts.size(), parts.data());

    msg = Java_detail::env->NewByteArray(op.cleartext.GetSize());
    CF_ASSERT(msg != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetByteArrayRegion(msg, 0, op.cleartext.GetSize(), (const jbyte*)op.cleartext.GetPtr());

    {
        const jboolean rv = Java_detail::env->CallStaticBooleanMethod(
                Java_detail::jclazz,
                Java_detail::method_ECDSA_Verify,
                hash, pub, sig, msg, chunks);

        ret = rv;
    }

end:
    Java_detail::env->DeleteLocalRef(hash);
    Java_detail::env->DeleteLocalRef(pub);
    Java_detail::env->DeleteLocalRef(sig);
    Java_detail::env->DeleteLocalRef(msg);
    return ret;
}
#endif

std::optional<component::Key> Java::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    if ( op.iterations == 0 ) {
        return ret;
    }
    if ( op.keySize == 0 ) {
        return ret;
    }
    if ( op.salt.GetSize() == 0 ) {
        return ret;
    }
    for (size_t i = 0; i < op.password.GetSize(); i++) {
        if ( op.password.GetPtr()[i] > 127 ) {
            return ret;
        }
    }

    bool initialized = false;
    jstring hash;
    jbyteArray salt;
    jbyteArray password;
    jint iterations;
    jint keysize;
    jbyteArray rv;

    switch ( op.digestType.Get() ) {
        case    CF_DIGEST("SHA1"):
            hash = Java_detail::env->NewStringUTF("PBKDF2WithHmacSHA1");
            break;
        case    CF_DIGEST("SHA224"):
            hash = Java_detail::env->NewStringUTF("PBKDF2WithHmacSHA224");
            break;
        case    CF_DIGEST("SHA256"):
            hash = Java_detail::env->NewStringUTF("PBKDF2WithHmacSHA256");
            break;
        case    CF_DIGEST("SHA384"):
            hash = Java_detail::env->NewStringUTF("PBKDF2WithHmacSHA384");
            break;
        case    CF_DIGEST("SHA512"):
            hash = Java_detail::env->NewStringUTF("PBKDF2WithHmacSHA512");
            break;
        default:
            return ret;

    }
    CF_ASSERT(hash != nullptr, "Cannot create string argument");

    salt = Java_detail::env->NewByteArray(op.salt.GetSize());
    CF_ASSERT(salt != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetByteArrayRegion(salt, 0, op.salt.GetSize(), (const jbyte*)op.salt.GetPtr());

    password = Java_detail::env->NewByteArray(op.password.GetSize());
    CF_ASSERT(password != nullptr, "Cannot create byte array argument");
    Java_detail::env->SetByteArrayRegion(password, 0, op.password.GetSize(), (const jbyte*)op.password.GetPtr());

    iterations = op.iterations;
    keysize = op.keySize;

    initialized = true;
    rv = static_cast<jbyteArray>(
            Java_detail::env->CallStaticObjectMethod(
                Java_detail::jclazz,
                Java_detail::method_PBKDF2,
                hash, password, salt, iterations, keysize * 8));

    CF_ASSERT(rv != nullptr, "Expected result");

    {
        const auto size = Java_detail::env->GetArrayLength(rv);
        const auto data = Java_detail::env->GetPrimitiveArrayCritical(rv, nullptr);

        ret = component::Key((const uint8_t*)data, size);

        Java_detail::env->ReleasePrimitiveArrayCritical(rv, data, 0);
    }

    if ( initialized ) {
        Java_detail::env->DeleteLocalRef(hash);
        Java_detail::env->DeleteLocalRef(salt);
        Java_detail::env->DeleteLocalRef(password);
        Java_detail::env->DeleteLocalRef(rv);
    }

    return ret;
}

std::optional<component::Bignum> Java::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool initialized = false;
    jstring bn1, bn2, bn3;
    jint calcop;
    jstring rv;
    std::string rv_str;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            calcop = 0;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            calcop = 1;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            calcop = 2;
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_FALSE(op.bn0.IsNegative());
            CF_CHECK_FALSE(op.bn1.IsNegative());
            calcop = 3;
            break;
        case    CF_CALCOP("GCD(A,B)"):
            calcop = 4;
            break;
        case    CF_CALCOP("And(A,B)"):
            calcop = 5;
            break;
        case    CF_CALCOP("Or(A,B)"):
            calcop = 6;
            break;
        case    CF_CALCOP("Xor(A,B)"):
            calcop = 7;
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            calcop = 8;
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            calcop = 9;
            break;
        case    CF_CALCOP("Abs(A)"):
            calcop = 10;
            break;
        case    CF_CALCOP("Neg(A)"):
            calcop = 11;
            break;
        case    CF_CALCOP("Mod(A,B)"):
            calcop = 12;
            break;
        case    CF_CALCOP("Exp(A,B)"):
            calcop = 13;
            break;
        case    CF_CALCOP("Min(A,B)"):
            calcop = 14;
            break;
        case    CF_CALCOP("Max(A,B)"):
            calcop = 15;
            break;
        case    CF_CALCOP("Sqrt(A)"):
            calcop = 16;
            break;
        case    CF_CALCOP("LShift1(A)"):
            calcop = 17;
            break;
        case    CF_CALCOP("RShift(A,B)"):
            CF_CHECK_FALSE(op.bn1.IsNegative());
            calcop = 18;
            break;
        case    CF_CALCOP("Bit(A,B)"):
            calcop = 19;
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            CF_CHECK_FALSE(op.bn0.IsNegative());
            calcop = 20;
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            calcop = 21;
            break;
        case    CF_CALCOP("NumBits(A)"):
            calcop = 22;
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            calcop = 23;
            break;
        case    CF_CALCOP("Sqr(A)"):
            calcop = 24;
            break;
        default:
            goto end;
    }

    bn1 = Java_detail::env->NewStringUTF(op.bn0.ToString(ds).c_str());
    CF_ASSERT(bn1 != nullptr, "Cannot create string argument");

    bn2 = Java_detail::env->NewStringUTF(op.bn1.ToString(ds).c_str());
    CF_ASSERT(bn2 != nullptr, "Cannot create string argument");

    bn3 = Java_detail::env->NewStringUTF(op.bn2.ToString(ds).c_str());
    CF_ASSERT(bn3 != nullptr, "Cannot create string argument");

    initialized = true;

    rv = static_cast<jstring>(
            Java_detail::env->CallStaticObjectMethod(
                Java_detail::jclazz,
                Java_detail::method_BignumCalc,
                bn1, bn2, bn3, calcop));

    if ( rv == nullptr ) {
        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("ExpMod(A,B,C)"):
                {
                    bool abortOk = false;

                    if ( op.bn2.IsZero() || op.bn2.IsNegative() ) {
                        abortOk = true;
                    }

                    CF_ASSERT(abortOk == true, "ExpMod unexpectedly failed")
                }
                break;
            case    CF_CALCOP("Div(A,B)"):
                {
                    bool abortOk = false;

                    if ( op.bn1.IsZero() ) {
                        abortOk = true;
                    }

                    CF_ASSERT(abortOk == true, "Div unexpectedly failed")
                }
                break;
            case    CF_CALCOP("Mod(A,B)"):
                {
                    bool abortOk = false;

                    if ( op.bn1.IsZero() ) {
                        abortOk = true;
                    }

                    CF_ASSERT(abortOk == true, "Mod unexpectedly failed")
                }
                break;
            case    CF_CALCOP("Exp(A,B)"):
                {
                    bool abortOk = false;

                    if ( op.bn1.IsNegative() ) {
                        abortOk = true;
                    }

                    CF_ASSERT(abortOk == true, "Exp unexpectedly failed")
                }
                break;
            case    CF_CALCOP("RShift(A,B)"):
            case    CF_CALCOP("Bit(A,B)"):
            case    CF_CALCOP("ClearBit(A,B)"):
            case    CF_CALCOP("SetBit(A,B)"):
                /* TODO can fail if B does not fit in int */
                break;
            default:
                CF_ASSERT(0, "Operation unexpectedly failed")
                break;
        }
    }

    CF_CHECK_NE(rv, nullptr);

    {
        const auto s = Java_detail::env->GetStringUTFChars(rv, 0);
        rv_str = std::string(s);
        Java_detail::env->ReleaseStringUTFChars(rv, s);
    }

    CF_CHECK_NE(rv_str, "none");

    ret = rv_str;

end:
    if ( initialized ) {
        Java_detail::env->DeleteLocalRef(bn1);
        Java_detail::env->DeleteLocalRef(bn2);
        Java_detail::env->DeleteLocalRef(bn3);
        Java_detail::env->DeleteLocalRef(rv);
    }
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
