#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <jni.h>

namespace cryptofuzz {
namespace module {

namespace BouncyCastle_detail {
    JavaVM* jvm = nullptr;
    JNIEnv* env = nullptr;
    jclass jclass;
    jmethodID method_Digest;
    jmethodID method_ECC_Point_Add;
    jmethodID method_ECC_Point_Mul;

    static JNIEnv* create_vm(JavaVM ** jvm) {
        std::string option_string = std::string("-Djava.class.path=") + std::string(CLASS_PATH);

        JNIEnv* env;
        JavaVMOption options[1];
        JavaVMInitArgs vm_args;

        options[0].optionString = (char*)option_string.c_str();

        vm_args.version = JNI_VERSION_1_8;
        vm_args.nOptions = 1;
        vm_args.options = options;
        vm_args.ignoreUnrecognized = 0;

        CF_ASSERT(JNI_CreateJavaVM(jvm, (void**)&env, &vm_args) >= 0, "Cannot instantiate JVM");


        return env;
    }

    static void initialize(void) {
        env = create_vm(&jvm);

        CF_ASSERT(env != nullptr, "Cannot instantiate JVM");

        jclass = env->FindClass("CryptofuzzBouncyCastleHarness");

        CF_ASSERT(jclass != nullptr, "Cannot find class");

        method_Digest = env->GetStaticMethodID(jclass, "Digest", "(Ljava/lang/String;[B[I)[B");
        CF_ASSERT(method_Digest != nullptr, "Cannot find method");

        method_ECC_Point_Add = env->GetStaticMethodID(
                jclass,
                "ECC_Point_Add",
"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
);
        CF_ASSERT(method_ECC_Point_Add != nullptr, "Cannot find method");

        method_ECC_Point_Mul = env->GetStaticMethodID(
                jclass,
                "ECC_Point_Mul",
"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;"
);
        CF_ASSERT(method_ECC_Point_Mul != nullptr, "Cannot find method");


    }
}

BouncyCastle::BouncyCastle(void) :
    Module("BouncyCastle") {
    BouncyCastle_detail::initialize();
}

std::optional<component::Digest> BouncyCastle::OpDigest(operation::Digest& op) {
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
            hash = BouncyCastle_detail::env->NewStringUTF("MD2");
            break;
        case    CF_DIGEST("MD4"):
            hash = BouncyCastle_detail::env->NewStringUTF("MD4");
            break;
        case    CF_DIGEST("MD5"):
            hash = BouncyCastle_detail::env->NewStringUTF("MD5");
            break;
        case    CF_DIGEST("SHA1"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA-1");
            break;
        case    CF_DIGEST("SHA224"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA-224");
            break;
        case    CF_DIGEST("SHA256"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA-256");
            break;
        case    CF_DIGEST("SHA384"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA-384");
            break;
        case    CF_DIGEST("SHA512"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA-512");
            break;
        case    CF_DIGEST("SHA3-224"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA3-224");
            break;
        case    CF_DIGEST("SHA3-256"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA3-256");
            break;
        case    CF_DIGEST("SHA3-384"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA3-384");
            break;
        case    CF_DIGEST("SHA3-512"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHA3-512");
            break;
        case    CF_DIGEST("TIGER"):
            hash = BouncyCastle_detail::env->NewStringUTF("Tiger");
            break;
        case    CF_DIGEST("SM3"):
            hash = BouncyCastle_detail::env->NewStringUTF("SM3");
            break;
        case    CF_DIGEST("RIPEMD128"):
            hash = BouncyCastle_detail::env->NewStringUTF("RIPEMD128");
            break;
        case    CF_DIGEST("RIPEMD160"):
            hash = BouncyCastle_detail::env->NewStringUTF("RIPEMD160");
            break;
        case    CF_DIGEST("RIPEMD256"):
            hash = BouncyCastle_detail::env->NewStringUTF("RIPEMD256");
            break;
        case    CF_DIGEST("RIPEMD320"):
            hash = BouncyCastle_detail::env->NewStringUTF("RIPEMD320");
            break;
        case    CF_DIGEST("WHIRLPOOL"):
            hash = BouncyCastle_detail::env->NewStringUTF("Whirlpool");
            break;
        case    CF_DIGEST("KECCAK_224"):
            hash = BouncyCastle_detail::env->NewStringUTF("Keccak-224");
            break;
        case    CF_DIGEST("KECCAK_256"):
            hash = BouncyCastle_detail::env->NewStringUTF("Keccak-256");
            break;
        case    CF_DIGEST("KECCAK_384"):
            hash = BouncyCastle_detail::env->NewStringUTF("Keccak-384");
            break;
        case    CF_DIGEST("KECCAK_512"):
            hash = BouncyCastle_detail::env->NewStringUTF("Keccak-512");
            break;
        case    CF_DIGEST("BLAKE2B128"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2b-128");
            break;
        case    CF_DIGEST("BLAKE2B160"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2b-160");
            break;
        case    CF_DIGEST("BLAKE2B256"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2b-256");
            break;
        case    CF_DIGEST("BLAKE2B384"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2b-384");
            break;
        case    CF_DIGEST("BLAKE2B512"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2b-512");
            break;
        case    CF_DIGEST("BLAKE2S128"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2s-128");
            break;
        case    CF_DIGEST("BLAKE2S160"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2s-160");
            break;
        case    CF_DIGEST("BLAKE2S224"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2s-224");
            break;
        case    CF_DIGEST("BLAKE2S256"):
            hash = BouncyCastle_detail::env->NewStringUTF("BLAKE2s-256");
            break;
#if 0
        case    CF_DIGEST("SHAKE256"):
            hash = BouncyCastle_detail::env->NewStringUTF("SHAKE256");
            break;
#endif
        default:
            return ret;

    }
    CF_ASSERT(hash != nullptr, "Cannot create string argument");

    msg = BouncyCastle_detail::env->NewByteArray(op.cleartext.GetSize());
    CF_ASSERT(msg != nullptr, "Cannot create byte array argument");
    BouncyCastle_detail::env->SetByteArrayRegion(msg, 0, op.cleartext.GetSize(), (const jbyte*)op.cleartext.GetPtr());

    for (const auto& part : util::ToParts(ds, op.cleartext)) {
        parts.push_back(part.second);
    }
    chunks = BouncyCastle_detail::env->NewIntArray(parts.size());
    CF_ASSERT(chunks != nullptr, "Cannot create byte array argument");
    BouncyCastle_detail::env->SetIntArrayRegion(chunks, 0, parts.size(), parts.data());

    initialized = true;

    rv = static_cast<jbyteArray>(
            BouncyCastle_detail::env->CallStaticObjectMethod(
                BouncyCastle_detail::jclass,
                BouncyCastle_detail::method_Digest,
                hash, msg, chunks));

    CF_ASSERT(rv != nullptr, "Expected result");

    {
        const auto size = BouncyCastle_detail::env->GetArrayLength(rv);
        const auto data = BouncyCastle_detail::env->GetPrimitiveArrayCritical(rv, nullptr);

        ret = component::Digest((const uint8_t*)data, size);

        BouncyCastle_detail::env->ReleasePrimitiveArrayCritical(rv, data, 0);
    }

    if ( initialized ) {
        BouncyCastle_detail::env->DeleteLocalRef(msg);
        BouncyCastle_detail::env->DeleteLocalRef(hash);
        BouncyCastle_detail::env->DeleteLocalRef(rv);
    }

    return ret;
}

std::optional<component::ECC_Point> BouncyCastle::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    bool initialized = false;
    jstring curve, ax, ay, bx, by;
    jstring rv;
    std::string rv_str;

    curve = BouncyCastle_detail::env->NewStringUTF(
            repository::ECC_CurveToString(op.curveType.Get()).c_str()
    );
    CF_ASSERT(curve != nullptr, "Cannot create string argument");

    ax = BouncyCastle_detail::env->NewStringUTF(op.a.first.ToTrimmedString().c_str());
    CF_ASSERT(ax != nullptr, "Cannot create string argument");

    ay = BouncyCastle_detail::env->NewStringUTF(op.a.second.ToTrimmedString().c_str());
    CF_ASSERT(ay != nullptr, "Cannot create string argument");

    bx = BouncyCastle_detail::env->NewStringUTF(op.b.first.ToTrimmedString().c_str());
    CF_ASSERT(bx != nullptr, "Cannot create string argument");

    by = BouncyCastle_detail::env->NewStringUTF(op.b.second.ToTrimmedString().c_str());
    CF_ASSERT(by != nullptr, "Cannot create string argument");

    initialized = true;

    rv = static_cast<jstring>(
            BouncyCastle_detail::env->CallStaticObjectMethod(
                BouncyCastle_detail::jclass,
                BouncyCastle_detail::method_ECC_Point_Add,
                curve, ax, ay, bx, by));
    CF_CHECK_NE(rv, nullptr);

    {
        const auto s = BouncyCastle_detail::env->GetStringUTFChars(rv, 0);
        rv_str = std::string(s);
        BouncyCastle_detail::env->ReleaseStringUTFChars(rv, s);
    }

    {
        std::vector<std::string> coords;
        boost::split(coords, rv_str, boost::is_any_of(" "));

        CF_ASSERT(coords.size() == 2, "Unexpected return value");

        ret = component::ECC_Point{coords[0], coords[1]};
    }
end:
    if ( initialized ) {
        BouncyCastle_detail::env->DeleteLocalRef(curve);
        BouncyCastle_detail::env->DeleteLocalRef(ax);
        BouncyCastle_detail::env->DeleteLocalRef(ay);
        BouncyCastle_detail::env->DeleteLocalRef(bx);
        BouncyCastle_detail::env->DeleteLocalRef(by);
        BouncyCastle_detail::env->DeleteLocalRef(rv);
    }

    return ret;
}

std::optional<component::ECC_Point> BouncyCastle::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool initialized = false;
    jstring curve, x, y, scalar;
    jint multiplier = 0;
    jstring rv;
    std::string rv_str;

    curve = BouncyCastle_detail::env->NewStringUTF(
            repository::ECC_CurveToString(op.curveType.Get()).c_str()
    );
    CF_ASSERT(curve != nullptr, "Cannot create string argument");

    x = BouncyCastle_detail::env->NewStringUTF(op.a.first.ToTrimmedString().c_str());
    CF_ASSERT(x != nullptr, "Cannot create string argument");

    y = BouncyCastle_detail::env->NewStringUTF(op.a.second.ToTrimmedString().c_str());
    CF_ASSERT(y != nullptr, "Cannot create string argument");

    scalar = BouncyCastle_detail::env->NewStringUTF(op.b.ToTrimmedString().c_str());
    CF_ASSERT(scalar != nullptr, "Cannot create string argument");

    initialized = true;

    try {
        multiplier = ds.Get<uint8_t>() % 3;
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    rv = static_cast<jstring>(
            BouncyCastle_detail::env->CallStaticObjectMethod(
                BouncyCastle_detail::jclass,
                BouncyCastle_detail::method_ECC_Point_Mul,
                curve, x, y, scalar, multiplier));
    CF_CHECK_NE(rv, nullptr);

    {
        const auto s = BouncyCastle_detail::env->GetStringUTFChars(rv, 0);
        rv_str = std::string(s);
        BouncyCastle_detail::env->ReleaseStringUTFChars(rv, s);
    }

    {
        std::vector<std::string> coords;
        boost::split(coords, rv_str, boost::is_any_of(" "));

        CF_ASSERT(coords.size() == 2, "Unexpected return value");

        ret = component::ECC_Point{coords[0], coords[1]};
    }

end:
    if ( initialized ) {
        BouncyCastle_detail::env->DeleteLocalRef(curve);
        BouncyCastle_detail::env->DeleteLocalRef(x);
        BouncyCastle_detail::env->DeleteLocalRef(y);
        BouncyCastle_detail::env->DeleteLocalRef(scalar);
        BouncyCastle_detail::env->DeleteLocalRef(rv);
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
