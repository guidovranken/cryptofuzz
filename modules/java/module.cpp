#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <jni.h>

namespace cryptofuzz {
namespace module {

namespace Java_detail {

    JavaVM* jvm = nullptr;
    JNIEnv* env = nullptr;
    jclass jclass;
    jmethodID method;

    static JNIEnv* create_vm(JavaVM ** jvm) {
        //char* option_string = "-Djava.class.path=/mnt/2tb/cf-java/cryptofuzz/modules/java/";
        char* option_string = "-Djava.class.path=" CLASS_PATH;
        JNIEnv* env;
        JavaVMOption options;
        JavaVMInitArgs vm_args;

        options.optionString = option_string;

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

        jclass = env->FindClass("CryptofuzzJavaHarness");
        CF_ASSERT(jclass != nullptr, "Cannot find class");

        method = env->GetStaticMethodID(jclass, "BignumCalc", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;");
        CF_ASSERT(method != nullptr, "Cannot find method");
    }
}

Java::Java(void) :
    Module("Java") {
    Java_detail::initialize();
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
                Java_detail::jclass,
                Java_detail::method,
                bn1, bn2, bn3, calcop));

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
    }
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
