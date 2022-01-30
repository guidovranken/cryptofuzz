#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include <libgen.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

namespace cryptofuzz {
namespace module {

namespace py_ecc_detail {
    void* OpBLS_PrivateToPublic = nullptr;
    void* OpBLS_IsG1OnCurve = nullptr;
    void* OpBLS_IsG2OnCurve = nullptr;
    void* OpBLS_HashToG2 = nullptr;
    void* OpBLS_MapToG2 = nullptr;
    void* OpBLS_Verify = nullptr;
    void* OpBLS_Sign = nullptr;
    void* OpBignumCalc_InvMod = nullptr;
    void* OpMisc_Fq2_Sqrt = nullptr;
    void* OpMisc_Iso_Map_G2 = nullptr;
    void* OpMisc_Multiply = nullptr;
    void* OpBLS_Decompress_G1 = nullptr;
    void* OpBLS_Compress_G1 = nullptr;
    void* OpBLS_Decompress_G2 = nullptr;
    void* OpBLS_Compress_G2 = nullptr;
    void* OpBLS_G1_Add = nullptr;
    void* OpBLS_G1_Mul = nullptr;
    void* OpBLS_G1_IsEq = nullptr;
    void* OpBLS_G1_Neg = nullptr;
    void* OpBLS_G2_Add = nullptr;
    void* OpBLS_G2_Mul = nullptr;
    void* OpBLS_G2_IsEq = nullptr;
    void* OpBLS_G2_Neg = nullptr;
}

static void* LoadPythonFunction(PyObject* pModule, const std::string fn) {
    void* pFunc = PyObject_GetAttrString(pModule, fn.c_str());

    CF_ASSERT(pFunc != nullptr, "Function not defined");
    CF_ASSERT(PyCallable_Check(static_cast<PyObject*>(pFunc)), "Function not callable");

    return pFunc;
}

static std::optional<std::string> RunPythonFunction(void* pFunc, const std::string arg) {
    std::optional<std::string> ret = std::nullopt;

    PyObject* pValue, *pArgs;

    pArgs = PyTuple_New(1);
    pValue = PyBytes_FromStringAndSize(arg.c_str(), arg.size());

    PyTuple_SetItem(pArgs, 0, pValue);
    pValue = PyObject_CallObject(static_cast<PyObject*>(pFunc), pArgs);

    if ( pValue == nullptr ) {
        /* Abort on unhandled exception */
        PyErr_PrintEx(1);
        abort();
    }

    if ( PyBytes_Check(pValue) ) {
        /* Retrieve output */

        uint8_t* output;
        Py_ssize_t outputSize;
        if ( PyBytes_AsStringAndSize(pValue, (char**)&output, &outputSize) != -1) {
            ret = std::string(output, output + outputSize);
        } else {
            /* TODO this should not happen */
            abort();
        }

    }

    Py_DECREF(pValue);
    Py_DECREF(pArgs);

    return ret;
}

static void ConfigurePython(void) {
    //const std::string argv0 = (*argv)[0];

    std::vector<uint8_t> program;

    {
        const std::string cpythonInstallPath = CRYPTOFUZZ_CPYTHON_PATH;
        CF_ASSERT(setenv("PYTHONHOME", cpythonInstallPath.c_str(), 1) == 0, "Cannot set PYTHONHOME");
    }

    const std::string scriptPath = PY_ECC_HARNESS_PATH;

    {

        FILE* fp = fopen(scriptPath.c_str(), "rb");
        CF_ASSERT(fp != nullptr, "Cannot open script");

        fseek (fp, 0, SEEK_END);
        long length = ftell(fp);
        CF_ASSERT(length >= 1, "Cannot determine script file size");

        fseek (fp, 0, SEEK_SET);
        program.resize(length);
        CF_ASSERT(fread(program.data(), 1, length, fp) == static_cast<size_t>(length), "Cannot read script");
        fclose(fp);
    }

    std::string code = std::string(program.data(), program.data() + program.size());

#if 0
    {
        wchar_t *program = Py_DecodeLocale(argv0.c_str(), nullptr);
        Py_SetProgramName(program);
        PyMem_RawFree(program);
    }
#endif

    Py_Initialize();

    {
        std::string setArgv0;

        setArgv0 += "import sys";
        setArgv0 += "\n";
        setArgv0 += "sys.argv[0] = '" + scriptPath + "'\n";

        CF_ASSERT(PyRun_SimpleString(setArgv0.c_str()) == 0, "Cannot set argv[0]");
    }

    {
        std::string setPYTHONPATH;

        setPYTHONPATH += "import sys";
        setPYTHONPATH += "\n";
        setPYTHONPATH += "sys.path.append('" CRYPTOFUZZ_CPYTHON_VENV_PATH "lib/python3.8/site-packages/" "')\n";
        setPYTHONPATH += "\n";

        CF_ASSERT(PyRun_SimpleString(setPYTHONPATH.c_str()) == 0, "Cannot set PYTHONPATH");
    }

    PyObject *pValue, *pModule, *pLocal;

    pModule = PyModule_New("fuzzermod");
    PyModule_AddStringConstant(pModule, "__file__", "");
    pLocal = PyModule_GetDict(pModule);
    pValue = PyRun_String(code.c_str(), Py_file_input, pLocal, pLocal);

            PyErr_PrintEx(1);
    CF_ASSERT(pValue != nullptr, "Cannot create Python function from string");

    Py_DECREF(pValue);

    py_ecc_detail::OpBLS_PrivateToPublic = LoadPythonFunction(pModule, "OpBLS_PrivateToPublic");
    py_ecc_detail::OpBLS_IsG1OnCurve = LoadPythonFunction(pModule, "OpBLS_IsG1OnCurve");
    py_ecc_detail::OpBLS_IsG2OnCurve = LoadPythonFunction(pModule, "OpBLS_IsG2OnCurve");
    py_ecc_detail::OpBLS_HashToG2 = LoadPythonFunction(pModule, "OpBLS_HashToG2");
    py_ecc_detail::OpBLS_MapToG2 = LoadPythonFunction(pModule, "OpBLS_MapToG2");
    py_ecc_detail::OpBLS_Verify = LoadPythonFunction(pModule, "OpBLS_Verify");
    py_ecc_detail::OpBLS_Sign = LoadPythonFunction(pModule, "OpBLS_Sign");
    py_ecc_detail::OpBignumCalc_InvMod = LoadPythonFunction(pModule, "OpBignumCalc_InvMod");
    py_ecc_detail::OpMisc_Fq2_Sqrt = LoadPythonFunction(pModule, "OpMisc_Fq2_Sqrt");
    py_ecc_detail::OpMisc_Iso_Map_G2 = LoadPythonFunction(pModule, "OpMisc_Iso_Map_G2");
    py_ecc_detail::OpMisc_Multiply = LoadPythonFunction(pModule, "OpMisc_Multiply");
    py_ecc_detail::OpBLS_Decompress_G1 = LoadPythonFunction(pModule, "OpBLS_Decompress_G1");
    py_ecc_detail::OpBLS_Compress_G1 = LoadPythonFunction(pModule, "OpBLS_Compress_G1");
    py_ecc_detail::OpBLS_Decompress_G2 = LoadPythonFunction(pModule, "OpBLS_Decompress_G2");
    py_ecc_detail::OpBLS_Compress_G2 = LoadPythonFunction(pModule, "OpBLS_Compress_G2");
    py_ecc_detail::OpBLS_G1_Add = LoadPythonFunction(pModule, "OpBLS_G1_Add");
    py_ecc_detail::OpBLS_G1_Neg = LoadPythonFunction(pModule, "OpBLS_G1_Neg");
    py_ecc_detail::OpBLS_G1_Mul = LoadPythonFunction(pModule, "OpBLS_G1_Mul");
    py_ecc_detail::OpBLS_G1_IsEq = LoadPythonFunction(pModule, "OpBLS_G1_IsEq");
    py_ecc_detail::OpBLS_G2_Add = LoadPythonFunction(pModule, "OpBLS_G2_Add");
    py_ecc_detail::OpBLS_G2_Neg = LoadPythonFunction(pModule, "OpBLS_G2_Neg");
    py_ecc_detail::OpBLS_G2_Mul = LoadPythonFunction(pModule, "OpBLS_G2_Mul");
    py_ecc_detail::OpBLS_G2_IsEq = LoadPythonFunction(pModule, "OpBLS_G2_IsEq");
}

py_ecc::py_ecc(void) :
    Module("py_ecc") {
        ConfigurePython();
    }

std::optional<component::BLS_PublicKey> py_ecc::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_PrivateToPublic, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::BLS_PublicKey(nlohmann::json::parse(*ret));
}

std::optional<bool> py_ecc::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_IsG1OnCurve, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return bool(nlohmann::json::parse(*ret));
}

std::optional<bool> py_ecc::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_IsG2OnCurve, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return bool(nlohmann::json::parse(*ret));
}
 
std::optional<component::G2> py_ecc::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_HashToG2, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G2(nlohmann::json::parse(*ret));
}

std::optional<component::G2> py_ecc::OpBLS_MapToG2(operation::BLS_MapToG2& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_MapToG2, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G2(nlohmann::json::parse(*ret));
}

std::optional<bool> py_ecc::OpBLS_Verify(operation::BLS_Verify& op) {
    static const std::vector<uint8_t> DST{0x42, 0x4c, 0x53, 0x5f, 0x53, 0x49, 0x47, 0x5f, 0x42, 0x4c, 0x53, 0x31, 0x32, 0x33, 0x38, 0x31, 0x47, 0x32, 0x5f, 0x58, 0x4d, 0x44, 0x3a, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53, 0x53, 0x57, 0x55, 0x5f, 0x52, 0x4f, 0x5f, 0x50, 0x4f, 0x50, 0x5f};
    if ( op.dest.Get() != DST ) {
        return std::nullopt;
    }

    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_Verify, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return bool(nlohmann::json::parse(*ret));
}

std::optional<component::BLS_Signature> py_ecc::OpBLS_Sign(operation::BLS_Sign& op) {
    static const std::vector<uint8_t> DST{0x42, 0x4c, 0x53, 0x5f, 0x53, 0x49, 0x47, 0x5f, 0x42, 0x4c, 0x53, 0x31, 0x32, 0x33, 0x38, 0x31, 0x47, 0x32, 0x5f, 0x58, 0x4d, 0x44, 0x3a, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53, 0x53, 0x57, 0x55, 0x5f, 0x52, 0x4f, 0x5f, 0x50, 0x4f, 0x50, 0x5f};
    if ( op.dest.Get() != DST ) {
        return std::nullopt;
    }
    if ( op.hashOrPoint == false ) {
        return std::nullopt;
    }

    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_Sign, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::BLS_Signature(nlohmann::json::parse(*ret));
}

std::optional<component::Bignum> py_ecc::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }
    if ( op.calcOp.Get() != CF_CALCOP("InvMod(A,B)") ){
        return std::nullopt;
    }
    const auto mod = op.modulo->ToTrimmedString();
    if (
            mod != "52435875175126190479447740508185965837690552500527637822603658699938581184513" &&
            mod != "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        return std::nullopt;
    }

    nlohmann::json j;
    j["a"] = op.bn0.ToTrimmedString();
    j["mod"] = mod;

    const auto ret = RunPythonFunction(py_ecc_detail::OpBignumCalc_InvMod, j.dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::Bignum(nlohmann::json::parse(*ret));
}

std::optional<component::G1> py_ecc::OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_Decompress_G1, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G1(nlohmann::json::parse(*ret));
}

std::optional<component::Bignum> py_ecc::OpBLS_Compress_G1(operation::BLS_Compress_G1& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_Compress_G1, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::Bignum(nlohmann::json::parse(*ret));
}

std::optional<component::G2> py_ecc::OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_Decompress_G2, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G2(nlohmann::json::parse(*ret));
}

std::optional<component::G1> py_ecc::OpBLS_Compress_G2(operation::BLS_Compress_G2& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_Compress_G2, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G1(nlohmann::json::parse(*ret));
}

std::optional<component::G1> py_ecc::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G1_Add, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G1(nlohmann::json::parse(*ret));
}

std::optional<component::G1> py_ecc::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G1_Mul, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G1(nlohmann::json::parse(*ret));
}

std::optional<bool> py_ecc::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G1_IsEq, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return bool(nlohmann::json::parse(*ret));
}

std::optional<component::G1> py_ecc::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G1_Neg, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G1(nlohmann::json::parse(*ret));
}

std::optional<component::G2> py_ecc::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G2_Add, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G2(nlohmann::json::parse(*ret));
}

std::optional<component::G2> py_ecc::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G2_Mul, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G2(nlohmann::json::parse(*ret));
}

std::optional<bool> py_ecc::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G2_IsEq, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return bool(nlohmann::json::parse(*ret));
}

std::optional<component::G2> py_ecc::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    const auto ret = RunPythonFunction(py_ecc_detail::OpBLS_G2_Neg, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }
    return component::G2(nlohmann::json::parse(*ret));
}

std::optional<Buffer> py_ecc::OpMisc(operation::Misc& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    try {
        switch ( op.operation.Get() ) {
            case    0:
                {
                    nlohmann::json j;
                    j["a_x"] = ds.GetData(0);
                    j["a_y"] = ds.GetData(0);
                    j["b_x"] = ds.GetData(0);
                    j["b_y"] = ds.GetData(0);
                    RunPythonFunction(py_ecc_detail::OpMisc_Fq2_Sqrt, j.dump());
                }
                break;
            case    1:
                {
                    nlohmann::json j;
                    j["a_x"] = ds.GetData(0);
                    j["a_y"] = ds.GetData(0);
                    j["b_x"] = ds.GetData(0);
                    j["b_y"] = ds.GetData(0);
                    j["c_x"] = ds.GetData(0);
                    j["c_y"] = ds.GetData(0);
                    RunPythonFunction(py_ecc_detail::OpMisc_Iso_Map_G2, j.dump());
                }
                break;
            case    2:
                {
                    nlohmann::json j;
                    j["a_x"] = ds.GetData(0, 96, 96);
                    j["a_y"] = ds.GetData(0, 96, 96);
                    j["b_x"] = ds.GetData(0, 96, 96);
                    j["b_y"] = ds.GetData(0, 96, 96);
                    j["c_x"] = ds.GetData(0, 96, 96);
                    j["c_y"] = ds.GetData(0, 96, 96);
                    j["multiplier"] = ds.GetData(0, 96, 96);
                    RunPythonFunction(py_ecc_detail::OpMisc_Multiply, j.dump());
                }
                break;
        }
    } catch ( fuzzing::datasource::Base::OutOfData ) { }

    return std::nullopt;
}

bool py_ecc::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
