#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

namespace cryptofuzz {
namespace module {

namespace Starkware_detail {
    void* OpECC_Point_Add = nullptr;
    void* OpECC_Point_Mul = nullptr;
    void* OpECC_Point_Dbl = nullptr;
    void* OpECC_Point_Neg = nullptr;
    void* OpECC_ValidatePubkey = nullptr;
    void* OpBLS_G1_Add = nullptr;
    void* OpBLS_G1_Mul = nullptr;
    void* OpBignumCalc_AddMod = nullptr;
    void* OpBignumCalc_SubMod = nullptr;
    void* OpBignumCalc_Mul = nullptr;
    void* OpBignumCalc_Mul_u = nullptr;
    void* OpBignumCalc_MulMod = nullptr;
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

    Starkware_detail::OpECC_Point_Add = LoadPythonFunction(pModule, "OpECC_Point_Add");
    Starkware_detail::OpECC_Point_Mul = LoadPythonFunction(pModule, "OpECC_Point_Mul");
    Starkware_detail::OpECC_Point_Dbl = LoadPythonFunction(pModule, "OpECC_Point_Dbl");
    Starkware_detail::OpECC_Point_Neg = LoadPythonFunction(pModule, "OpECC_Point_Neg");
    Starkware_detail::OpECC_ValidatePubkey = LoadPythonFunction(pModule, "OpECC_ValidatePubkey");
    Starkware_detail::OpBLS_G1_Add = LoadPythonFunction(pModule, "OpBLS_G1_Add");
    Starkware_detail::OpBLS_G1_Mul = LoadPythonFunction(pModule, "OpBLS_G1_Mul");
    Starkware_detail::OpBignumCalc_AddMod = LoadPythonFunction(pModule, "OpBignumCalc_AddMod");
    Starkware_detail::OpBignumCalc_SubMod = LoadPythonFunction(pModule, "OpBignumCalc_SubMod");
    Starkware_detail::OpBignumCalc_Mul = LoadPythonFunction(pModule, "OpBignumCalc_Mul");
    Starkware_detail::OpBignumCalc_Mul_u = LoadPythonFunction(pModule, "OpBignumCalc_Mul_u");
    Starkware_detail::OpBignumCalc_MulMod = LoadPythonFunction(pModule, "OpBignumCalc_MulMod");
}

Starkware::Starkware(void) :
    Module("Starkware") {
        ConfigurePython();
    }

std::optional<component::ECC_Point> Starkware::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return std::nullopt;
    }

    std::optional<std::string> ret = std::nullopt;

    ret = RunPythonFunction(Starkware_detail::OpECC_Point_Add, op.ToJSON().dump());

    CF_CHECK_NE(ret, std::nullopt);

    return component::ECC_Point(nlohmann::json::parse(*ret));

end:
    return std::nullopt;
}

std::optional<component::ECC_Point> Starkware::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return std::nullopt;
    }

    std::optional<std::string> ret = std::nullopt;

    ret = RunPythonFunction(Starkware_detail::OpECC_Point_Mul, op.ToJSON().dump());

    CF_CHECK_NE(ret, std::nullopt);

    return component::ECC_Point(nlohmann::json::parse(*ret));

end:
    return std::nullopt;
}

std::optional<component::ECC_Point> Starkware::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return std::nullopt;
    }

    std::optional<std::string> ret = std::nullopt;

    ret = RunPythonFunction(Starkware_detail::OpECC_Point_Dbl, op.ToJSON().dump());

    CF_CHECK_NE(ret, std::nullopt);

    return component::ECC_Point(nlohmann::json::parse(*ret));

end:
    return std::nullopt;
}

std::optional<component::ECC_Point> Starkware::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return std::nullopt;
    }

    std::optional<std::string> ret = std::nullopt;

    ret = RunPythonFunction(Starkware_detail::OpECC_Point_Neg, op.ToJSON().dump());

    CF_CHECK_NE(ret, std::nullopt);

    return component::ECC_Point(nlohmann::json::parse(*ret));

end:
    return std::nullopt;
}

std::optional<bool> Starkware::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return std::nullopt;
    }

    std::optional<std::string> ret = std::nullopt;

    ret = RunPythonFunction(Starkware_detail::OpECC_ValidatePubkey, op.ToJSON().dump());

    CF_CHECK_NE(ret, std::nullopt);

    return bool(nlohmann::json::parse(*ret));

end:
    return std::nullopt;
}

std::optional<component::G1> Starkware::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    const auto ret = RunPythonFunction(Starkware_detail::OpBLS_G1_Add, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }

    return component::G1(nlohmann::json::parse(*ret));
}

std::optional<component::G1> Starkware::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    const auto ret = RunPythonFunction(Starkware_detail::OpBLS_G1_Mul, op.ToJSON().dump());
    if ( ret == std::nullopt ) {
        return std::nullopt;
    }

    return component::G1(nlohmann::json::parse(*ret));
}

std::optional<component::Bignum> Starkware::OpBignumCalc(operation::BignumCalc& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    nlohmann::json j;
    j["bn0"] = op.bn0.ToTrimmedString();
    j["bn1"] = op.bn1.ToTrimmedString();
    j["bn2"] = op.bn2.ToTrimmedString();

    std::optional<std::string> ret = std::nullopt;

    if ( op.calcOp.Get() == CF_CALCOP("AddMod(A,B,C)") ){
        ret = RunPythonFunction(Starkware_detail::OpBignumCalc_AddMod, j.dump());
    } else if ( op.calcOp.Get() == CF_CALCOP("SubMod(A,B,C)") ){
        ret = RunPythonFunction(Starkware_detail::OpBignumCalc_SubMod, j.dump());
    } else if ( op.calcOp.Get() == CF_CALCOP("Mul(A,B)") ){
        bool which = false;

        try {
            which = ds.Get<bool>();
        } catch ( ... ) { }

        if ( which ) {
            ret = RunPythonFunction(Starkware_detail::OpBignumCalc_Mul, j.dump());
        } else {
            ret = RunPythonFunction(Starkware_detail::OpBignumCalc_Mul_u, j.dump());
        }
    } else if ( op.calcOp.Get() == CF_CALCOP("MulMod(A,B,C)") ){
        ret = RunPythonFunction(Starkware_detail::OpBignumCalc_MulMod, j.dump());
    }

    CF_CHECK_NE(ret, std::nullopt);

    return component::Bignum(nlohmann::json::parse(*ret));
end:
    return std::nullopt;
}

} /* namespace module */
} /* namespace cryptofuzz */
