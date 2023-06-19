#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#include <libplatform/libplatform.h>
#include <v8-context.h>
#include <v8-initialization.h>
#include <v8-isolate.h>
#include <v8-local-handle.h>
#include <v8-primitive.h>
#include <v8-script.h>
#include <v8-exception.h>

#include <iostream>

namespace cryptofuzz {
namespace module {

namespace V8_embedded_detail {
    v8::Isolate* isolate;
    v8::Eternal<v8::Context> context;
    v8::Eternal<v8::Script> script;
    std::unique_ptr<v8::Platform> platform;

    static v8::Local<v8::Value> Load(const std::string& s) {
        return v8::String::NewFromUtf8(isolate, s.c_str()).ToLocalChecked();
    }
}
V8_embedded::V8_embedded(void) :
    Module("V8-embedded") {
        v8::V8::InitializeICUDefaultLocation("");
        v8::V8::InitializeExternalStartupData("");
        V8_embedded_detail::platform = v8::platform::NewDefaultPlatform();
        v8::V8::InitializePlatform(V8_embedded_detail::platform.get());
        v8::V8::Initialize();

        v8::Isolate::CreateParams create_params;
        create_params.array_buffer_allocator =
            v8::ArrayBuffer::Allocator::NewDefaultAllocator();
        V8_embedded_detail::isolate = v8::Isolate::New(create_params);

        v8::Isolate::Scope isolate_scope(V8_embedded_detail::isolate);

        v8::HandleScope handle_scope(V8_embedded_detail::isolate);

        auto context = v8::Context::New(V8_embedded_detail::isolate);
        V8_embedded_detail::context = v8::Eternal<v8::Context>(V8_embedded_detail::isolate, context);

        v8::Context::Scope context_scope(context);

        {
#include "harness.h"
            char harness[sizeof(harness_js) + 1];
            memcpy(harness, harness_js, sizeof(harness_js));
            harness[sizeof(harness_js)] = 0;
            v8::Local<v8::String> source =
                v8::String::NewFromUtf8Literal(V8_embedded_detail::isolate, harness);

            auto script = v8::Script::Compile(context, source).ToLocalChecked();
            V8_embedded_detail::script = v8::Eternal<v8::Script>(V8_embedded_detail::isolate, script);
            script->Run(context).ToLocalChecked();
        }
}

std::optional<component::Bignum> V8_embedded::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    v8::HandleScope handle_scope(V8_embedded_detail::isolate);
    auto ctx = V8_embedded_detail::context.Get(V8_embedded_detail::isolate);

    v8::Local<v8::Value> harness_object = ctx->Global()->Get(
            ctx,
            V8_embedded_detail::Load("cryptofuzz")
    ).ToLocalChecked();
    CF_ASSERT(harness_object->IsFunction(), "V8 error");

    {
        v8::TryCatch trycatch(V8_embedded_detail::isolate);
        v8::Local<v8::Value> argv[] = {
            V8_embedded_detail::Load(repository::CalcOpToString(op.calcOp.Get())),
            V8_embedded_detail::Load(op.bn0.ToString()),
            V8_embedded_detail::Load(op.bn1.ToString()),
        };
        v8::MaybeLocal<v8::Value> harness_ret = harness_object.As<v8::Object>()->CallAsFunction(
                ctx,
                ctx->Global(),
                3,
                argv);

        if (!harness_ret.IsEmpty()) {
            const auto s = harness_ret.ToLocalChecked();
            if ( s->IsString() ) {
                v8::String::Utf8Value utf8Value(V8_embedded_detail::isolate, s);
                ret = component::Bignum(std::string(*utf8Value));
            }
        }
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
