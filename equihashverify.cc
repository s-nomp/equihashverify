#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "crypto/equihash.h"

#include <vector>
using namespace v8;

const char* ToCString(const String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

int verifyEH(const char *hdr, const std::vector<unsigned char> &soln, const char *personalizationString, unsigned int N, unsigned int K) {
    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(N, K, state, personalizationString);

    crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);

    bool isValid;
    EhIsValidSolution(N, K, state, soln, isValid);

    return isValid;
}

void Verify(const v8::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 4) {
        isolate->ThrowException(
            Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments"))
        );

        return;
    }

    if (!args[3]->IsInt32() || !args[4]->IsInt32()) {
        isolate->ThrowException(
            Exception::TypeError(String::NewFromUtf8(isolate, "Third and fourth parameters should be equihash parameters (n, k)"))
        );

        return;
    }

    Local<Object> header = args[0]->ToObject();
    Local<Object> solution = args[1]->ToObject();

    if(!node::Buffer::HasInstance(header) || !node::Buffer::HasInstance(solution)) {
        isolate->ThrowException(
            Exception::TypeError(String::NewFromUtf8(isolate, "First two arguments should be buffer objects."))
        );

        return;
    }

    if (!args[2]->IsString()) {
        isolate->ThrowException(
            Exception::TypeError(String::NewFromUtf8(isolate, "Third argument should be the personalization string."))
        );

        return;
    }

    const char *hdr = node::Buffer::Data(header);
    if(node::Buffer::Length(header) != 140) {
        //invalid hdr length
        args.GetReturnValue().Set(false);
        return;
    }

    const char *soln = node::Buffer::Data(solution);

    std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));

    String::Utf8Value str(args[2]);
    const char* personalizationString = ToCString(str);

    // Validate for N, K (3rd and 4th parameters)
    bool result = verifyEH(
        hdr,
        vecSolution,
        personalizationString,
        args[3].As<Uint32>()->Value(),
        args[4].As<Uint32>()->Value()
    );

    args.GetReturnValue().Set(result);
}


void Init(Handle<Object> exports) {
    NODE_SET_METHOD(exports, "verify", Verify);
}

NODE_MODULE(equihashverify, Init)
