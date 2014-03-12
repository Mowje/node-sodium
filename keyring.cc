#define BUILDING_NODE_EXTENSION

#include <iostream>

#include <string>
#include <map>
#include <exception>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <utility>
#include <iomanip>
#include <algorithm>

#include <node.h>
#include <node_buffer.h>
#include "keyring.h"

//Including some libsodium internals used to make the edwards -> montgomery transformation
//#include ""

//Including libsodium export headers
#include "sodium.h"

using namespace v8;
using namespace node;
using namespace std;

//Defining "invlid number of parameters" macro
#define MANDATORY_ARGS(n, message) \
	if (args.Length() < n){ \
		ThrowException(TypeError(String::New(message.c_str()))); \
	}

Persistent<Function> KeyRing::constructor;

KeyRing::KeyRing(string filename) : filename_(filename){
	if (filename != ""){
		if (!doesFileExist(filename)){
			//Throw a V8 exception??
			return;
		}
		loadKeyPair(filename);
	}
}

KeyRing::~KeyRing(){

}

void KeyRing::Init(Handle<Object> exports){
	//Prepare constructor template
	Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
	tpl->SetClassName(String::NewSymbol("KeyRing"));
	tpl->InstanceTemplate()->SetInternalFieldCount(5);
	//Prototype
	tpl->PrototypeTemplate()->Set(String::NewSymbol("encrypt"), FunctionTemplate::New(Encrypt)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(Decrypt)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("sign"), FunctionTemplate::New(Sign)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("agree"), FunctionTemplate::New(Agree)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("publicKeyInfo"), FunctionTemplate::New(PublicKeyInfo)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("createKeyPair"), FunctionTemplate::New(CreateKeyPair)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("load"), FunctionTemplate::New(Load)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("save"), FunctionTemplate::New(Save)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("clear"), FunctionTemplate::New(Clear)->GetFunction());

	constructor = Persistent<Function>::New(tpl->GetFunction());
	exports->Set(String::NewSymbol("KeyRing"), constructor);
}

/*
* JS -> C++ data constructor bridge
*/
Handle<Value> KeyRing::New(const Arguments& args){
	HandleScope scope;
	if (args.IsConstructCall()){
		//Invoked as a constructor
		if (args.Length() > 1){
			ThrowException(Exception::TypeError(String::New("Invalid number of arguments on KeyRing constructor call")));
			return scope.Close(Undefined());
		}
		string filename;
		if (args[0]->IsUndefined()){
			filename = "";
		} else {
			String::Utf8Value filenameVal(args[0]->ToString());
			filename = string(*filenameVal);
		}
		KeyRing* newInstance = new KeyRing(filename);
		newInstance->Wrap(args.This());
		return args.This();
	} else {
		//Invoked as a plain function; turn it into construct call
		if (args.Length() > 1){
			ThrowException(Exception::TypeError(String::New("Invalid number of arguments on KeyRing constructor call")));
			return scope.Close(Undefined());
		}
		if (args.Length() == 1){
			Local<Value> argv[1] = { args[0] };
			return scope.Close(constructor->NewInstance(1, argv));
		} else {
			return scope.Close(constructor->NewInstance());
		}
	}
}

/**
* Make a Curve25519 key exchange for a given public key, then encrypt the message
*/
Handle<Value> KeyRing::Encrypt(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

Handle<Value> KeyRing::Decrypt(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

Handle<Value> KeyRing::Sign(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

Handle<Value> KeyRing::Agree(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

Handle<Value> KeyRing::PublicKeyInfo(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

/*
* Generates an Ed25519 keypair (and converts it to Curve25519 expresssion). Save it to filename if given
* String filename [optional], Function callback [optional]
*/
Handle<Value> KeyRing::CreateKeyPair(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	crypto_sign_keypair((unsigned char*)instance->publicKey.data(), (unsigned char*)instance->privateKey.data());
	cout << "Public key: " << strToHex(instance->publicKey) << endl;
}

Handle<Value> KeyRing::Load(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

Handle<Value> KeyRing::Save(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

Handle<Value> KeyRing::Clear(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());

	return scope.Close(Undefined());
}

map<string, string>* KeyRing::edwardsToMontgomery(map<string, string>* edwards){

}

string KeyRing::strToHex(string const& s){
	static const char* const charset = "0123456789abcdef";
	size_t length = s.length();

	string output;
	output.reserve(2 * length);
	for (size_t i = 0; i < length; i++){
	   const unsigned char c = s[i];
	   output.push_back(charset[c >> 4]);
	   output.push_back(charset[c & 15]);
	}
	return output;
}

string KeyRing::hexToStr(string const& s){
	static const char* const charset = "0123456789abcdef";
    size_t length = s.length();
    if (length & 1) throw invalid_argument("Odd length");
    
    string output;
    output.reserve(length / 2);
    for (size_t i = 0; i < length; i+= 2){
        char a = s[i];
        const char* p = lower_bound(charset, charset + 16, a);
        if (*p != a) throw invalid_argument("Invalid hex char");
        
        char b = s[i + 1];
        const char* q = lower_bound(charset, charset + 16, b);
        if (*q != b) throw invalid_argument("Invalid hex char");
        
        output.push_back(((p - charset) << 4) | (q - charset));
    }
    return output;
}

bool KeyRing::doesFileExist(string const& filename){
	fstream file(filename.c_str(), ios::in);
	bool isGood = file.good();
	file.close();
	return isGood;
}

void KeyRing::saveKeyPair(string const& filename, map<string, string>* keyPair){
	fstream fileWriter(filename.c_str(), ios::out | ios::trunc);
	
}

map<string, string>* KeyRing::loadKeyPair(string const& filename){

}