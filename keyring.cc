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
		keyPair = loadKeyPair(filename);
	}
}

KeyRing::~KeyRing(){
	if (keyPair != 0){
		delete keyPair;
		keyPair = 0;
	}
}

void KeyRing::Init(Handle<Object> exports){
	//Prepare constructor template
	Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
	tpl->SetClassName(String::NewSymbol("KeyRing"));
	tpl->InstanceTemplate()->SetInternalFieldCount(2);
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

//Function callback (optional)
Handle<Value> KeyRing::PublicKeyInfo(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	//Checking that a keypair is loaded in memory
	if (instance->keyPair == 0){
		ThrowException(Exception::TypeError(String::New("No key has been loaded into memory")));
		return scope.Close(Undefined());
	}
	//Sync/async fork
	if (args.Length() == 0){
		return scope.Close(instance->PPublicKeyInfo());
	} else {
		Local<Function> callback = Local<Function>::Cast(args[0]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(instance->PPublicKeyInfo()) };
		callback->Call(Context::GetCurrent()->Global(), argc, argv);
		return scope.Close(Undefined());
	}
}

Local<Object> KeyRing::PPublicKeyInfo(){
	Local<Object> pubKeyObj = Object::New();
	if (keyPair == 0){
		throw new runtime_error("No loaded key pair");
	}
	string keyType = keyPair->at("keyType");
	string publicKey = keyPair->at("publicKey");
	pubKeyObj->Set(String::NewSymbol("keyType"), String::New(keyType.c_str()));
	pubKeyObj->Set(String::NewSymbol("publicKey"), String::New(publicKey.c_str()));
	return pubKeyObj;
}

/*
* Generates a keypair. Save it to filename if given
* String keyType, String filename [optional], Function callback [optional]
*/
Handle<Value> KeyRing::CreateKeyPair(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (args.Length() < 1){

	}
	String::Utf8Value keyTypeVal(args[0]->ToString());
	string keyType(*keyTypeVal);
	if (!(keyType == "ed25519" || keyType == "curve25519")) {
		ThrowException(Exception::TypeError(String::New("Invalid key type")));
		return scope.Close(Undefined());
	}
	//Preparing new keypair map
	map<string, string>* newKeyPair = new map<string, string>();
	//Delete the keypair loaded in memory, if any
	if (instance->keyPair != 0){
		delete instance->keyPair;
		instance->keyPair = 0;
	}
	instance->keyPair = newKeyPair;

	if (keyType == "ed25519"){
		string privateKey, publicKey;
		publicKey.reserve(32);
		privateKey.reserve(64);
		crypto_sign_keypair((unsigned char*)publicKey.data(), (unsigned char*)privateKey.data());

		newKeyPair->insert(make_pair("keyType", "ed25519"));
		newKeyPair->insert(make_pair("privateKey", strToHex(privateKey)));
		newKeyPair->insert(make_pair("publicKey", strToHex(publicKey)));
	} else if (keyType == "curve25519"){
		string privateKey, publicKey;
		publicKey.reserve(32);
		privateKey.reserve(32);
		crypto_box_keypair((unsigned char*)publicKey.data(), (unsigned char*)privateKey.data());

		newKeyPair->insert(make_pair("keyType", "curve25519"));
		newKeyPair->insert(make_pair("privateKey", strToHex(privateKey)));
		newKeyPair->insert(make_pair("publicKey", strToHex(publicKey)));
	}

	if (args.Length() >= 2 && !args[1]->IsUndefined()){ //Save keypair to file
		String::Utf8Value filenameVal(args[1]->ToString());
		string filename(*filenameVal);
		saveKeyPair(filename, instance->keyPair);
	}
	if (args.Length() == 3){ //Callback
		Local<Function> callback = Local<Function>::Cast(args[2]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(instance->PPublicKeyInfo()) };
		callback->Call(Context::GetCurrent()->Global(), argc, argv);
		return scope.Close(Undefined());
	} else {
		return scope.Close(instance->PPublicKeyInfo());
	}
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
	if (instance->keyPair != 0){
		delete instance->keyPair;
		instance->keyPair = 0;
	}
	return scope.Close(Undefined());
}

/*map<string, string>* KeyRing::edwardsToMontgomery(map<string, string>* edwards){

}*/

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