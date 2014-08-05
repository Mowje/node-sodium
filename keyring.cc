//#define BUILDING_NODE_EXTENSION

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
#include <cstring>

#include <node.h>
#include <node_buffer.h>
#include "keyring.h"

//Including libsodium export headers
#include "sodium.h"

using namespace v8;
using namespace node;
using namespace std;

#define PREPARE_FUNC_VARS() \
	HandleScope scope; \
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This()); \
	Local<Object> globalObj = Context::GetCurrent()->Global();

//Defining "invlid number of parameters" macro
#define MANDATORY_ARGS(n, message) \
	if (args.Length() < n){ \
		ThrowException(Exception::TypeError(String::New(message))); \
		return scope.Close(Undefined()); \
	}

#define CHECK_KEYPAIR(type) \
	if (instance->_keyType == ""){ \
		ThrowException(Exception::TypeError(String::New("No key pair has been loaded into the key ring"))); \
		return scope.Close(Undefined()); \
	} \
	if (instance->_keyType != type){ \
		ThrowException(Exception::TypeError(String::New("Invalid key type"))); \
		return scope.Close(Undefined()); \
	}

#define BUILD_BUFFER(data) \
	int resultBufferLength = strlen(data); \
	Buffer* slowBuffer = Buffer::New(resultBufferLength); \
	memcpy(Buffer::Data(slowBuffer), data, resultBufferLength); \
	Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer"))); \
	Handle<Value> constructorArgs[3] = { slowBuffer->handle_, Integer::New(resultBufferLength), Integer::New(0) }; \
	Local<Object> resultBuffer = bufferConstructor->NewInstance(3, constructorArgs);

Persistent<Function> KeyRing::constructor;

KeyRing::KeyRing(string const& filename, unsigned char* password, size_t passwordSize) : _filename(filename), _privateKey(0), _publicKey(0){
	if (filename != ""){
		if (!doesFileExist(filename)){
			//Throw a V8 exception??
			return;
		}
		loadKeyPair(filename, &_keyType, _privateKey, _publicKey, password, passwordSize);
		_filename = filename;
	}
}

KeyRing::~KeyRing(){
	if (_privateKey != 0){
		delete _privateKey;
		_privateKey = 0;
	}
	if (_publicKey != 0){
		delete _publicKey;
		_publicKey = 0;
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
* Parameter : String filename [optional]
*/
Handle<Value> KeyRing::New(const Arguments& args){
	HandleScope scope;
	if (args.IsConstructCall()){
		//Invoked as a constructor
		string filename;
		unsigned char* password = 0;
		size_t passwordSize = 0;
		if (args[0]->IsUndefined()){
			filename = "";
		} else {
			String::Utf8Value filenameVal(args[0]->ToString());
			filename = string(*filenameVal);
		}
		if (args.Length() > 1 && !args[1]->IsUndefined()){
			//Casting password
			Local<Object> passwordVal = args[1]->ToObject();

			password = (unsigned char*) Buffer::Data(passwordVal);
			passwordSize = Buffer::Length(passwordVal);
		}
		KeyRing* newInstance = new KeyRing(filename, password, passwordSize);
		newInstance->Wrap(args.This());
		return args.This();
	} else {
		//Invoked as a plain function; turn it into construct call
		if (args.Length() > 2){
			ThrowException(Exception::TypeError(String::New("Invalid number of arguments on KeyRing constructor call")));
			return scope.Close(Undefined());
		}
		if (args.Length() > 0){
			unsigned int argsLength = args.Length();
			Local<Value> * argvPtr = NULL;
			if (argsLength == 1){
				Local<Value> argv[1] = {args[0]};
				argvPtr = argv;
			} else if (argsLength == 2){
				Local<Value> argv[2] = {args[0], args[1]};
				argvPtr = argv;
			}
			return scope.Close(constructor->NewInstance(argsLength, argvPtr));
		} else return scope.Close(constructor->NewInstance());


		/*if (args.Length() == 1){
			Local<Value> argv[1] = { args[0] };
			return scope.Close(constructor->NewInstance(1, argv));
		} else {
			return scope.Close(constructor->NewInstance());
		}*/
	}
}

/**
* Make a Curve25519 key exchange for a given public key, then encrypt the message (crypto_box)
* Parameters Buffer message, Buffer publicKey, Buffer nonce, callback (optional)
* Returns Buffer
*/
Handle<Value> KeyRing::Encrypt(const Arguments& args){
	PREPARE_FUNC_VARS();
	MANDATORY_ARGS(3, "Mandatory args : message, counterpartPubKey, nonce\nOptional args: callback");
	CHECK_KEYPAIR("curve25519");

	Local<Object> messageVal = args[0]->ToObject();
	Local<Object> publicKeyVal = args[1]->ToObject();
	Local<Object> nonceVal = args[2]->ToObject();

	const unsigned char* message = (unsigned char*) Buffer::Data(messageVal);
	const size_t messageLength = Buffer::Length(messageVal);

	const unsigned char* publicKey = (unsigned char*) Buffer::Data(publicKeyVal);
	const size_t publicKeyLength = Buffer::Length(publicKeyVal);
	if (publicKeyLength != crypto_box_PUBLICKEYBYTES){
		stringstream errMsg;
		errMsg << "Public key must be " << crypto_box_PUBLICKEYBYTES << " bytes long";
		ThrowException(Exception::TypeError(String::New(errMsg.str().c_str())));
		return scope.Close(Undefined());
	}
	const unsigned char* nonce = (unsigned char*) Buffer::Data(nonceVal);
	const size_t nonceLength = Buffer::Length(nonceVal);
	if (nonceLength != crypto_box_NONCEBYTES){
		stringstream errMsg;
		errMsg << "The nonce must be " << crypto_box_NONCEBYTES << " bytes long";
		ThrowException(Exception::TypeError(String::New(errMsg.str().c_str())));
		return scope.Close(Undefined());
	}

	unsigned char* paddedMessage = new unsigned char[messageLength + crypto_box_ZEROBYTES];
	for (unsigned int i = 0; i < crypto_box_ZEROBYTES; i++){
		paddedMessage[i] = 0;
	}
	memcpy((void*) (paddedMessage + crypto_box_ZEROBYTES), (void*) message, messageLength);

	Buffer* cipherBuf = Buffer::New(messageLength + crypto_box_ZEROBYTES);
	unsigned char* cipher = (unsigned char*)Buffer::Data(cipherBuf);

	int boxResult = crypto_box(cipher, paddedMessage, messageLength + crypto_box_ZEROBYTES, nonce, publicKey, instance->_privateKey);
	if (boxResult != 0){
		stringstream errMsg;
		errMsg << "Error while encrypting message. Error code : " << boxResult;
		ThrowException(Exception::TypeError(String::New(errMsg.str().c_str())));
		return scope.Close(Undefined());
	}

	//BUILD_BUFFER(string((char*) cipher, message.length()).c_str());
	if (args.Length() == 3){
		return scope.Close(cipherBuf->handle_);
	} else {
		BUILD_BUFFER(string((char*)cipher, messageLength + crypto_box_ZEROBYTES).c_str());
		Local<Function> callback = Local<Function>::Cast(args[3]);
		const int argc = 1;
		Local<Value> argv[argc] = { resultBuffer };
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	}
}

/*
* Decrypt a message, using crypto_box_open
* Args : Buffer cipher, Buffer publicKey, Buffer nonce, Function callback (optional)
*/
Handle<Value> KeyRing::Decrypt(const Arguments& args){
	PREPARE_FUNC_VARS();
	MANDATORY_ARGS(3, "Mandatory args : cipher, counterpartPubKey, nonce\nOptional args: callback");
	CHECK_KEYPAIR("curve25519");

	Local<Object> cipherVal = args[0]->ToObject();
	Local<Object> publicKeyVal = args[1]->ToObject();
	Local<Object> nonceVal = args[2]->ToObject();

	const unsigned char* cipher = (unsigned char*) Buffer::Data(cipherVal);
	const size_t cipherLength = Buffer::Length(cipherVal);

	//Checking that the first crypto_box_BOXZEROBYTES are zeros
	unsigned int i = 0;
	for (i = 0; i < crypto_box_BOXZEROBYTES; i++){
		if (cipher[i]) break;
	}
	if (i < crypto_box_BOXZEROBYTES){
		stringstream errMsg;
		errMsg << "The first " << crypto_box_BOXZEROBYTES << " bytes of the cipher argument must be zeros";
		ThrowException(Exception::TypeError(String::New(errMsg.str().c_str())));
		return scope.Close(Undefined());
	}

	const unsigned char* publicKey = (unsigned char*) Buffer::Data(publicKeyVal);

	const unsigned char* nonce = (unsigned char*) Buffer::Data(nonceVal);

	unsigned char* message = new unsigned char[cipherLength];

	int boxResult = crypto_box_open(message, cipher, cipherLength, nonce, publicKey, instance->_privateKey);
	if (boxResult != 0){
		stringstream errMsg;
		errMsg << "Error while decrypting message. Error code : " << boxResult;
		ThrowException(Exception::TypeError(String::New(errMsg.str().c_str())));
		return scope.Close(Undefined());
	}

	unsigned char* plaintext = new unsigned char[cipherLength - crypto_box_ZEROBYTES];
	memcpy(plaintext, (void*) (message + crypto_box_ZEROBYTES), cipherLength - crypto_box_ZEROBYTES);


	BUILD_BUFFER(string((char*)plaintext, cipherLength - crypto_box_ZEROBYTES).c_str());
	if (args.Length() == 3){
		return scope.Close(resultBuffer);
	} else {
		Local<Function> callback = Local<Function>::Cast(args[3]);
		const int argc = 1;
		Local<Value> argv[argc] = { resultBuffer };
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	}
}

/*
* Sign a given message, using crypto_sign
* Args: Buffer message, Function callback (optional)
*/
Handle<Value> KeyRing::Sign(const Arguments& args){
	PREPARE_FUNC_VARS();
	MANDATORY_ARGS(1, "Mandatory args : message\nOptional args: callback");
	CHECK_KEYPAIR("ed25519");

	Local<Value> messageVal = args[0]->ToObject();

	const unsigned char* message = (unsigned char*) Buffer::Data(messageVal);
	const size_t messageLength = Buffer::Length(messageVal);

	Buffer* signatureBuf = Buffer::New(messageLength + crypto_sign_BYTES);
	unsigned char* signature = (unsigned char*) Buffer::Data(signatureBuf);
	unsigned long long signatureSize;

	int signResult = crypto_sign(signature, &signatureSize, message, messageLength, instance->_privateKey);
	if (signResult != 0){
		stringstream errMsg;
		errMsg << "Error while signing the message. Code : " << signResult << endl;
		ThrowException(Exception::TypeError(String::New(errMsg.str().c_str())));
		return scope.Close(Undefined());
	}

	//BUILD_BUFFER(string((char*) signature, messageLength + crypto_sign_BYTES).c_str());

	if (args.Length() == 1){
		return scope.Close(signatureBuf->handle_);
	} else {
		BUILD_BUFFER(string((char*) signature, messageLength + crypto_sign_BYTES).c_str());
		Local<Function> callback = Local<Function>::Cast(args[1]);
		const int argc = 1;
		Local<Value> argv[argc] = { resultBuffer };
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	}
}

/*
* Do a Curve25519 key-exchange
* Args : Buffer counterpartPubKey, Function callback (optional)
*/
Handle<Value> KeyRing::Agree(const Arguments& args){
	PREPARE_FUNC_VARS();
	MANDATORY_ARGS(1, "Mandatory args : counterpartPubKey\nOptional: callback");
	CHECK_KEYPAIR("curve25519");

	Local<Object> publicKeyVal = args[0]->ToObject();
	const unsigned char* counterpartPubKey = (unsigned char*) Buffer::Data(publicKeyVal);

	Buffer* sharedSecretBuf = Buffer::New(crypto_scalarmult_BYTES);
	unsigned char* sharedSecret = (unsigned char*) Buffer::Data(sharedSecretBuf);
	crypto_scalarmult(sharedSecret, instance->_privateKey, counterpartPubKey);

	if (args.Length() == 1){
		return scope.Close(sharedSecretBuf->handle_);
	} else {
		BUILD_BUFFER(string((char*) sharedSecret, crypto_scalarmult_BYTES).c_str());
		Local<Function> callback = Local<Function>::Cast(args[1]);
		const int argc = 1;
		Local<Value> argv[argc] = { resultBuffer };
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	}
}

//Function callback (optional)
Handle<Value> KeyRing::PublicKeyInfo(const Arguments& args){
	PREPARE_FUNC_VARS();
	//Checking that a keypair is loaded in memory
	if (instance->_keyType == "" || instance->_privateKey == 0 || instance->_publicKey == 0){
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
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	}
}

Local<Object> KeyRing::PPublicKeyInfo(){
	Local<Object> pubKeyObj = Object::New();
	if (_keyType == "" || _privateKey == 0 || _publicKey == 0){
		throw new runtime_error("No loaded key pair");
	}
	//string keyType = keyPair->at("keyType");
	string publicKey = strToHex(string((char*) _publicKey, ((_keyType == "ed25519") ? crypto_sign_PUBLICKEYBYTES : crypto_box_PUBLICKEYBYTES)));
	pubKeyObj->Set(String::NewSymbol("keyType"), String::New(_keyType.c_str()));
	pubKeyObj->Set(String::NewSymbol("publicKey"), String::New(publicKey.c_str()));
	return pubKeyObj;
}

/*
* Generates a keypair. Save it to filename if given
* String keyType, String filename [optional], Function callback [optional], Buffer passoword [optional], Number opsLimit [optional], Number r [optional], Number p [optional]
*/
Handle<Value> KeyRing::CreateKeyPair(const Arguments& args){
	PREPARE_FUNC_VARS();
	MANDATORY_ARGS(1, "Please give the type of the key you want to generate");
	String::Utf8Value keyTypeVal(args[0]->ToString());
	string keyType(*keyTypeVal);
	if (!(keyType == "ed25519" || keyType == "curve25519")) {
		ThrowException(Exception::TypeError(String::New("Invalid key type")));
		return scope.Close(Undefined());
	}
	//Delete the keypair loaded in memory, part by part, if any
	if (instance->_keyType != ""){
		instance->_keyType = "";
	}
	if (instance->_privateKey != 0){
		delete instance->_privateKey;
		instance->_privateKey = 0;
	}
	if (instance->_publicKey != 0){
		delete instance->_publicKey;
		instance->_publicKey = 0;
	}
	instance->_filename = "";
	//Generating keypairs
	if (keyType == "ed25519"){
		unsigned char* privateKey = new unsigned char[crypto_sign_SECRETKEYBYTES];
		unsigned char* publicKey = new unsigned char[crypto_sign_PUBLICKEYBYTES];
		crypto_sign_keypair(publicKey, privateKey);

		instance->_privateKey = privateKey;
		instance->_publicKey = publicKey;
		instance->_keyType = "ed25519";

	} else if (keyType == "curve25519"){
		unsigned char* privateKey = new unsigned char[crypto_box_SECRETKEYBYTES];
		unsigned char* publicKey = new unsigned char[crypto_box_PUBLICKEYBYTES];
		crypto_box_keypair(publicKey, privateKey);

		instance->_privateKey = privateKey;
		instance->_publicKey = publicKey;
		instance->_keyType = "curve25519";
	}

	if (args.Length() >= 2 && !args[1]->IsUndefined()){ //Save keypair to file
		String::Utf8Value filenameVal(args[1]->ToString());
		string filename(*filenameVal);
		if (args.Length() > 3 && !args[3]->IsUndefined()){
			Local<Value> passwordVal = args[3]->ToObject();
			const unsigned char* password = (unsigned char*) Buffer::Data(passwordVal);
			const size_t passwordSize = Buffer::Length(passwordVal);
			if (args.Length() > 4){
				unsigned long opsLimit = 16384;
				unsigned short r = 8;
				unsigned short p = 1;
				if (args[4]->IsNumber()){
					opsLimit = (unsigned long) args[4]->IntegerValue();
				}
				if (args.Length() > 5 && args[5]->IsNumber()){
					r = (unsigned short) args[4]->Int32Value();
				}
				if (args.Length() > 6 && args[6]->IsNumber()){
					p = (unsigned short) args[5]->Int32Value();
				}
				saveKeyPair(filename, keyType, instance->_privateKey, instance->_publicKey, password, passwordSize, opsLimit, r, p);
			} else saveKeyPair(filename, keyType, instance->_privateKey, instance->_publicKey, password, passwordSize);
		} else saveKeyPair(filename, keyType, instance->_privateKey, instance->_publicKey);
		instance->_filename = filename;
	}
	if (args.Length() >= 3){ //Callback
		Local<Function> callback = Local<Function>::Cast(args[2]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(instance->PPublicKeyInfo()) };
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	} else {
		return scope.Close(instance->PPublicKeyInfo());
	}
}

// String filename, Function callback (optional), password, maxOpsLimit
Handle<Value> KeyRing::Load(const Arguments& args){
	PREPARE_FUNC_VARS();
	MANDATORY_ARGS(1, "Mandatory args : String filename\nOptional args : Function callback");

	String::Utf8Value filenameVal(args[0]->ToString());
	string filename(*filenameVal);


	if (instance->_keyType == ""){
		instance->_keyType = "";
	}
	if (instance->_privateKey != 0){
		delete instance->_privateKey;
		instance->_privateKey = 0;
	}
	if (instance ->_publicKey != 0){
		delete instance->_publicKey;
		instance->_publicKey = 0;
	}
	instance->_filename = "";

	fstream fileReader(filename.c_str(), ios::in);
	string keyStr;
	getline(fileReader, keyStr);
	fileReader.close();
	if (keyStr[0] == 0x05){ //Curve25519
		instance->_privateKey = new unsigned char[crypto_box_SECRETKEYBYTES];
		instance->_publicKey = new unsigned char[crypto_box_PUBLICKEYBYTES];
	} else if (keyStr[0] == 0x06){
		instance->_privateKey = new unsigned char[crypto_sign_SECRETKEYBYTES];
		instance->_publicKey = new unsigned char[crypto_sign_PUBLICKEYBYTES];
	} else {
		ThrowException(Exception::TypeError(String::New("Invalid key file")));
	}

	if (args.Length() > 2){
		Local<Value> passwordVal = args[2]->ToObject();
		const unsigned char* password = (unsigned char*) Buffer::Data(passwordVal);
		const size_t passwordSize = Buffer::Length(passwordVal);
		unsigned long maxOpsLimit = 4194304;
		if (args.Length() > 3 && args[3]->IsNumber()){
			maxOpsLimit = (unsigned long) args[3]->IntegerValue();
			//cout << "MaxOpsLimit: " << maxOpsLimit << endl;
		}

		try {
			loadKeyPair(filename, &(instance->_keyType), instance->_privateKey, instance->_publicKey, password, passwordSize, maxOpsLimit);
		} catch (runtime_error* e){
			ThrowException(Exception::Error(String::New(e->what())));
			return scope.Close(Undefined());
		} catch (void* e){
			ThrowException(Exception::Error(String::New("Error while loading the encrypted key file")));
			return scope.Close(Undefined());
		}

	} else {
		try {
			loadKeyPair(filename, &(instance->_keyType), instance->_privateKey, instance->_publicKey);
		} catch (runtime_error* e){
			ThrowException(Exception::Error(String::New(e->what())));
			return scope.Close(Undefined());
		} catch (void* e){
			ThrowException(Exception::Error(String::New("Error while loading the key file")));
			return scope.Close(Undefined());
		}
	}

	instance->_filename = filename;

	instance->PPublicKeyInfo();

	if (args.Length() == 1){
		return scope.Close( instance->PPublicKeyInfo() );
	} else {
		if (args[1]->IsUndefined()) return scope.Close( instance->PPublicKeyInfo() );
		Local<Function> callback = Local<Function>::Cast(args[1]);
		const int argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(instance->PPublicKeyInfo()) };
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	}
}

// String filename, Function callback (optional), Buffer password (optional), Number opsLimit (optional), Number r (optional), Number p (optional)
Handle<Value> KeyRing::Save(const Arguments& args){
	PREPARE_FUNC_VARS();
	MANDATORY_ARGS(1, "Mandatory args : String filename\nOptional args : Function callback");

	if (instance->_keyType == "" || instance->_publicKey == 0 || instance->_privateKey == 0){ //Checking that a key is indeed defined. If not, throw an exception
		ThrowException(Exception::TypeError(String::New("No key has been loaded into the keyring")));
		return scope.Close(Undefined());
	}

	String::Utf8Value filenameVal(args[0]);
	string filename(*filenameVal);

	if (args.Length() > 2){
		if (args[2]->IsUndefined()){
			ThrowException(Exception::TypeError(String::New("When using encryption, the password can't be null")));
			return scope.Close(Undefined());
		}

		Local<Value> passwordVal = args[2]->ToObject();
		const unsigned char* password = (unsigned char*) Buffer::Data(passwordVal);
		const size_t passwordSize = Buffer::Length(passwordVal);

		if (args.Length() > 3){
			//Additional scrypt parameters
			unsigned long opsLimit = 16384;
			unsigned short r = 8;
			unsigned short p = 1;
			if (args[3]->IsNumber()){
				opsLimit = (unsigned long) args[3]->IntegerValue();
			}
			if (args.Length() > 4 && args[4]->IsNumber()){
				r = (unsigned short) args[4]->Int32Value();
			}
			if (args.Length() > 5 && args[5]->IsNumber()){
				p = (unsigned short) args[5]->Int32Value();
			}
			try {
				saveKeyPair(filename, instance->_keyType, instance->_privateKey, instance->_publicKey, password, passwordSize, opsLimit, r, p);
			} catch (runtime_error* e){
				ThrowException(Exception::Error(String::New(e->what())));
				return scope.Close(Undefined());
			} catch (void* e){
				ThrowException(Exception::Error(String::New("Error while saving the encrypted key file")));
				return scope.Close(Undefined());
			}
		} else {
			try {
				saveKeyPair(filename, instance->_keyType, instance->_privateKey, instance->_publicKey, password, passwordSize);
			} catch (runtime_error* e){
				ThrowException(Exception::Error(String::New(e->what())));
				return scope.Close(Undefined());
			} catch (void* e){
				ThrowException(Exception::Error(String::New("Error while saving the encrypted key file")));
				return scope.Close(Undefined());
			}
		}

	} else {
		try {
			saveKeyPair(filename, instance->_keyType, instance->_privateKey, instance->_publicKey);
		} catch (runtime_error* e){
			ThrowException(Exception::Error(String::New(e->what())));
			return scope.Close(Undefined());
		} catch (void* e){
			ThrowException(Exception::Error(String::New("Error while saving the key file")));
			return scope.Close(Undefined());
		}
	}

	if (args.Length() == 1 || (args.Length() > 1 && args[1]->IsUndefined())){
		return scope.Close(Undefined());
	} else {
		Local<Function> callback = Local<Function>::Cast(args[1]);
		const int argc = 0;
		Local<Value> argv[argc];
		callback->Call(globalObj, argc, argv);
		return scope.Close(Undefined());
	}
}

Handle<Value> KeyRing::Clear(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->_keyType != ""){
		instance->_keyType = "";
	}
	if (instance->_privateKey != 0){
		delete instance->_privateKey;
		instance->_privateKey = 0;
	}
	if (instance->_publicKey != 0){
		delete instance->_publicKey;
		instance->_publicKey = 0;
	}
	instance->_filename = "";
	return scope.Close(Undefined());
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

void KeyRing::saveKeyPair(string const& filename, string const& keyType, const unsigned char* privateKey, const unsigned char* publicKey, const unsigned char* password, const size_t passwordSize, const unsigned long opsLimit, const unsigned int r, const unsigned int p){
	fstream fileWriter(filename.c_str(), ios::out | ios::trunc);
	/*string params[] = {"keyType", "privateKey", "publicKey"};
	for (int i = 0; i < 3; i++){
		if (!(keyPair->count(params[i]) > 0)) throw new runtime_error("Missing parameter when saving file : " + params[i]);
	}*/
	if (!((keyType == "ed25519" || keyType == "curve25519") && privateKey != 0 && publicKey != 0)) throw new runtime_error("Invalid parameters");

	string keyBufferStr = encodeKeyBuffer(keyType, privateKey, publicKey);

	//cout << "Key buffer: " << strToHex(keyBufferStr) << endl;

	if (passwordSize > 0){
		//cout << "Password has been provided" << endl;
		//Write key type
		if (keyType == "curve25519") fileWriter << (unsigned char) 0x05;
		else fileWriter << (unsigned char) 0x06; //ed25519
		//cout << "Type, " << endl;
		//Write r (2bytes)
		fileWriter << (unsigned char) (r >> 8);
		fileWriter << (unsigned char) r;
		//cout << "R, " << endl;
		//Write p (2bytes)
		fileWriter << (unsigned char) (p >> 8);
		fileWriter << (unsigned char) p;
		//cout << "P, " << endl;
		//Write opsLimit (8bytes)
		for (unsigned short i = 8; i > 0; i--){
			fileWriter << (unsigned char) (opsLimit >> (8 * (i - 1)));
		}
		//cout << "OpsLimit" << endl;
		//Write saltSize (2bytes)
		unsigned short saltSize = 8;
		//cout << "Salt size: " << saltSize << endl;
		fileWriter << (unsigned char) (saltSize >> 8);
		fileWriter << (unsigned char) saltSize;
		//Write nonceSize (2bytes)
		unsigned short nonceSize = crypto_secretbox_NONCEBYTES;
		//cout << "Nonce size: " << nonceSize << endl;
		fileWriter << (unsigned char) (nonceSize >> 8);
		fileWriter << (unsigned char) nonceSize;
		//Write keyBufferSize (4bytes)
		unsigned short keyBufferSize = keyBufferStr.length() + crypto_secretbox_MACBYTES;
		//cout << "Encrypted buffer size: " << keyBufferSize << endl;
		for (unsigned short i = 4; i > 0; i--){
			fileWriter << (unsigned char) (keyBufferSize >> (8 * (i - 1)));
		}
		//fileWriter << (unsigned char) (keyBufferSize >> 8);
		//fileWriter << (unsigned char) keyBufferSize;
		//Generate salt
		unsigned char* salt = new unsigned char[saltSize];
		randombytes_buf(salt, saltSize);
		//Write salt
		for (unsigned short i = 0; i < saltSize; i++) fileWriter << ((unsigned char) salt[i]);
		//Generate nonce
		unsigned char* nonce = new unsigned char[nonceSize];
		randombytes_buf(nonce, nonceSize);
		//Write nonce
		for (unsigned short i = 0; i < nonceSize; i++) fileWriter << ((unsigned char) nonce[i]);
		//Derive password
		unsigned short derivedKeySize = 32;
		unsigned char* derivedKey = new unsigned char[derivedKeySize];
		crypto_pwhash_scryptsalsa208sha256_ll(password, passwordSize, salt, saltSize, opsLimit, r, p, derivedKey, derivedKeySize);

		//Encrypt
		unsigned char* encryptedKey = new unsigned char[keyBufferSize];
		crypto_secretbox_easy(encryptedKey, (unsigned char*) keyBufferStr.c_str(), keyBufferStr.length(), nonce, derivedKey);
		//Write the encrypted key
		for (unsigned long i = 0; i < keyBufferSize; i++) fileWriter << ((unsigned char) encryptedKey[i]);

		delete salt;
		delete nonce;
		delete derivedKey;
		delete encryptedKey;

	} else {
		//cout << "No password has been provided" << endl;
		fileWriter << keyBufferStr;
	}
	fileWriter.close();

	/*if (keyType == "curve25519"){
		//Writing key type
		fileWriter << (unsigned char) 0x05;
		//Writing public key length
		fileWriter << (unsigned char) (crypto_box_PUBLICKEYBYTES >> 8);
		fileWriter << (unsigned char) (crypto_box_PUBLICKEYBYTES);
		//Writing public key
		for (unsigned int i = 0; i < crypto_box_PUBLICKEYBYTES; i++){
			fileWriter << (unsigned char) publicKey[i];
		}
		//Writing private key length
		fileWriter << (unsigned char) (crypto_box_SECRETKEYBYTES >> 8);
		fileWriter << (unsigned char) (crypto_box_SECRETKEYBYTES);
		//Writing the private key
		for (unsigned int i = 0; i < crypto_box_SECRETKEYBYTES; i++){
			fileWriter << (unsigned char) privateKey[i];
		}
	} else if (keyType == "ed25519"){
		//Writing key type
		fileWriter << (unsigned char) 0x06;
		//Writing public key length
		fileWriter << (unsigned char) (crypto_sign_PUBLICKEYBYTES >> 8);
		fileWriter << (unsigned char) (crypto_sign_PUBLICKEYBYTES);
		//Writing the public key
		for (unsigned int i = 0; i < crypto_sign_PUBLICKEYBYTES; i++){
			fileWriter << (unsigned char) publicKey[i];
		}
		//Writing private key length
		fileWriter << (unsigned char) (crypto_sign_SECRETKEYBYTES >> 8);
		fileWriter << (unsigned char) (crypto_sign_SECRETKEYBYTES);
		//Writing the private key
		for (unsigned int i = 0; i < crypto_sign_SECRETKEYBYTES; i++){
			fileWriter << (unsigned char) privateKey[i];
		}
	} else throw new runtime_error("Unknown key type: " + keyType);
	fileWriter.close();*/
}

void KeyRing::loadKeyPair(string const& filename, string* keyType, unsigned char* privateKey, unsigned char* publicKey, const unsigned char* password, const size_t passwordSize, unsigned long opsLimitBeforeException){
	fstream fileReader(filename.c_str(), ios::in);
	filebuf* fileBuffer = fileReader.rdbuf();
	string keyStr = "";
	while(fileBuffer->in_avail() > 0){
		keyStr += (char) fileBuffer->sbumpc();
	}
	fileReader.close();

	if (passwordSize > 0){
		/* Encrypted key file format. Numbers are in big endian
		* 1 byte : key type. 0x05 for Curve25519, 0x06 for Ed25519
		* 2 bytes : r (unsigned short)
		* 2 bytes : p (unsigned short)
		* 8 bytes : opsLimit (unsigned long)
		* 2 bytes: salt size (sn, unsigned short)
		* 2 bytes : nonce size (ss, unsigned short)
		* 4 bytes : key buffer size (x, unsigned long)
		* sn bytes: salt
		* ss bytes : nonce
		* x bytes : encrypted key buffer
		*/

		//Variable that will be used to check the size of the file; that it corresponds to what the file is supposed to contain.
		//With this technique, trying to avoid buffer overflows and potential RCEs that might come with them
		unsigned short minRemainingSize = 21; //17 bytes from the above description + 4 bytes of the MAC of the encrypted key buffer

		/*string encryptedKeyFileBuffer;
		getline(fileReader, encryptedKeyFileBuffer);
		fileReader.close();*/

		stringstream encryptedKeyStream(keyStr);
		stringbuf* buf = encryptedKeyStream.rdbuf();

		if (buf->in_avail() < minRemainingSize) throw new runtime_error("corrupted key file");

		//Reading key type
		char keyTypeChar = buf->sbumpc(); //Key type. Checking its a valid value, instead of simply discarding it.
		if (!(keyTypeChar == 0x05 || keyTypeChar == 0x06)){
			throw new runtime_error("invalid key type");
		}
		minRemainingSize--;

		//Reading r
		unsigned short r;
		r = ((unsigned short) buf->sbumpc()) << 8;
		r += (unsigned short) buf->sbumpc();
		minRemainingSize -= 2;

		//Reading p
		unsigned short p;
		p = ((unsigned short) buf->sbumpc()) << 8;
		p += (unsigned short) buf->sbumpc();
		minRemainingSize -= 2;

		//Reading opsLimit, N
		unsigned long long opsLimit = 0;
		for (int i = 7; i >= 0; i--){
			opsLimit += ((unsigned long long) buf->sbumpc()) << (8 * i);
		}
		minRemainingSize -= 8;
		// No need to check it (remainingSize condition) here. Need to check for correct available bytes after reading a variable length field, (or before reading the field itself but after reading the field's size, as done above with the salt)

		//Check that N is within the user given limit
		if (opsLimit > opsLimitBeforeException){
			throw new runtime_error("Key file asks for more scrypt derivations than is allowed");
		}

		//Reading salt size
		unsigned short saltSize;
		saltSize = ((unsigned short) buf->sbumpc()) << 8;
		saltSize += (unsigned short) buf->sbumpc();
		minRemainingSize -= 2;
		minRemainingSize += saltSize;
		//cout << "Available bytes after reading salt size: " << buf->in_avail() << endl;
		//cout << "minRemainingSize: " << minRemainingSize << endl;
		if (buf->in_avail() < minRemainingSize) throw new runtime_error("corrupted key file");

		//Reading nonce size
		unsigned short nonceSize;
		nonceSize = ((unsigned short) buf->sbumpc()) << 8;
		nonceSize += (unsigned short) buf->sbumpc();
		minRemainingSize -= 2;
		minRemainingSize += nonceSize;
		//cout << "Available bytes after reading nonce size: " << buf->in_avail() << endl;
		//cout << "minRemainingSize: " << minRemainingSize << endl;
		if (buf->in_avail() < minRemainingSize) throw new runtime_error("corrupted key file");

		if (nonceSize != crypto_secretbox_NONCEBYTES){
			throw new runtime_error("Invalid nonce size");
		}

		//Reading encrypted key buffer size
		unsigned long keyBufferSize = 0;
		for (int i = 3; i >= 0; i--){
			keyBufferSize += ((unsigned long) buf->sbumpc()) << (8 * i);
			//cout << "I : " << i << endl;
		}
		minRemainingSize -= 4;
		minRemainingSize += keyBufferSize;
		if (buf->in_avail() < minRemainingSize) throw new runtime_error("corrupted key file");

		//Reading salt
		unsigned char* salt = new unsigned char[saltSize];
		for (int i = 0; i < saltSize; i++){
			salt[i] = (unsigned char) buf->sbumpc();
		}
		minRemainingSize -= saltSize;

		unsigned char* nonce = new unsigned char[nonceSize];
		for (int i = 0; i < nonceSize; i++){
			nonce[i] = (unsigned char) buf->sbumpc();
		}
		minRemainingSize -= nonceSize;

		unsigned int encryptedKeyLength = buf->in_avail();
		unsigned char* encryptedKey = new unsigned char[encryptedKeyLength];
		for (unsigned long i = 0; i < keyBufferSize; i++){
			encryptedKey[i] = (unsigned char) buf->sbumpc();
		}
		minRemainingSize -= keyBufferSize;

		unsigned short keySize = 32;
		unsigned char* derivedKey = new unsigned char[keySize];

		crypto_pwhash_scryptsalsa208sha256_ll(password, passwordSize, salt, saltSize, opsLimit, r, p, derivedKey, keySize);

		unsigned int keyPlainTextLength = encryptedKeyLength - crypto_secretbox_MACBYTES;
		unsigned char* keyPlainText = new unsigned char[keyPlainTextLength];

		if (crypto_secretbox_open_easy(keyPlainText, encryptedKey, encryptedKeyLength, nonce, derivedKey) != 0){
			throw new runtime_error("Invalid password or corrupted key file");
		}

		if (buf->in_avail() > 0) cout << "Key file loaded. However there are some \"left over bytes\"" << endl;

		decodeKeyBuffer(string((char*) keyPlainText, keyPlainTextLength), keyType, privateKey, publicKey);

		delete salt;
		delete nonce;
		delete encryptedKey;
		delete derivedKey;
		delete keyPlainText;

	} else {
		decodeKeyBuffer(keyStr, keyType, privateKey, publicKey);
	}

	/*stringstream keyStream(keyStr);
	stringbuf* buffer = keyStream.rdbuf();*/
	//Declaring the keyPair map
	//map<string, string>* keyPair;
	//Reading the keytype
	/*char _keyType = buffer->sbumpc();
	if (!(_keyType == 0x05 || _keyType == 0x06)){ //Checking that the key type is valid
		stringstream errMsg;
		errMsg << "Invalid key type: " << (int) _keyType;
		throw new runtime_error(errMsg.str());
	}
	//keyPair = new map<string, string>();
	unsigned short publicKeyLength, privateKeyLength;
	if (_keyType == 0x05){ //Curve25519
		//Getting public key length
		publicKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicKeyLength += (unsigned short) buffer->sbumpc();
		if (publicKeyLength != crypto_box_PUBLICKEYBYTES){ //Checking key length
			stringstream errMsg;
			errMsg << "Invalid public key length : " << publicKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting public key
		for (unsigned int i = 0; i < publicKeyLength; i++){
			publicKey[i] = buffer->sbumpc();
		}
		//Getting private key length
		privateKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateKeyLength += (unsigned short) buffer->sbumpc();
		if (privateKeyLength != crypto_box_SECRETKEYBYTES){ //Checking key length
			stringstream errMsg;
			errMsg << "Invalid private key length : " << privateKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting private key
		for (unsigned int i = 0; i < privateKeyLength; i++){
			privateKey[i] = buffer->sbumpc();
		}
		//Building keypair map
		*keyType = "curve25519";
	} else if (_keyType == 0x06){ //Ed25519
		//Getting public key length
		publicKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicKeyLength += (unsigned short) buffer->sbumpc();
		if (publicKeyLength != crypto_sign_PUBLICKEYBYTES){ //Checking key length
			stringstream errMsg;
			errMsg << "Invalid public key length : " << publicKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting public key
		for (unsigned int i = 0; i < publicKeyLength; i++){
			publicKey[i] = buffer->sbumpc();
		}
		//Getting private key length
		privateKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateKeyLength += (unsigned short) buffer->sbumpc();
		if (privateKeyLength != crypto_sign_SECRETKEYBYTES){ //Cheking key length
			stringstream errMsg;
			errMsg << "Invalid private key length : " << privateKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting private key
		for (unsigned int i = 0; i < privateKeyLength; i++){
			privateKey[i] = buffer->sbumpc();
		}
		//Building keypair map
		*keyType = "ed25519";
	}*/
}

void KeyRing::decodeKeyBuffer(std::string const& keyBuffer, std::string* keyType, unsigned char* privateKey, unsigned char* publicKey){
	stringstream keyStream(keyBuffer);
	stringbuf* buffer = keyStream.rdbuf();

	/*
	* 1 byte for key type. 0x05 for curve25519, 0x06 for Ed25519
	* 2 bytes for public key length (pubL, unsigned short, BE)
	* pubL bytes for public key
	* 2 bytes for private key length (secL, unsigned short, BE)
	* secL bytes for private key
	*/
	unsigned short minRemainingSize = 5;

	//cout << "decoding buffer: " << strToHex(keyBuffer) << endl;

	if (buffer->in_avail() < minRemainingSize) throw new runtime_error("corrupted key file");

	char _keyType = buffer->sbumpc();
	minRemainingSize--;

	if (!(_keyType == 0x05 || _keyType == 0x06)){ //Checking that the key type is valid
		stringstream errMsg;
		errMsg << "Invalid key type: " << (int) _keyType;
		throw new runtime_error(errMsg.str());
	}

	unsigned short publicKeyLength, privateKeyLength;
	if (_keyType == 0x05){ //Curve25519
		//Getting public key length
		publicKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicKeyLength += (unsigned short) buffer->sbumpc();
		//Checking size validity
		minRemainingSize -= 2;
		if (buffer->in_avail() < minRemainingSize + publicKeyLength) throw new runtime_error("corrupted key file");

		if (publicKeyLength != crypto_box_PUBLICKEYBYTES){ //Checking key length
			stringstream errMsg;
			errMsg << "Invalid public key length : " << publicKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting public key
		for (unsigned int i = 0; i < publicKeyLength; i++){
			publicKey[i] = buffer->sbumpc();
		}

		//Getting private key length
		privateKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateKeyLength += (unsigned short) buffer->sbumpc();
		//Checking size validity
		minRemainingSize -= 2;
		if (buffer->in_avail() < minRemainingSize + privateKeyLength) throw new runtime_error("corrupted key file");

		if (privateKeyLength != crypto_box_SECRETKEYBYTES){ //Checking key length
			stringstream errMsg;
			errMsg << "Invalid private key length : " << privateKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting private key
		for (unsigned int i = 0; i < privateKeyLength; i++){
			privateKey[i] = buffer->sbumpc();
		}

		//Building keypair map
		*keyType = "curve25519";
	} else if (_keyType == 0x06){ //Ed25519
		//Getting public key length
		publicKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicKeyLength += (unsigned short) buffer->sbumpc();
		//Checking size validity
		minRemainingSize -= 2;
		if (buffer->in_avail() < minRemainingSize + publicKeyLength) throw new runtime_error("corrupted key file");

		if (publicKeyLength != crypto_sign_PUBLICKEYBYTES){ //Checking key length
			stringstream errMsg;
			errMsg << "Invalid public key length : " << publicKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting public key
		for (unsigned int i = 0; i < publicKeyLength; i++){
			publicKey[i] = buffer->sbumpc();
		}

		//Getting private key length
		privateKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateKeyLength += (unsigned short) buffer->sbumpc();
		//Checking size validity
		minRemainingSize -= 2;
		if (buffer->in_avail() < minRemainingSize + privateKeyLength) throw new runtime_error("corrupted key file");

		if (privateKeyLength != crypto_sign_SECRETKEYBYTES){ //Cheking key length
			stringstream errMsg;
			errMsg << "Invalid private key length : " << privateKeyLength;
			throw new runtime_error(errMsg.str());
		}
		//Getting private key
		for (unsigned int i = 0; i < privateKeyLength; i++){
			privateKey[i] = buffer->sbumpc();
		}

		//Building keypair map
		*keyType = "ed25519";
	}
	if (buffer->in_avail() > 0) cout << "Key buffer loaded. However there are some \"left over bytes\"" << endl;
}

std::string KeyRing::encodeKeyBuffer(std::string const& keyType, const unsigned char* privateKey, const unsigned char* publicKey){
	stringstream s;

	if (keyType == "curve25519"){
		//Writing key type
		s << (unsigned char) 0x05;
		//Writing public key length
		s << (unsigned char) (crypto_box_PUBLICKEYBYTES >> 8);
		s << (unsigned char) (crypto_box_PUBLICKEYBYTES);
		//Writing public key
		for (unsigned int i = 0; i < crypto_box_PUBLICKEYBYTES; i++){
			s << (unsigned char) publicKey[i];
		}
		//Writing private key length
		s << (unsigned char) (crypto_box_SECRETKEYBYTES >> 8);
		s << (unsigned char) (crypto_box_SECRETKEYBYTES);
		//Writing the private key
		for (unsigned int i = 0; i < crypto_box_SECRETKEYBYTES; i++){
			s << (unsigned char) privateKey[i];
		}
	} else if (keyType == "ed25519"){
		//Writing key type
		s << (unsigned char) 0x06;
		//Writing public key length
		s << (unsigned char) (crypto_sign_PUBLICKEYBYTES >> 8);
		s << (unsigned char) (crypto_sign_PUBLICKEYBYTES);
		//Writing the public key
		for (unsigned int i = 0; i < crypto_sign_PUBLICKEYBYTES; i++){
			s << (unsigned char) publicKey[i];
		}
		//Writing private key length
		s << (unsigned char) (crypto_sign_SECRETKEYBYTES >> 8);
		s << (unsigned char) (crypto_sign_SECRETKEYBYTES);
		//Writing the private key
		for (unsigned int i = 0; i < crypto_sign_SECRETKEYBYTES; i++){
			s << (unsigned char) privateKey[i];
		}
	} else throw new runtime_error("Unknown key type: " + keyType);
	return s.str();
}
