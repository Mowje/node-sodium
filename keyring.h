#ifndef KEYRING_H
#define KEYRING_H

#include <string>

#include <node.h>
#include <nan.h>

class KeyRing : public node::ObjectWrap{

public:
	//static void Init(v8::Handle<v8::Object> exports);
	static NAN_MODULE_INIT(Init);

private:
	explicit KeyRing(std::string const& filename = "", unsigned char* password = 0, size_t passwordSize = 0);
	~KeyRing();
	//Internal attributes
	std::string _filename;
	unsigned char* _privateKey;
	unsigned char* _publicKey;
	unsigned char* _altPrivateKey;
	unsigned char* _altPublicKey;
	std::string _keyType;
	bool _keyLock;
	v8::Local<v8::Object> globalObj;
	v8::Local<v8::Function> bufferConstructor;
	/*
	* Internal methods
	*/
	static std::string strToHex(std::string const& s);
	static std::string hexToStr(std::string const& s);

	//File methods
	static void loadKeyPair(std::string const& filename, std::string* keyType, unsigned char* privateKey, unsigned char* publicKey, const unsigned char* password = 0, const size_t passwordSize = 0, unsigned long opsLimitBeforeException = 4194304);
	static void saveKeyPair(std::string const& filename, std::string const& keyType, const unsigned char* privateKey, const unsigned char* publicKey, const unsigned char* password = 0, const size_t passwordSize = 0, const unsigned long opsLimit = 16384, const unsigned int r = 8, const unsigned int p = 1);
	static bool doesFileExist(std::string const& filename);
	static void decodeKeyBuffer(std::string const& keyBuffer, std::string* keyType, unsigned char* privateKey, unsigned char* publicKey);
	static std::string encodeKeyBuffer(std::string const& keyType, const unsigned char* privateKey, const unsigned char* publicKey);
	static void deriveAltKeys(unsigned char* edPub, unsigned char* edSec, unsigned char* cPub, unsigned char* cSec); //Called whenever an Ed25519 key is loaded/generated. Used to calculate the Curve25519 version of it and put in memory

	//private PubKeyInfo object constructor
	v8::Local<v8::Object> PPublicKeyInfo();

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}

	/*
	* JS Methods
	*/
	static NAN_METHOD(New);
	static NAN_METHOD(Encrypt);
	static NAN_METHOD(Decrypt);
	static NAN_METHOD(Sign);
	static NAN_METHOD(Agree);
	static NAN_METHOD(PublicKeyInfo);
	static NAN_METHOD(CreateKeyPair);
	static NAN_METHOD(Load);
	static NAN_METHOD(Save);
	static NAN_METHOD(Clear);
	static NAN_METHOD(SetKeyBuffer);
	static NAN_METHOD(GetKeyBuffer);
	static NAN_METHOD(LockKeyBuffer);
};

#endif
