#ifndef KEYRING_H
#define KEYRING_H

#include <string>
#include <map>

#include <node.h>

class KeyRing : public node::ObjectWrap{

public:
	static void Init(v8::Handle<v8::Object> exports);

private:
	explicit KeyRing(std::string const& filename = "", unsigned char* password = 0, size_t passwordSize = 0);
	~KeyRing();
	//Internal attributes
	//std::map<std::string, std::string>* keyPair;
	std::string _filename;
	unsigned char* _privateKey;
	unsigned char* _publicKey;
	std::string _keyType;
	bool _keyLock;
	/*
	* Internal methods
	*/
	static std::string strToHex(std::string const& s);
	static std::string hexToStr(std::string const& s);
	//static std::map<std::string, std::string>* edwardsToMontgomery(std::map<std::string, std::string>* edwards);

	//File methods
	static void loadKeyPair(std::string const& filename, std::string* keyType, unsigned char* privateKey, unsigned char* publicKey, const unsigned char* password = 0, const size_t passwordSize = 0, unsigned long opsLimitBeforeException = 4194304);
	static void saveKeyPair(std::string const& filename, std::string const& keyType, const unsigned char* privateKey, const unsigned char* publicKey, const unsigned char* password = 0, const size_t passwordSize = 0, const unsigned long opsLimit = 16384, const unsigned int r = 8, const unsigned int p = 1);
	static bool doesFileExist(std::string const& filename);
	static void decodeKeyBuffer(std::string const& keyBuffer, std::string* keyType, unsigned char* privateKey, unsigned char* publicKey);
	static std::string encodeKeyBuffer(std::string const& keyType, const unsigned char* privateKey, const unsigned char* publicKey);

	//private PubKeyInfo object constructor
	v8::Local<v8::Object> PPublicKeyInfo();


	/*
	* JS Methods
	*/
	static v8::Handle<v8::Value> New(const v8::Arguments& args);
	static v8::Handle<v8::Value> Encrypt(const v8::Arguments& args);
	static v8::Handle<v8::Value> Decrypt(const v8::Arguments& args);
	static v8::Handle<v8::Value> Sign(const v8::Arguments &args);
	static v8::Handle<v8::Value> Agree(const v8::Arguments &args);
	static v8::Handle<v8::Value> PublicKeyInfo(const v8::Arguments& args);
	static v8::Handle<v8::Value> CreateKeyPair(const v8::Arguments& args);
	static v8::Handle<v8::Value> Load(const v8::Arguments& args);
	static v8::Handle<v8::Value> Save(const v8::Arguments& args);
	static v8::Handle<v8::Value> Clear(const v8::Arguments& args);
	static v8::Handle<v8::Value> SetKeyBuffer(const v8::Arguments& args);
	static v8::Handle<v8::Value> GetKeyBuffer(const v8::Arguments& args);
	static v8::Handle<v8::Value> LockKeyBuffer(const v8::Arguments& args);
	static v8::Persistent<v8::Function> constructor;
};

#endif
