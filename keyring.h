#ifndef KEYRING_H
#define KEYRING_H

#include <string>
#include <map>

#include <node.h>

class KeyRing : public node::ObjectWrap{

public:
	static void Init(v8::Handle<v8::Object> exports);

private:
	explicit KeyRing(std::string filename = "");
	~KeyRing();
	//Internal attributes
	std::map<std::string, std::string>* keyPair;
	std::string filename_;
	/*
	* Internal methods
	*/
	static std::string strToHex(std::string const& s);
	static std::string hexToStr(std::string const& s);
	//static std::map<std::string, std::string>* edwardsToMontgomery(std::map<std::string, std::string>* edwards);

	//File methods
	static std::map<std::string, std::string>* loadKeyPair(std::string const& filename);
	static void saveKeyPair(std::string const& filename, std::map<std::string, std::string>* keyPair);
	static bool doesFileExist(std::string const& filename);

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
	static v8::Persistent<v8::Function> constructor;
};

#endif