/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include <node.h>
#include <node_buffer.h>

#include <cstdlib>
#include <ctime>
#include <cmath>
//#include <cstdint> //Is it needed?
#include <cstring>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>

#include "sodium.h"

#include "keyring.h"

using namespace node;
using namespace v8;

// Check if a function argument is a node Buffer. If not throw V8 exception
#define ARG_IS_BUFFER(i,msg) \
    if (!Buffer::HasInstance(args[i])) { \
        std::ostringstream oss; \
        oss << "argument " << msg << " must be a buffer"; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

#define NEW_BUFFER_AND_PTR(name, size) \
    Buffer* name = Buffer::New(size); \
    Local<Object> name ## _handle = Local<Object>::New(name->handle_); \
    unsigned char* name ## _ptr = (unsigned char*)Buffer::Data(name ## _handle)

#define GET_ARG_AS(i, NAME, TYPE) \
    ARG_IS_BUFFER(i,#NAME); \
    TYPE NAME = (TYPE) Buffer::Data(args[i]->ToObject()); \
    unsigned long long NAME ## _size = Buffer::Length(args[i]->ToObject()); \
    if( NAME ## _size == 0 ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " length cannot be zero" ; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

#define GET_ARG_AS_LEN(i, NAME, MAXLEN, TYPE) \
    GET_ARG_AS(i, NAME, TYPE); \
    if( NAME ## _size != MAXLEN ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " must be " << MAXLEN << " bytes long" ; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

#define GET_ARG_AS_UCHAR(i, NAME) \
    GET_ARG_AS(i, NAME, unsigned char*)

#define GET_ARG_AS_UCHAR_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, unsigned char*)

#define GET_ARG_AS_VOID(i, NAME) \
    GET_ARG_AS(i, NAME, void*)

#define GET_ARG_AS_VOID_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, void*)


#define NUMBER_OF_MANDATORY_ARGS(n, message) \
    if (args.Length() < (n)) {                \
        return V8Exception(message);          \
    }

//Helper function
static Handle<Value> V8Exception(const char* msg) {
    return ThrowException(Exception::Error(String::New(msg)));
}

// Lib Sodium Version Functions
Handle<Value> bind_sodium_version_string(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        String::New(sodium_version_string())
    );
}

Handle<Value> bind_sodium_library_version_minor(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        Integer::New(sodium_library_version_minor())
    );
}

Handle<Value> bind_sodium_library_version_major(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        Integer::New(sodium_library_version_major())
    );
}

// Lib Sodium Utils
Handle<Value> bind_memzero(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");
    GET_ARG_AS_VOID(0, buffer);
    sodium_memzero(buffer, buffer_size);
    return scope.Close(Null());
}

/**
 * int sodium_memcmp(const void * const b1_, const void * const b2_, size_t size);
 */
Handle<Value> bind_memcmp(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"argument must be a buffer");

    GET_ARG_AS_VOID(0, buffer_1);
    GET_ARG_AS_VOID(1, buffer_2);

    size_t size;
    if (args[2]->IsUint32()) {
        size = args[2]->Int32Value();
    } else {
        return V8Exception("argument size must be a positive number");
    }

    size_t s = (buffer_1_size < buffer_2_size)? buffer_1_size : buffer_2_size;

    if( s < size ) {
        size = s;
    }

    return scope.Close(Integer::New(sodium_memcmp(buffer_1, buffer_2, size)));
}

/**
 * char *sodium_bin2hex(char * const hex, const size_t hexlen,
 *                    const unsigned char *bin, const size_t binlen);
 */
Handle<Value> bind_sodium_bin2hex(const Arguments& args) {
    HandleScope scope;
    return V8Exception("use node's native Buffer.toString()");
}

// Lib Sodium Random

// void randombytes_buf(void *const buf, const size_t size)
Handle<Value> bind_randombytes_buf(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");

    GET_ARG_AS_VOID(0, buffer);
    randombytes_buf(buffer, buffer_size);
    return scope.Close(Null());
}

// void randombytes_stir()
Handle<Value> bind_randombytes_stir(const Arguments& args) {
    HandleScope scope;
    randombytes_stir();
    return scope.Close(Null());
}

Handle<Value> bind_randombytes_close(const Arguments& args) {
    HandleScope scope;

    // int randombytes_close()
    return scope.Close(Integer::New(randombytes_close()));
}

Handle<Value> bind_randombytes_random(const Arguments& args) {
    HandleScope scope;

    // uint_32 randombytes_random()
    return scope.Close(Uint32::New(randombytes_random()));
}

Handle<Value> bind_randombytes_uniform(const Arguments& args) {
    HandleScope scope;
    uint32_t upper_bound;

    NUMBER_OF_MANDATORY_ARGS(1,"argument size must be a positive number");

    if (args[0]->IsUint32()) {
        upper_bound = args[0]->Int32Value();
    } else {
        return V8Exception("argument size must be a positive number");
    }

    // uint32_t randombytes_uniform(const uint32_t upper_bound)
    return scope.Close(Uint32::New(randombytes_uniform(upper_bound)));
}


Handle<Value> bind_crypto_verify_16(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be two buffers");

    GET_ARG_AS_UCHAR_LEN(0,string1, crypto_verify_16_BYTES);
    GET_ARG_AS_UCHAR_LEN(1,string2, crypto_verify_16_BYTES);

    return scope.Close(Integer::New(crypto_verify_16(string1, string2)));
}

// int crypto_verify_16(const unsigned char * string1, const unsigned char * string2)
Handle<Value> bind_crypto_verify_32(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be two buffers");

    GET_ARG_AS_UCHAR_LEN(0,string1, crypto_verify_32_BYTES);
    GET_ARG_AS_UCHAR_LEN(1,string2, crypto_verify_32_BYTES);

    return scope.Close(Integer::New(crypto_verify_32(string1, string2)));
}

/**
 * int crypto_shorthash(
 *    unsigned char *out,
 *    const unsigned char *in,
 *    unsigned long long inlen,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] out    result of hash
 *    [in]  in     input buffer
 *    [in]  inlen  size of input buffer
 *    [in]  key    key buffer
 *
 * A lot of applications and programming language implementations have been
 * recently found to be vulnerable to denial-of-service attacks when a hash
 * function with weak security guarantees, like Murmurhash 3, was used to
 * construct a hash table.
 * In order to address this, Sodium provides the �shorthash� function,
 * currently implemented using SipHash-2-4. This very fast hash function
 * outputs short, but unpredictable (without knowing the secret key) values
 * suitable for picking a list in a hash table for a given key.
 */
Handle<Value> bind_crypto_shorthash(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");

    GET_ARG_AS_UCHAR(0,message);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_shorthash_KEYBYTES);

    NEW_BUFFER_AND_PTR(hash, crypto_shorthash_BYTES);

    if( crypto_shorthash(hash_ptr, message, message_size, key) == 0 ) {
        return scope.Close(hash->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_hash(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
Handle<Value> bind_crypto_hash(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");

    GET_ARG_AS_UCHAR(0,msg);

    NEW_BUFFER_AND_PTR(hash, crypto_hash_BYTES);

    if( crypto_hash(hash_ptr, msg, msg_size) == 0 ) {
        return scope.Close(hash->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_hash_sha256(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
Handle<Value> bind_crypto_hash_sha256(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");
    GET_ARG_AS_UCHAR(0, msg);
    NEW_BUFFER_AND_PTR(hash, 32);

    if( crypto_hash_sha256(hash_ptr, msg, msg_size) == 0 ) {
        return scope.Close(hash->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_hash_sha512(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
Handle<Value> bind_crypto_hash_sha512(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");

    GET_ARG_AS_UCHAR(0, msg);

    NEW_BUFFER_AND_PTR(hash, 64);

    if( crypto_hash_sha512(hash_ptr, msg, msg_size) == 0 ) {
        return scope.Close(hash->handle_);
    }
    return scope.Close(Null());
}

/**
* int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
*                                      unsigned long long outlen,
*                                      const char * const passwd,
*                                      unsigned long long passwdlen,
*                                      const unsigned char * const salt,
*                                      unsigned long long opslimit,
*                                      size_t memlimit);
*/
Handle<Value> bind_crypto_pwhash_scryptsalsa208sha256(const Arguments& args){
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3, "arguments password and salt must be buffers; keyLength, opslimit and memlimit must be integers");

    GET_ARG_AS_UCHAR(0, password);
    GET_ARG_AS_UCHAR_LEN(1, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

    unsigned int keyLength = 32;
    unsigned long long opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
    size_t memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;

    //Get the key length parameter
    if (args.Length() >= 3 && !(args[2]->IsUndefined() || args[2]->IsNull())){
        if (!args[2]->IsNumber()){
            ThrowException(Exception::TypeError(String::New("when defined, keyLength must be a positive integer")));
            return scope.Close(Undefined());
        } else {
            int keyLengthArg = args[2]->Int32Value();
            //Check parameter value
            if (keyLengthArg <= 0){
                ThrowException(Exception::RangeError(String::New("when defined, keyLength must be a positive integer")));
                return scope.Close(Undefined());
            }
            keyLength = (unsigned int) keyLengthArg;
        }
    }

    //Get the opslimit parameter
    if (args.Length() >= 4 && !(args[3]->IsUndefined() || args[3]->IsNull())){
        if (!args[3]->IsNumber()){
            ThrowException(Exception::TypeError(String::New("when defined, opslimit must be a positive integer")));
            return scope.Close(Undefined());
        } else {
            long long opslimitArg = args[3]->IntegerValue();
            //Check parameter value
            if (opslimitArg <= 0){
                ThrowException(Exception::RangeError(String::New("when defined, opslimit must be a positive integer")));
                return scope.Close(Undefined());
            }
            opslimit = opslimitArg;
        }
    }

    //Get the memlimit parameter
    if (args.Length() >= 5 && !(args[4]->IsUndefined() || args[4]->IsNull())){
        if (!args[4]->IsNumber()){
            ThrowException(Exception::TypeError(String::New("when defined, memlimit must be a positive integer")));
            return scope.Close(Undefined());
        } else {
            size_t memlimitArg = args[4]->IntegerValue();
            //Check parameter value
            if (memlimitArg <= 0){
                ThrowException(Exception::RangeError(String::New("when defined, memlimit must be a positive integer")));
                return scope.Close(Undefined());
            }
            memlimit = memlimitArg;
        }
    }

    NEW_BUFFER_AND_PTR(key, keyLength);

    if (crypto_pwhash_scryptsalsa208sha256(key_ptr, keyLength, (char*) password, password_size, salt, opslimit, memlimit) != 0){
        ThrowException(Exception::Error(String::New("out of memory")));
        return scope.Close(Undefined());
    }
    return scope.Close(key_handle);

}

/**
* int crypto_pwhash_scryptsalsa208sha256_ll(const uint8_t * passwd, size_t passwdlen,
*                                      const uint8_t * salt, size_t saltlen,
*                                      uint64_t N, uint32_t r, uint32_t p,
*                                      uint8_t * buf, size_t buflen)
*/
Handle<Value> bind_crypto_pwhash_scryptsalsa208sha256_ll(const Arguments& args){
    HandleScope scope;
    // scrypt(pass, salt, opsLimit, r, p, keyLength)
    NUMBER_OF_MANDATORY_ARGS(2, "arguments password and salt must be a buffers");

    unsigned long long N = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
    unsigned int r = 8;
    unsigned int p = 1;
    unsigned int keyLength = 32;

    GET_ARG_AS_UCHAR(0, password);
    GET_ARG_AS_UCHAR(1, salt);

    if (args.Length() >= 3 && !(args[2]->IsUndefined() || args[2]->IsNull())){
        if (!args[2]->IsNumber()){
            ThrowException(Exception::TypeError(String::New("when defined, N must be a positive number")));
            return scope.Close(Undefined());
        } else {
            long long nArg = (long long) args[2]->IntegerValue();
            if (nArg <= 0){
                ThrowException(Exception::RangeError(String::New("when defined, N must be a positive number")));
                return scope.Close(Undefined());
            }
            N = (unsigned long long) nArg;
        }
    }

    if (args.Length() >= 4 && !(args[3]->IsUndefined() || args[3]->IsNull())){
        if (!args[3]->IsNumber()){
            ThrowException(Exception::TypeError(String::New("when defined, r must be a positive integer")));
            return scope.Close(Undefined());
        } else {
            int rArg = args[3]->Int32Value();
            if (rArg <= 0){
                ThrowException(Exception::RangeError(String::New("when defined, r must be a positive integer")));
                return scope.Close(Undefined());
            }
            r = (unsigned int) rArg;
        }
    }

    if (args.Length() >= 5 && !(args[4]->IsUndefined() || args[4]->IsNull())){
        if (!args[4]->IsNumber()){
            ThrowException(Exception::TypeError(String::New("when defined, p must be a positive integer")));
            return scope.Close(Undefined());
        } else {
            int pArg = args[4]->Int32Value();
            if (pArg <= 0){
                ThrowException(Exception::RangeError(String::New("when defined, p must be a positive integer")));
                return scope.Close(Undefined());
            }
            p = (unsigned int) pArg;
        }
    }

    if (args.Length() >= 6 && !(args[5]->IsUndefined() || args[5]->IsNull())){
        if (!args[5]->IsNumber()){
            ThrowException(Exception::TypeError(String::New("when defined, keyLength must be a positive integer")));
            return scope.Close(Undefined());
        } else {
            int keyLengthArg = args[5]->Int32Value();
            if (keyLengthArg <= 0){
                ThrowException(Exception::RangeError(String::New("when defined, keyLength must be a positive integer")));
                return scope.Close(Undefined());
            }
            keyLength = (unsigned int) keyLengthArg;
        }
    }

    NEW_BUFFER_AND_PTR(key, keyLength);

    if (crypto_pwhash_scryptsalsa208sha256_ll(password, password_size, salt, salt_size, N, r, p, key_ptr, keyLength) != 0){
        ThrowException(Exception::Error(String::New("out of memory")));
        return scope.Close(Undefined());
    }
    return scope.Close(key_handle);

}

/**
 * Password based file encryption with ease of use. scrypt + secretbox. Same format as for encrypted key files produced by KeyRing.save
 * Buffer fileContent
 * Buffer password
 * String filename //Transform it back into a string
 * Function callback
 *
 */
Handle<Value> pw_file_encrypt(const Arguments& args){
    HandleScope scope;
    Local<Object> globalObj = Context::GetCurrent()->Global();

    NUMBER_OF_MANDATORY_ARGS(3, "arguments fileContent, password and filename can't be null");

    if (args.Length() > 3){
        if (!args[3]->IsFunction()){
            ThrowException(Exception::TypeError(String::New("When defined, callback must be a function")));
            return scope.Close(Undefined());
        }
    }

    GET_ARG_AS_UCHAR(0, fileContent);
    GET_ARG_AS_UCHAR(1, password);
    String::Utf8Value filenameVal(args[2]);
    std::string filename(*filenameVal);

    //std::string filename((char*)filenameBuffer, filenameBuffer_size);
    unsigned int r = 8;
    unsigned int p = 1;
    unsigned long long opsLimit = 16384;
    unsigned short saltSize = 8;
    unsigned short nonceSize = crypto_secretbox_NONCEBYTES;

    std::fstream fileWriter(filename.c_str(), std::ios::out | std::ios::trunc);

    //Writing r
    fileWriter << (unsigned char) (r >> 8);
    fileWriter << (unsigned char) r;
    //Writing p
    fileWriter << (unsigned char) (p >> 8);
    fileWriter << (unsigned char) p;
    //Writing opsLimit
    for (unsigned short i = 8; i > 0; i--){
        fileWriter << (unsigned char) (opsLimit >> (8 * (i - 1)));
    }
    //Writing saltSize
    fileWriter << (unsigned char) (saltSize >> 8);
    fileWriter << (unsigned char) saltSize;
    //Writing nonceSize
    fileWriter << (unsigned char) (nonceSize >> 8);
    fileWriter << (unsigned char) nonceSize;
    //Writing content size
    unsigned int contentBufferSize = fileContent_size + crypto_secretbox_MACBYTES;
    for (unsigned short i = 4; i > 0; i--){
        fileWriter << (unsigned char) (contentBufferSize >> (8 * (i - 1)));
    }
    //Generate salt and write it
    unsigned char* salt = new unsigned char[saltSize];
    randombytes_buf(salt, saltSize);
    for (unsigned short i = 0; i < saltSize; i++) fileWriter << ((unsigned char) salt[i]);
    //Generate nonce and write it
    unsigned char* nonce = new unsigned char[nonceSize];
    randombytes_buf(nonce, nonceSize);
    for (unsigned short i = 0; i < nonceSize; i++) fileWriter << ((unsigned char) nonce[i]);
    //Derive password into key
    unsigned short derivedKeySize = crypto_secretbox_KEYBYTES;
    unsigned char* derivedKey = new unsigned char[derivedKeySize];
    crypto_pwhash_scryptsalsa208sha256_ll(password, password_size, salt, saltSize, opsLimit, r, p, derivedKey, derivedKeySize);

    //Encrypt fileContent and write it
    unsigned char* encryptedContent = new unsigned char[contentBufferSize];
    crypto_secretbox_easy(encryptedContent, fileContent, fileContent_size, nonce, derivedKey);
    for (unsigned long i = 0; i < contentBufferSize; i++){
        fileWriter << ((unsigned char) encryptedContent[i]);
    }

    //Close and clean up
    fileWriter.close();

    sodium_memzero(salt, saltSize);
    sodium_memzero(nonce, nonceSize);
    sodium_memzero(derivedKey, derivedKeySize);
    sodium_memzero(encryptedContent, contentBufferSize);

    delete salt;
    delete nonce;
    delete derivedKey;
    delete encryptedContent;

    salt = 0;
    nonce = 0;
    derivedKey = 0;
    encryptedContent = 0;

    //Either callback or return undefined
    if (args.Length() > 3){
        Local<Function> callback = Local<Function>::Cast(args[3]);
        const int argc = 0;
        Local<Value> argv[argc];
        callback->Call(globalObj, argc, argv);
    }
    return scope.Close(Undefined());
}

/**
 * Password based file decryption with ease of use. scrypt + secretbox. Same format as for encrypted key files produced by KeyRing.save
 * String filename
 * Buffer password
 * Function callback
 *
 */
Handle<Value> pw_file_decrypt(const Arguments& args){
    HandleScope scope;
    //Local<Object> globalObj = Context::GetCurrent()->Global();

    //Local<Value> err;
    //const int argc = 2;

    NUMBER_OF_MANDATORY_ARGS(2, "arguments filename and password must be defined");

    if (args.Length() > 2){
        if (!args[2]->IsFunction()){
            ThrowException(Exception::TypeError(String::New("When defined, callback must be a function")));
            return scope.Close(Undefined());
        }
    }

    //GET_ARG_AS_UCHAR(0, filename);
    String::Utf8Value filenameVal(args[0]);
    std::string filename(*filenameVal);
    GET_ARG_AS_UCHAR(1, password);

    std::fstream fileReader(filename.c_str(), std::ios::in);
    std::string fileString = "";
    std::filebuf* fileBuffer = fileReader.rdbuf();
    while (fileBuffer->in_avail() > 0){
        fileString += (char) fileBuffer->sbumpc();
    }
    fileReader.close();

    std::stringstream fileStringStream(fileString);
    std::stringbuf* buf = fileStringStream.rdbuf();

    /* Encrypted file format. Numbers are in big endian
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
    unsigned short minRemainingSize = 20; //16 bytes from the above description + 4 bytes of the MAC of the encrypted key buffer
    const unsigned long opsLimitBeforeException = 4194304;

    if (buf->in_avail() < minRemainingSize){
        ThrowException(Exception::RangeError(String::New("Invalid file format")));
        return scope.Close(Undefined());
    }

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

    //Reading opsLimit
    unsigned long long opsLimit = 0;
    for (int i = 7; i >= 0; i--){
        opsLimit += ((unsigned long long) buf->sbumpc()) << (8 * i);
    }
    minRemainingSize -= 8;

    if (opsLimit > opsLimitBeforeException){
        ThrowException(Exception::RangeError(String::New("Encrypted key file asks from more scrypt iterations than is allowed")));
        return scope.Close(Undefined());
    }

    //Reading salt size
    unsigned short saltSize;
    saltSize = ((unsigned short) buf->sbumpc()) << 8;
    saltSize += (unsigned short) buf->sbumpc();
    minRemainingSize -= 2;
    minRemainingSize += saltSize;

    //Reading nonce size
    unsigned short nonceSize;
    nonceSize = ((unsigned short) buf->sbumpc()) << 8;
    nonceSize += (unsigned short) buf->sbumpc();
    minRemainingSize -= 2;
    minRemainingSize += nonceSize;

    if (buf->in_avail() < minRemainingSize){
        ThrowException(Exception::RangeError(String::New("Invalid encrypted file format")));
        return scope.Close(Undefined());
    }

    if (nonceSize != crypto_secretbox_NONCEBYTES){
        ThrowException(Exception::RangeError(String::New("Invalid nonce size")));
        return scope.Close(Undefined());
    }

    //Reading the supposed encrypted content length and check its validity
    unsigned int encryptedContentSize = 0;
    for (int i = 3; i >= 0; i--){
        encryptedContentSize += ((unsigned int) buf->sbumpc()) << (8 * i);
    }
    minRemainingSize -= 4;
    minRemainingSize += encryptedContentSize;

    if (buf->in_avail() < minRemainingSize){
        ThrowException(Exception::RangeError(String::New("Invalid encrypted file format")));
        return scope.Close(Undefined());
    }

    //Reading salt
    unsigned char* salt = new unsigned char[saltSize];
    for (int i = 0; i < saltSize; i++){
        salt[i] = (unsigned char) buf->sbumpc();
    }
    minRemainingSize -= saltSize;

    //Reading nonce
    unsigned char* nonce = new unsigned char[nonceSize];
    for (int i = 0; i < nonceSize; i++){
        nonce[i] = (unsigned char) buf->sbumpc();
    }
    minRemainingSize -= nonceSize;

    //Reading encrypted content
    //Length of the remaining data has already been checked before
    unsigned int encryptedContentLength = buf->in_avail();
    unsigned char* encryptedContent = new unsigned char[encryptedContentLength];
    for (unsigned long i = 0; i < encryptedContentSize; i++){
        encryptedContent[i] = (unsigned char) buf->sbumpc();
    }
    minRemainingSize -= encryptedContentSize;

    unsigned short keySize = 32;
    unsigned char* derivedKey = new unsigned char[keySize];

    //Deriving the password
    crypto_pwhash_scryptsalsa208sha256_ll(password, password_size, salt, saltSize, opsLimit, r, p, derivedKey, keySize);

    unsigned int plaintextLength = encryptedContentSize - crypto_secretbox_MACBYTES;
    NEW_BUFFER_AND_PTR(plaintext, plaintextLength);
    //unsigned char* plaintext = new unsigned char[plaintextLength];

    //Decryption
    if (crypto_secretbox_open_easy(plaintext_ptr, encryptedContent, encryptedContentSize, nonce, derivedKey) != 0){
        ThrowException(Exception::Error(String::New("Invalid password or corrupted file")));
        return scope.Close(Undefined());
    }

    //Memory clean up
    sodium_memzero(salt, saltSize);
    sodium_memzero(nonce, nonceSize);
    sodium_memzero(derivedKey, keySize);

    delete salt;
    delete nonce;
    delete derivedKey;

    salt = 0;
    nonce = 0;
    derivedKey = 0;

    /*if (args.Length() > 2){ //Callback has been provided
        Local<Function> callback = Local<Function>::Cast(args[2]);
        Local<Value> argv[argc] = {Undefined(), Local<Value>::New(plaintext->handle_)};
        callback->Call(globalObj, argc, argv);
        return scope.Close(Undefined());
    } else*/ return scope.Close(plaintext_handle);

}

/**
 * int crypto_auth(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
Handle<Value> bind_crypto_auth(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and key must be buffers");

    GET_ARG_AS_UCHAR(0, msg);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_auth_KEYBYTES);

    NEW_BUFFER_AND_PTR(token, crypto_auth_BYTES);

    if( crypto_auth(token_ptr, msg, msg_size, key) == 0 ) {
        return scope.Close(token->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_auth_verify(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
Handle<Value> bind_crypto_auth_verify(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments token, message, and key must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, token, crypto_auth_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_auth_KEYBYTES);

    return scope.Close(Integer::New(crypto_auth_verify(token, message, message_size, key)));
}

/**
 * int crypto_onetimeauth(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
Handle<Value> bind_crypto_onetimeauth(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and key must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_onetimeauth_KEYBYTES);

    NEW_BUFFER_AND_PTR(token, crypto_onetimeauth_BYTES);

    if( crypto_onetimeauth(token_ptr, message, message_size, key) == 0 ) {
        return scope.Close(token->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_onetimeauth_verify(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
Handle<Value> bind_crypto_onetimeauth_verify(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments token, message, and key must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, token, crypto_onetimeauth_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_onetimeauth_KEYBYTES);

    return scope.Close(Integer::New(crypto_onetimeauth_verify(token, message, message_size, key)));
}

/**
 * int crypto_stream(
 *    unsigned char * stream,
 *    unsigned long long slen,
 *    const unsigned char * nonce,
 *    const unsigned char * key)
 *
 * Generates a stream using the given secret key and nonce.
 *
 * Parameters:
 *    [out] stream  the generated stream.
 *    [out]  slen    the length of the generated stream.
 *    [in]  nonce   the nonce used to generate the stream.
 *    [in]  key     the key used to generate the stream.
 *
 * Returns:
 *    0 if operation successful
 */
Handle<Value> bind_crypto_stream(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"argument length must be a positive number, arguments nonce, and key must be buffers");

    if (!args[0]->IsUint32())
        return V8Exception("argument length must be positive number");

    unsigned long long slen = args[0]->ToUint32()->Value();
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_stream_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_stream_KEYBYTES);

    NEW_BUFFER_AND_PTR(stream, slen);

    if( crypto_stream(stream_ptr, slen, nonce, key) == 0) {
        return scope.Close(stream->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * int crypto_stream_xor(
 *    unsigned char *c,
 *    const unsigned char *m,
 *    unsigned long long mlen,
 *    const unsigned char *n,
 *    const unsigned char *k)
 *
 * Parameters:
 *    [out] ctxt 	buffer for the resulting ciphertext.
 *    [in] 	msg 	the message to be encrypted.
 *    [in] 	mlen 	the length of the message.
 *    [in] 	nonce 	the nonce used during encryption.
 *    [in] 	key 	secret key used during encryption.
 *
 * Returns:
 *    0 if operation successful.
 *
 * Precondition:
 *    ctxt must have length minimum mlen.
 *    nonce must have length minimum crypto_stream_NONCEBYTES.
 *    key must have length minimum crpyto_stream_KEYBYTES
 */
Handle<Value> bind_crypto_stream_xor(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_stream_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_stream_KEYBYTES);

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_stream_xor(ctxt_ptr, message, message_size, nonce, key) == 0) {
        return scope.Close(ctxt->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Encrypts and authenticates a message using the given secret key, and nonce.
 *
 * int crypto_secretbox(
 *    unsigned char *ctxt,
 *    const unsigned char *msg,
 *    unsigned long long mlen,
 *    const unsigned char *nonce,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] ctxt 	the buffer for the cipher-text.
 *    [in] 	msg 	the message to be encrypted.
 *    [in] 	mlen 	the length of msg.
 *    [in] 	nonce 	a nonce with length crypto_box_NONCEBYTES.
 *    [in] 	key 	the shared secret key.
 *
 * Returns:
 *    0 if operation is successful.
 *
 * Precondition:
 *    first crypto_secretbox_ZEROBYTES of msg be all 0..
 *
 * Postcondition:
 *    first crypto_secretbox_BOXZERBYTES of ctxt be all 0.
 *    first mlen bytes of ctxt will contain the ciphertext.
 */
Handle<Value> bind_crypto_secretbox(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(pmb, message_size + crypto_secretbox_ZEROBYTES);

    // Fill the first crypto_secretbox_ZEROBYTES with 0
    unsigned int i;
    for(i=0; i < crypto_secretbox_ZEROBYTES; i++) {
        pmb_ptr[i] = 0U;
    }

    //Copy the message to the new buffer
    memcpy((void*) (pmb_ptr + crypto_secretbox_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_secretbox_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_secretbox(ctxt_ptr, pmb_ptr, message_size, nonce, key) == 0) {
        return scope.Close(ctxt->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and senders public key.
 *
 * int crypto_secretbox_open(
 *    unsigned char *msg,
 *    const unsigned char *ctxt,
 *    unsigned long long clen,
 *    const unsigned char *nonce,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] msg 	the buffer to place resulting plaintext.
 *    [in] 	ctxt 	the ciphertext to be decrypted.
 *    [in] 	clen 	the length of the ciphertext.
 *    [in] 	nonce 	a randomly generated nonce.
 *    [in] 	key 	the shared secret key.
 *
 * Returns:
 *    0 if successful and -1 if verification fails.
 *
 * Precondition:
 *    first crypto_secretbox_BOXZEROBYTES of ctxt be all 0.
 *    the nonce must be of length crypto_secretbox_NONCEBYTES
 *
 * Postcondition:
 *    first clen bytes of msg will contain the plaintext.
 *    first crypto_secretbox_ZEROBYTES of msg will be all 0.
 *
 * Warning:
 *    if verification fails msg may contain data from the computation.
 */
Handle<Value> bind_crypto_secretbox_open(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments cipherText, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, cipher_text);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(message, cipher_text_size);

    // API requires that the first crypto_secretbox_ZEROBYTES of msg be 0 so lets check
    if( cipher_text_size < crypto_secretbox_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have at least " << crypto_secretbox_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }

    unsigned int i;
    for(i=0; i < crypto_secretbox_BOXZEROBYTES; i++) {
        if( cipher_text[i] ) break;
    }
    if( i < crypto_secretbox_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_secretbox_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }

    if( crypto_secretbox_open(message_ptr, cipher_text, cipher_text_size, nonce, key) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipher_text_size - crypto_secretbox_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (message_ptr + crypto_secretbox_ZEROBYTES), cipher_text_size - crypto_secretbox_ZEROBYTES);

        return scope.Close(plain_text->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Signs a given message using the signer's signing key.
 *
 * int crypto_sign(
 *    unsigned char * sig,
 *    unsigned long long * slen,
 *    const unsigned char * msg,
 *    unsigned long long mlen,
 *    const unsigned char * sk)
 *
 * Parameters:
 *    [out] sig     the resulting signature.
 *    [out] slen    the length of the signature.
 *    [in] 	msg     the message to be signed.
 *    [in] 	mlen    the length of the message.
 *    [in] 	sk 	    the signing key.
 *
 * Returns:
 *    0 if operation successful
 *
 * Precondition:
 *    sig must be of length mlen+crypto_sign_BYTES
 *    sk must be of length crypto_sign_SECRETKEYBYTES
 */
Handle<Value> bind_crypto_sign(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_sign_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(sig, message_size + crypto_sign_BYTES);

    unsigned long long slen = 0;
    if( crypto_sign(sig_ptr, &slen, message, message_size, secretKey) == 0) {
        return scope.Close(sig->handle_);
    }
    return scope.Close(Undefined());
}

/**
* Signs a given message using the signer's signing key, without appending the message to the signature
*
* int crypto_sign_detached(
*    unsigned char* sig,
*    unsigned long long * slen,
*    const unsigned cahr * msg,
*    unsigned long long mlen,
*    const unsigned char * sk)
*
* Parameters:
*    [out] sig    the resulting detached signature
*    [out] slen   length of the resulting signature
*    [in]  msg    the message to be signed
*    [in]  mlen   length of the message
*    [in]  sk     the signing key
*
* Returns:
*    0 if the operation is successful
*
* Precondition:
*    sig must be of length crypto_sign_BYTES
*    sk must be of length crypto_sign_SECRETKEYBYTES
*/
Handle<Value> bind_crypto_sign_detached(const Arguments& args){
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2, "arguments message, and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_sign_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(sig, crypto_sign_BYTES);

    unsigned long long slen = 0;
    if ( crypto_sign_detached(sig_ptr, &slen, message, message_size, secretKey) == 0){
        return scope.Close(sig->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Generates a signing/verification key pair.
 *
 * int crypto_sign_keypair(
 *    unsigned char * vk,
 *    unsigned char * sk)
 *
 * Parameters:
 *    [out] vk 	the verification key.
 *    [out] sk 	the signing key.
 *
 * Returns:
 *    0 if operation successful.
 *
 * Precondition:
 *    the buffer for vk must be at least crypto_sign_PUBLICKEYBYTES in length
 *    the buffer for sk must be at least crypto_sign_SECRETKEYTBYTES in length
 *
 * Postcondition:
 *    first crypto_sign_PUBLICKEYTBYTES of vk will be the key data.
 *    first crypto_sign_SECRETKEYTBYTES of sk will be the key data.
 */
Handle<Value> bind_crypto_sign_keypair(const Arguments& args) {
    HandleScope scope;

    NEW_BUFFER_AND_PTR(vk, crypto_sign_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_sign_SECRETKEYBYTES);

    if( crypto_sign_keypair(vk_ptr, sk_ptr) == 0) {
        Local<Object> result = Object::New();
        result->Set(String::NewSymbol("publicKey"),vk->handle_);
        result->Set(String::NewSymbol("secretKey"), sk->handle_);
        return scope.Close(result);
    }
    return scope.Close(Undefined());
}

/**
 * Verifies the signed message sig using the signer's verification key.
 *
 * int crypto_sign_open(
 *    unsigned char * msg,
 *    unsigned long long * mlen,
 *    const unsigned char * sig,
 *    unsigned long long smlen,
 *    const unsigned char * vk)
 *
 * Parameters:
 *
 *    [out] msg     the resulting message.
 *    [out] mlen    the length of msg.
 *    [in] 	sig     the signed message.
 *    [in] 	smlen   length of the signed message.
 *    [in] 	vk 	    the verification key.
 *
 * Returns:
 *    0 if successful, -1 if verification fails.
 *
 * Precondition:
 *    length of msg must be at least smlen
 *
 * Warning:
 *    if verification fails msg may contain data from the computation.
 */
Handle<Value> bind_crypto_sign_open(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments signedMessage and verificationKey must be buffers");

    GET_ARG_AS_UCHAR(0, signedMessage);
    GET_ARG_AS_UCHAR_LEN(1, publicKey, crypto_sign_PUBLICKEYBYTES);

    unsigned long long mlen = 0;
    NEW_BUFFER_AND_PTR(msg, signedMessage_size);

    if( crypto_sign_open(msg_ptr, &mlen, signedMessage, signedMessage_size, publicKey) == 0) {
        NEW_BUFFER_AND_PTR(m, mlen);
        memcpy(m_ptr, msg_ptr, mlen);
        return scope.Close(m->handle_);
    }
    return scope.Close(Undefined());
}

/**
* Verifies the detached signature of a message using the signer's public key
*
* int crypto_sign_verify_detached(
*    const unsigned char * sig,
*    const unsigned char * msg,
*    unsigned long long mlen,
*    const unsigned char * pk)
*
* Parameters:
*    [in] sig    the message's detached signature
*    [in] msg    the message to which the signature will be verified
*    [in] mlen   the message's length
*    [in] pk     the signer's public key
*
* Returns:
*    0 if successful, -1 otherwise
*
* Precondition:
*    sig must be of length crypto_sign_BYTES
*    pk must be of length crypto_sign_PUBLICKEYBYTES
*/
Handle<Value> bind_crypto_sign_verify_detached(const Arguments& args){
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3, "arguements signature, message and publicKey must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, signature, crypto_sign_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_sign_PUBLICKEYBYTES);

    if (crypto_sign_verify_detached(signature, message, message_size, publicKey) == 0){
        return scope.Close(Boolean::New(true));
    }
    return scope.Close(Boolean::New(false));

}

/**
* Translates the Ed25519 public key to Curve25519
* int crypto_sign_ed25519_pk_to_curve25519  (
*    unsigned char* curve25519_pk,
*    const unsigned char* ed25519_pk
* )
*
* Parameters:
*    [out]  curve25519_pk   the resulting Curve25519 public key
*    [in]   ed25519_pk      the source Ed25519 public key
*
* Returns:
*    0 if operation is successful.
*/
Handle<Value> bind_crypto_sign_ed25519_pk_to_curve25519(const Arguments& args){
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1, "arguments ed25519_pk must be a buffer");

    GET_ARG_AS_UCHAR_LEN(0, ed25519_pk, crypto_sign_PUBLICKEYBYTES);

    NEW_BUFFER_AND_PTR(curve25519_pk, crypto_box_PUBLICKEYBYTES);

    if (crypto_sign_ed25519_pk_to_curve25519(curve25519_pk_ptr, ed25519_pk) == 0){
        return scope.Close(curve25519_pk->handle_);
    }
    return scope.Close(Undefined());
}

/**
* Translates the Ed25519 secret key to Curve25519
* int crypto_sign_ed25519_sk_to_curve25519  (
*    unsigned char* curve25519_sk,
*    const unsigned char* ed25519_sk
* )
*
* Parameters:
*    [out]  curve25519_sk   the resulting Curve25519 secret key
*    [in]   ed25519_sk      the source Ed25519 secret key
*
* Returns:
*    0 if operation is successful.
*/
Handle<Value> bind_crypto_sign_ed25519_sk_to_curve25519(const Arguments& args){
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1, "arguments ed25519_sk must be a buffer");

    GET_ARG_AS_UCHAR_LEN(0, ed25519_sk, crypto_sign_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(curve25519_sk, crypto_box_SECRETKEYBYTES);

    if (crypto_sign_ed25519_sk_to_curve25519(curve25519_sk_ptr, ed25519_sk) == 0){
        return scope.Close(curve25519_sk->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Encrypts a message given the senders secret key, and receivers public key.
 * int crypto_box	(
 *    unsigned char * ctxt,
 *    const unsigned char * msg,
 *    unsigned long long mlen,
 *    const unsigned char * nonce,
 *    const unsigned char * pk,
 *    const unsigned char * sk)
 *
 * Parameters:
 *    [out] ctxt    the buffer for the cipher-text.
 *    [in] 	msg     the message to be encrypted.
 *    [in] 	mlen    the length of msg.
 *    [in] 	nonce   a randomly generated nonce.
 *    [in] 	pk 	    the receivers public key, used for encryption.
 *    [in] 	sk 	    the senders private key, used for signing.
 *
 * Returns:
 *    0 if operation is successful.
 *
 * Precondition:
 *    first crypto_box_ZEROBYTES of msg be all 0.
 *    the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *    first crypto_box_BOXZEROBYTES of ctxt be all 0.
 *    first mlen bytes of ctxt will contain the ciphertext.
 */
Handle<Value> bind_crypto_box(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(4,"arguments message, nonce, publicKey and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(msg, message_size + crypto_box_ZEROBYTES);

    // Fill the first crypto_box_ZEROBYTES with 0
    unsigned int i;
    for(i=0; i < crypto_box_ZEROBYTES; i++) {
       msg_ptr[i] = 0U;
    }
    //Copy the message to the new buffer
    memcpy((void*) (msg_ptr + crypto_box_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_box_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_box(ctxt_ptr, msg_ptr, message_size, nonce, publicKey, secretKey) == 0) {
        return scope.Close(ctxt->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Randomly generates a secret key and a corresponding public key.
 *
 * int crypto_box_keypair(
 *    unsigned char * pk,
 *    unsigned char * sk)
 *
 * Parameters:
 *    [out] pk  the buffer for the public key with length crypto_box_PUBLICKEYBYTES
 *    [out] sk  the buffer for the private key with length crypto_box_SECRETKEYTBYTES
 *
 * Returns:
 *    0 if generation successful.
 *
 * Precondition:
 *    the buffer for pk must be at least crypto_box_PUBLICKEYBYTES in length
 *    the buffer for sk must be at least crypto_box_SECRETKEYTBYTES in length
 *
 * Postcondition:
 *    first crypto_box_PUBLICKEYTBYTES of pk will be the key data.
 *    first crypto_box_SECRETKEYTBYTES of sk will be the key data.
 */
Handle<Value> bind_crypto_box_keypair(const Arguments& args) {
    HandleScope scope;

    NEW_BUFFER_AND_PTR(pk, crypto_box_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_box_SECRETKEYBYTES);

    if( crypto_box_keypair(pk_ptr, sk_ptr) == 0) {
        Local<Object> result = Object::New();
        result->Set(String::NewSymbol("publicKey"), pk->handle_);
        result->Set(String::NewSymbol("secretKey"), sk->handle_);
        return scope.Close(result);
    }
    return scope.Close(Undefined());
}

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and senders public key.
 *
 * int crypto_box_open(
 *    unsigned char *       msg,
 *    const unsigned char * ctxt,
 *    unsigned long long    clen,
 *    const unsigned char * nonce,
 *    const unsigned char * pk,
 *    const unsigned char * sk)
 *
 * Parameters:
 *     [out] msg     the buffer to place resulting plaintext.
 *     [in]  ctxt    the ciphertext to be decrypted.
 *     [in]  clen    the length of the ciphertext.
 *     [in]  nonce   a randomly generated.
 *     [in]  pk      the senders public key, used for verification.
 *     [in]  sk      the receivers private key, used for decryption.
 *
 Returns:
 *     0 if successful and -1 if verification fails.
 *
 Precondition:
 *     first crypto_box_BOXZEROBYTES of ctxt be all 0.
 *     the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *     first clen bytes of msg will contain the plaintext.
 *     first crypto_box_ZEROBYTES of msg will be all 0.
 */
Handle<Value> bind_crypto_box_open(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(4,"arguments cipherText, nonce, publicKey and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, cipherText);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);

    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if( cipherText_size < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }

    unsigned int i;
    for(i=0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }
    if( i < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_box_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size);

    if( crypto_box_open(msg_ptr, cipherText, cipherText_size, nonce, publicKey, secretKey) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);
        return scope.Close(plain_text->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Partially performs the computation required for both encryption and decryption of data.
 *
 * int crypto_box_beforenm(
 *    unsigned char*        k,
 *    const unsigned char*  pk,
 *    const unsigned char*  sk)
 *
 * Parameters:
 *    [out] k   the result of the computation.
 *    [in]  pk  the receivers public key, used for encryption.
 *    [in]  sk  the senders private key, used for signing.
 *
 * The intermediate data computed by crypto_box_beforenm is suitable for both
 * crypto_box_afternm and crypto_box_open_afternm, and can be reused for any
 * number of messages.
 */
Handle<Value> bind_crypto_box_beforenm(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments publicKey, and secretKey must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(k, crypto_box_BEFORENMBYTES);

    crypto_box_beforenm(k_ptr, publicKey, secretKey);
    return scope.Close(k->handle_);
}

/**
 * Encrypts a given a message m, using partial computed data.
 *
 * int crypto_box_afternm(
 *    unsigned char * ctxt,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * nonce,
 *       const unsigned char * k)
 *
 * Parameters:
 *    [out] ctxt   the buffer for the cipher-text.
 *    [in]  msg    the message to be encrypted.
 *    [in]  mlen   the length of msg.
 *    [in]  nonce  a randomly generated nonce.
 *    [in]  k      the partial computed data.
 *
 * Returns:
 *    0 if operation is successful.
 */
Handle<Value> bind_crypto_box_afternm(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce and k must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, k, crypto_box_BEFORENMBYTES);

    // Pad the message with crypto_box_ZEROBYTES zeros
    NEW_BUFFER_AND_PTR(msg, message_size + crypto_box_ZEROBYTES);

    unsigned int i;
    for(i=0; i < crypto_box_ZEROBYTES; i++) {
       msg_ptr[i] = 0U;
    }
    //Copy the message to the new buffer
    memcpy((void*) (msg_ptr + crypto_box_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_box_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_box_afternm(ctxt_ptr, msg_ptr, message_size, nonce, k) == 0) {
        return scope.Close(ctxt->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and senders public key.
 *
 * int crypto_box_open_afternm ( unsigned char * msg,
 *    const unsigned char * ctxt,
 *    unsigned long long clen,
 *    const unsigned char * nonce,
 *    const unsigned char * k)
 *
 * Parameters:
 *    [out] msg    the buffer to place resulting plaintext.
 *    [in]  ctxt   the ciphertext to be decrypted.
 *    [in]  clen   the length of the ciphertext.
 *    [in]  nonce  a randomly generated nonce.
 *    [in]  k      the partial computed data.
 *
 * Returns:
 *    0 if successful and -1 if verification fails.
 *
 * Precondition:
 *    first crypto_box_BOXZEROBYTES of ctxt be all 0.
 *    the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *    first clen bytes of msg will contain the plaintext.
 *    first crypto_box_ZEROBYTES of msg will be all 0.
 */
Handle<Value> bind_crypto_box_open_afternm(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments cipherText, nonce, k");

    GET_ARG_AS_UCHAR(0, cipherText);
    GET_ARG_AS_UCHAR_LEN(0, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(1, k, crypto_box_BEFORENMBYTES);

    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if( cipherText_size < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }

    unsigned int i;
    for(i=0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }
    if( i < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_box_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size);

    if( crypto_box_open_afternm(msg_ptr, cipherText, cipherText_size, nonce, k) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text,cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);

        return scope.Close(plain_text->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
 */
Handle<Value> bind_crypto_scalarmult_base(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");

    GET_ARG_AS_UCHAR_LEN(0, n, crypto_scalarmult_SCALARBYTES);
    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_BYTES);

    if( crypto_scalarmult_base(q_ptr, n) == 0) {
        return scope.Close(q->handle_);
    }
    return scope.Close(Undefined());
}


/**
 * int crypto_scalarmult(unsigned char *q, const unsigned char *n,
 *                  const unsigned char *p)
 */
Handle<Value> bind_crypto_scalarmult(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, n, crypto_scalarmult_SCALARBYTES);
    GET_ARG_AS_UCHAR_LEN(1, p, crypto_scalarmult_BYTES);

    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_BYTES);

    if( crypto_scalarmult(q_ptr, n, p) == 0) {
        return scope.Close(q->handle_);
    }
    return scope.Close(Undefined());
}


#define NEW_INT_PROP(NAME) \
    target->Set(String::NewSymbol(#NAME), Integer::New(NAME), ReadOnly)

#define NEW_STRING_PROP(NAME) \
    target->Set(String::NewSymbol(#NAME), String::New(NAME), ReadOnly)

#define NEW_METHOD(NAME) \
    NODE_SET_METHOD(target, #NAME, bind_ ## NAME)

void RegisterModule(Handle<Object> target) {
    // init sodium library before we do anything
    sodium_init();

    // Register KeyRing object
    KeyRing::Init(target);

    // Register version functions
    NEW_METHOD(sodium_version_string);

    //NEW_METHOD(version);
    NEW_METHOD(sodium_library_version_minor);
    NEW_METHOD(sodium_library_version_major);

    // register utilities
    NEW_METHOD(memzero);
    NEW_METHOD(memcmp);

    // register random utilities
    NEW_METHOD(randombytes_buf);
    NEW_METHOD(randombytes_close);
    NEW_METHOD(randombytes_stir);
    NEW_METHOD(randombytes_random);
    NEW_METHOD(randombytes_uniform);

    // String comparisons
    NEW_METHOD(crypto_verify_16);
    NEW_METHOD(crypto_verify_32);

    // Hash
    NEW_METHOD(crypto_hash);
    NEW_METHOD(crypto_hash_sha512);
    NEW_METHOD(crypto_hash_sha256);
    NEW_INT_PROP(crypto_hash_BYTES);
    //NEW_INT_PROP(crypto_hash_BLOCKBYTES); //Seems that this constant isn't available anymore
    NEW_STRING_PROP(crypto_hash_PRIMITIVE);

    // Password hash / Key derivation
    NEW_METHOD(crypto_pwhash_scryptsalsa208sha256);
    NEW_METHOD(crypto_pwhash_scryptsalsa208sha256_ll);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_STRBYTES);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);

    // Password-based file encryption
    NODE_SET_METHOD(target, "encrypt_file", pw_file_encrypt);
    NODE_SET_METHOD(target, "decrypt_file", pw_file_decrypt);

    // Auth
    NEW_METHOD(crypto_auth);
    NEW_METHOD(crypto_auth_verify);
    NEW_INT_PROP(crypto_auth_BYTES);
    NEW_INT_PROP(crypto_auth_KEYBYTES);
    NEW_STRING_PROP(crypto_auth_PRIMITIVE);

    // One Time Auth
    NEW_METHOD(crypto_onetimeauth);
    NEW_METHOD(crypto_onetimeauth_verify);
    NEW_INT_PROP(crypto_onetimeauth_BYTES);
    NEW_INT_PROP(crypto_onetimeauth_KEYBYTES);
    NEW_STRING_PROP(crypto_onetimeauth_PRIMITIVE);

    // Stream
    NEW_METHOD(crypto_stream);
    NEW_METHOD(crypto_stream_xor);
    NEW_INT_PROP(crypto_stream_KEYBYTES);
    NEW_INT_PROP(crypto_stream_NONCEBYTES);
    NEW_STRING_PROP(crypto_stream_PRIMITIVE);

    /*
     * Not implemented in the default crypto_stream, only in the AES variations which are not
     * ported yet
    NEW_METHOD(crypto_stream_beforenm);
    NEW_METHOD(crypto_stream_afternm);
    NEW_METHOD(crypto_stream_xor_afternm);
    */

    // Secret Box
    NEW_METHOD(crypto_secretbox);
    NEW_METHOD(crypto_secretbox_open);
    NEW_INT_PROP(crypto_secretbox_BOXZEROBYTES);
    NEW_INT_PROP(crypto_secretbox_KEYBYTES);
    NEW_INT_PROP(crypto_secretbox_NONCEBYTES);
    NEW_INT_PROP(crypto_secretbox_ZEROBYTES);

    // Sign
    NEW_METHOD(crypto_sign);
    NEW_METHOD(crypto_sign_detached);
    NEW_METHOD(crypto_sign_keypair);
    NEW_METHOD(crypto_sign_open);
    NEW_METHOD(crypto_sign_verify_detached);
    NEW_INT_PROP(crypto_sign_BYTES);
    NEW_INT_PROP(crypto_sign_PUBLICKEYBYTES);
    NEW_INT_PROP(crypto_sign_SECRETKEYBYTES);

    //Ed25519 -> Curve25519 translation
    NEW_METHOD(crypto_sign_ed25519_pk_to_curve25519);
    NEW_METHOD(crypto_sign_ed25519_sk_to_curve25519);

    // Box
    NEW_METHOD(crypto_box);
    NEW_METHOD(crypto_box_keypair);
    NEW_METHOD(crypto_box_open);
    NEW_METHOD(crypto_box_beforenm);
    NEW_METHOD(crypto_box_afternm);
    NEW_METHOD(crypto_box_open_afternm);
    NEW_INT_PROP(crypto_box_NONCEBYTES);
    NEW_INT_PROP(crypto_box_BEFORENMBYTES);
    NEW_INT_PROP(crypto_box_BOXZEROBYTES);
    NEW_INT_PROP(crypto_box_PUBLICKEYBYTES);
    NEW_INT_PROP(crypto_box_SECRETKEYBYTES);
    NEW_INT_PROP(crypto_box_ZEROBYTES);
    NEW_INT_PROP(crypto_box_MACBYTES);
    NEW_STRING_PROP(crypto_box_PRIMITIVE);

    NEW_METHOD(crypto_shorthash);
    NEW_INT_PROP(crypto_shorthash_BYTES);
    NEW_INT_PROP(crypto_shorthash_KEYBYTES);
    NEW_STRING_PROP(crypto_shorthash_PRIMITIVE);

    // Scalar Mult
    NEW_METHOD(crypto_scalarmult);
    NEW_METHOD(crypto_scalarmult_base);
    NEW_INT_PROP(crypto_scalarmult_SCALARBYTES);
    NEW_INT_PROP(crypto_scalarmult_BYTES);
    NEW_STRING_PROP(crypto_scalarmult_PRIMITIVE);

}

NODE_MODULE(sodium, RegisterModule);
