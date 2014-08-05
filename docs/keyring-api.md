# KeyRing API
----------------------

To initialize a `KeyRing` object:

```js
var sodium = require('sodium');
var keyring = new sodium.KeyRing();
```

**NOTE:** This gives you access to a wrapped version of the `KeyRing` class, that has better type testing. You can however directly access the C++ version by using instead :

```js
var sodium = require('sodium');
var keyring = new sodium.api.KeyRing();
```

Note that they have the same methods and parameters. But the JS wrapper adds more type testing and dodges a current bugs when saving/loading key files are when making some asynchronous calls.

----------------------

As of now, some async calls, with callbacks, (like signatures) are not working properly on the pure C++ binding.

Don't forget to call the `clear` method once you're done using the keypair loaded in the keyring. Otherwise the keys might stay in memory (ie, memory leak, in between security issues in case the memory is dumped)

Also, when you want to skip an optional parameter but want to define an other parameter that follows it, you must set the first one to `undefined`. Sorry for the inconvenience.

Additionally :
`encrypt`, `decrypt`, `agree` can be called when the loaded key pair is a Curve25519 one. `sign` can be called when the loaded key pair is a Ed25519 one. In case it's not respected, an exception will be thrown.

----------------------

## Methods :

* `KeyRing([String filename], [String|Buffer password])` : Constructor function
	* String filename : Optional. Path to a key file to be loaded into the KeyRing upon construction
* `KeyRing.createKeyPair(String keyType, [String filename], [Function callback], [String|Buffer password], [Number opsLimit], [Number r], [Number p])`
	* String keyType : 'curve25519' or 'ed25519'. Other values will raise an exception
	* String filename : path where you want to save the key once it's generated. Optional
	* Function callback : Optional. Function that will take the `PublicKeyInfo` object if the generation succeeds (ie, if parameters are valid)
	* String|Buffer password : Password that will be used to encrypt the newly generated key. Password will be derived through [scrypt](https://www.tarsnap.com/scrypt.html), using default parameters (opsLimit = 16384, r = 8, p = 1; could be overwritten using the arguments that follow. Optional.
	* Number opsLimit : limit number of operations for the scrypt key derivation. Optional. Defaults to 16384
	* Number r : r parameter of scrypt. Optional. Defaults to r = 8
	* Number p : p parameter of scrypt. Optional. Defaults to p = 1
	* Returns the `PublicKeyInfo` object (if no callback has been given)
* `KeyRing.publicKeyInfo([Function callback])`
	Returns an object (or passes it to the callback, if defined) containing the `keyType` and the `publicKey` (as hex-encoded string)
* `KeyRing.clear()`
	Clears the loaded key from memory
* `KeyRing.load(String filename, [Function callback], [String|Buffer password], [Number maxOpsLimit])`
	* String filename : path to the key file
	* Function callback : callback function that will receive the PublicKeyInfo object of the key that just has been loaded. Optional
	* String|Buffer password : password that will be used to decrypt the file, if that is needed. Optional.
	* Number maxOpsLimit : max number of scrypt operations before throwing an exception. This parameter is a counter-measure to key files that might have an opsLimit parameter way to high and that might freeze your program when you load them. Defaults to 4194304 (= 2^22). Optional.
	* Returns the `PublicKeyInfo` object (if no callback has been given)
* `KeyRing.save(String filename, [Function callback], [String|Buffer password], [Number opsLimit], [Number r], [Number p])`
	* String filename : path to the key file
	* Function callback : callback function that will be called when the key has been saved
	* String|Buffer password : Password that will be used to encrypt the key. Password will be derived through [scrypt](https://www.tarsnap.com/scrypt.html), using default parameters (opsLimit = 16384, r = 8, p = 1; could be overwritten using the arguments that follow. Optional.
	* Number opsLimit : limit number of operations for the scrypt key derivation. Optional. Defaults to 16384
	* Number r : r parameter of scrypt. Optional. Defaults to r = 8
	* Number p : p parameter of scrypt. Optional. Defaults to p = 1
	* Returns `Undefined`, in case no callback has been given
* `KeyRing.encrypt(Buffer message, Buffer publicKey, Buffer nonce, [Function callback])`
	* Buffer message : the message to encrypt
	* Buffer publicKey : the receiver's public key
	* Buffer nonce : a random number that will be used to initialize the stream cipher. Must be unique, don't use the same nonce twice
	* Function callback : Optional. When defined, it's called when the encryption operation is completed and receieves the encrypted message, as a `Buffer`
	* Returns the encrypted message as a `Buffer` (if no callback has been given)
* `KeyRing.decrypt(Buffer cipher, Buffer publicKey, Buffer nonce, [Function callback])`
	* Buffer cipher : the encrypted message
	* Buffer publicKey : the counterpart's public key
	* Buffer nonce : the random nonce used upon encryption
	* Function callback : Optional. Function that will be called once the decryption is completed and receives the decrypted message as a `Buffer`
	* Returns the decrypted message as a `Buffer` (if no callback has been defined)
* `KeyRing.agree(Buffer publicKey, [Function callback])`
	* Buffer publicKey : the counterpart's public key, with whom you want to make the key curve25519 key exchange
	* Function callback : Optional. Function that will be called once the shared secret has been calculated. Receives the shared secret as a `Buffer`
	* Returns the shared secret as a `Buffer`, if no callback has been given
* `KeyRing.sign(Buffer message, [Function callback])`
	* Buffer message : the message to be signed
	* Function callback : Optional. A function that will receive the signature as a `Buffer` once completed
	* Returns the signature as a `Buffer`, if no callback has been given

## Key file format

Note that numbers are written in big endian.

* keyType : one byte, 0x05 for Curve25519, 0x06 for Ed25519
* publicKeyLength : 2 bytes, unsigned integer. Length of the public key, in bytes
* publicKey
* privateKeyLength : 2 bytes, unsigned integer. Length of the private key, in bytes
* privateKey

## Encrypted key file format

Note that numbers are written in big endian.

* keyType : one byte, 0x05 for Curve25519, 0x06 for Ed25519
* r : the r parameter of scrypt (unsigned short)
* p : the p parameter of scrypt (unsigned short)
* opsLimit : the maximum number of allowed iterations in scrypt (unsigned long)
* saltSize : password salt size (sn, unsigned short)
* nonceSize : encryption nonce (ss, unsigned short)
* keyBufferSize : size of the key buffer that will be encrypted (x, unsigned long)
* sn bytes: salt
* ss bytes : nonce
* x bytes : encrypted key buffer, (plain text is the content of a non-encrypted key file, as described above)
