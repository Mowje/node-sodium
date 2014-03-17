# KeyRing API
----------------------

To initialize a `KeyRing` object:

```js
var sodium = require('sodium');
var keyring = new sodium.KeyRing();
```

**NOTE:**
----------------------
Don't forget to call the `clear` method once you're done using the keypair loaded in the keyring. Otherwise the keys might stay in memory (ie, memory leak, in between security issues in case the memory is dumped)

Also, when you want to skip an optional parameter but want to define an other parameter that follows it, you must set the first one to `undefined`. Sorry for the inconvenience.

Additionally :
`encrypt`, `decrypt`, `agree` can be called when the loaded key pair is a Curve25519 one. `sign` can be called when the loaded key pair is a Ed25519 one. In case it's not respected, an exception will be thrown.
----------------------

## Methods :

* `KeyRing.createKeyPair(String keyType, [String filename], [Function callback])`
	* String keyType : 'curve25519' or 'ed25519'. Other values will raise an exception
	* String filename : path where you want to save the key once it's generated. Optional
	* Function callback : Optional. Function that will take the `PublicKeyInfo` object if the generation succeeds (ie, if parameters are valid)
	* Returns the `PublicKeyInfo` object (if no callback has been given)
* `KeyRing.publicKeyInfo([Function callback])`
	Returns an object (or passes it to the callback, if defined) containing the `keyType` and the `publicKey` (as hex-encoded string)
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
