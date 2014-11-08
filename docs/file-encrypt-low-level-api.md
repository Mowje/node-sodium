# Password-based file encryption

I implemented this feature using `scrypt` + `secretbox` methods of Libsodium. The file format is the same as for encrypted key files as implemented by the `KeyRing` (except that the leading byte describing the key type is removed)

## Access

	var sodium = require('sodium').api;

	//Example of file encryption
	sodium.encrypt_file(fileContent, password, filePath);

	//Example of file decryption
	var plainText = sodium.decrypt_file(filePath, password);

## Functions

### encrypt_file(Buffer fileContent, Buffer password, String filePath)

Encrypt the given fileContent, using a key derived from the given password and storing the result at filePath

Parameters:

	* `Buffer fileContent` - the content to be protected by encryption
	* `Buffer password` - the password that will be derived into a key
	* `String filePath` - the destination file
	* `Function callback` - OPTIONAL. Callback function

Throws an exception if the parameters aren't of the correct type

### decrypt_file(String filePath, Buffer password)

Decrypts the file at the given filePath and encrypted using `encrypt_file` with the given password

Parameters:

	* `String filePath` - path to the encrypted file
	* `Buffer password` - the password that was used to encrypt the file

Returns:
	* A buffer containing the decrypted content
	* Throws a `TypeError` if the provided parameters aren't of the correct types
	* Throws a `RangeError` if the file is of incorrect format
	* Throws a simple `Error` if the password is invalid or if the file couldn't be unencrypted correclty
