# Pwhash Low Level API

## Detailed Description

Provides password-based key derivation with the scrypt function

# Usage

## Access

	var sodium = require('sodium').api;

	// Example of calling a key derivation
	var derviedKey = sodium.crypto_pwhash_scryptsalsa208sha256(password, salt, resultKeyLength, operationsLimit, memoryLimit)

	// Accessing a constant
	var memLimitIntensive = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;

## Constants

	* `crypto_pwhash_scryptsalsa208sha256_SALTBYTES` 			mandatory salt size when calling `crypto_pwhash_scryptsalsa208sha256`
	* `crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE`	proposed number of iterations when derived key is to be used with sensitive data
	* `crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE`	proposed number of iterations when derived key is to be used in an interactive context (eg, logins)
	* `crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE`	proposed memory limit when derived key is to be used with sensitive data
	* `crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE` proposed memory limit when derived key is to be used in an interactive context (eg, logins)

## Functions

### crypto_pwhash_scryptsalsa208sha256(Buffer password, Buffer salt, [Number resultKeyLength], [Number opsLimit], [Number memoryLimit])

High-level call to scrypt. (In case you know about r and p parameters in scrypt, this method sorts these values out based on the memory limit; if you want to set r and p yourself, use the lower level function described below)
Derives a password into a key of given length, through the (memory-intensive) scrypt function

Parameters:

  * `Buffer password` - the password to be derived
  * `Buffer salt` - the salt to be appended to the password before derivation. Length must be equal to crypto_pwhash_scryptsalsa208sha256_SALTBYTES (= 32 bytes)
  * `Number resultKeyLength` - the desired length (in bytes) for the resulting key. Optional. Defaults to 32.
  * `Number opsLimit` - the threshold of scrypt iterations. Optional. Defaults to crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE (= 16384)
  * `Number memLimit` - the upper memory usage limit to be used in the key derivation. Optinal. Defaults to crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE (= 16777216)

Returns:

  * Buffer containing the resulting key
  * Throws exceptions if salt is of wrong length, or if the given numeric parameters aren't positive integers

### crypto_pwhash_scryptsalsa208sha256_ll(Buffer password, Buffer salt, [Number opsLimit], [Number r], [Number p], [Number resultKeyLength])

Low-level call to scrypt. r and p parameters can be set by yourself
Derives a password into a key of given length, through the (memory-intensive) scrypt function

Parameters:

  * `Buffer password` - the password to be derived
  * `Buffer salt` - the salt to be appended to the password before derivation. No imposed length
  * `Number opsLimit` - the threshold of scrypt iterations. Positive integer number. Optional. Defaults to crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  * `Number r` - the r parameter of the scrypt function. Positive integer number. Optional. Defaults to r = 8
  * `Number p` - the p parameter of the scrypt function. Positive integer number. Optional. Defaults to p = 1
  * `Number resultKeyLength` - the result key length. Positive integer number. Optional. Defaults to 32 bytes

Returns:

  * Buffer containing the derived key
  * Throws an exception if the numeric parameters aren't positive integer numbers
