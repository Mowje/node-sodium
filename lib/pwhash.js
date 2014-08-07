var binding = require('../build/Release/sodium');
var Buffer = require('buffer').Buffer;

/**
* Derives a password into a cryptographic key of a given length. High-level call
*
* @param {String|Buffer} password - the password to be derived
* @param {String|Buffer} salt - the salt to be appended to the password before derivation. Must be 32 bytes long
* @param {Number} keyLength - the resulting key length. Optional. Defaults to 32 bytes
* @param {Number} opsLimit - the threshold of scrypt iterations. Optional. Defaults to crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE (= 16384)
* @param {Number} memLimit - the upper memory usage (in bytes) limit to be used in the key derivation. Must be a power of 2. Optional. Defaults to crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE (= 16777216)
* @throws {TypeError} if the salt isn't 32 bytes long, or if the numeric parameters aren't positive integers
*/
exports.crypto_pwhash_scryptsalsa208sha256 = function(password, salt, keyLength, opsLimit, memLimit){

	if (!(typeof password == 'string' || Buffer.isBuffer(password))){
		throw new TypeError('password must either be a string or a buffer');
	}
	if (!(typeof salt == 'string' || Buffer.isBuffer(salt))){
		throw new TypeError('salt must either be a string or a buffer');
	}

	var passwordBuf;
	var saltBuf;

	if (Buffer.isBuffer(password)){
		passwordBuf = password;
	} else {
		passwordBuf = new Buffer(password, 'utf8');
 	}

	if (Buffer.isBuffer(salt)){
		if (salt.length != binding.crypto_pwhash_scryptsalsa208sha256_SALTBYTES){
			throw new TypeError('salt must be ' + binding.crypto_pwhash_scryptsalsa208sha256_SALTBYTES + ' bytes long');
		}
		saltBuf = salt;
	} else {
		if (Buffer.byteLength(salt, 'utf8') != binding.crypto_pwhash_scryptsalsa208sha256_SALTBYES){
			throw new TypeError('salt must be ' + binding.crypto_pwhash_scryptsalsa208sha256_SALTBYTES + ' bytes long');
		}
		saltBuf = new Buffer(salt, 'utf8');
	}

	if (typeof keyLength != 'undefined' && !(typeof keyLength == 'number' && keyLength == Math.round(keyLength) && keyLength > 0)) throw new TypeError('when defined, keyLength must be a positive integer');
	if (typeof opsLimit != 'undefined' && !(typeof opsLimit == 'number' && opsLimit == Math.round(opsLimit) && opsLimit > 0)) throw new TypeError('when defined, opsLimit must be a positive integer');
	if (typeof memLimit != 'undefined' && !(typeof memLimit == 'number' && memLimit == Math.round(memLimit) && memLimit > 0)) throw new TypeError('when defined, memLimit must be a positive integer');

	return binding.crypto_pwhash_scryptsalsa208sha256(passwordBuf, saltBuf, keyLength, opsLimit, memLimit);

};

/**
* Derives a password into a cryptographic key of a given length. Low-level call
*
* @param {String|Buffer} password - the password to be derived
* @param {String|Buffer} salt - the salt to be appended to the password before derivation
* @param {Number} N - the opsLimit; the maximal number of iterations of the scrypt function. Optional. Defaults to crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE (=16384)
* @param {Number} r - the r parameter of the scrypt function. Optional. Defaults to 8
* @param {Number} p - the p parameter of the scrypt function. Optional. Defaults to 1
* @param {Number} keyLength - resulting key length, in bytes. Optional. Defaults to 32 bytes
*/
exports.crypto_pwhash_scryptsalsa208sha256_ll = function(password, salt, _N, _r, _p, _keyLength){

	if (!(typeof password == 'string' || Buffer.isBuffer(password))){
		throw new TypeError('password must either be a string or a buffer');
	}
	if (!(typeof salt == 'string' || Buffer.isBuffer(salt))){
		throw new TypeError('salt must either be a string or a buffer');
	}

	var passwordBuf;
	var saltBuf;
	var N, r, p, keyLength;

	if (Buffer.isBuffer(password)){
		passwordBuf = password;
	} else {
		passwordBuf = new Buffer(password, 'utf8');
	}

	if (Buffer.isBuffer(salt)){
		saltBuf = salt;
	} else {
		saltBuf = new Buffer(salt, 'utf8');
	}

	if (typeof _N != 'undefined'){
		if (typeof _N == 'number' && _N > 0 && _N == Math.floor(_N)){
			N = _N;
		} else {
			throw new TypeError('when defined, N must be a positive integer');
		}
	}
	if (typeof _r != 'undefined'){
		if (typeof _r == 'number' && _r > 0 && _r == Math.floor(_r)){
			r = _r;
		} else {
			throw new TypeError('when defined, r must be a positive integer');
		}
	}
	if (typeof _p != 'undefined'){
		if (typeof _p == 'number' && _p > 0 && _p == Math.floor(_p)){
			p = _p;
		} else {
			throw new TypeError('when defined, p must be a positive integer');
		}
	}
	if (typeof _keyLength != 'undefined'){
		if (typeof _keyLength == 'number' && _keyLength > 0 && _keyLength == Math.floor(_keyLength)){
			keyLength = _keyLength;
		} else {
			throw new TypeError('when defined, keyLength must be a positive integer');
		}
	}

	return binding.crypto_pwhash_scryptsalsa208sha256_ll(passwordBuf, saltBuf, N, r, p, keyLength);

};
