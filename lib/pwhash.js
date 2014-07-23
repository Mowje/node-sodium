var binding = require('../build/Release/sodium');
var Buffer = require('buffer').Buffer;

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
		if (salt.length != binding.crypto_pwhash_scryptsalsa208sha256_SALTBYES){
			throw new TypeError('salt must be ' + binding.crypto_pwhash_scryptsalsa208sha256_SALTBYES + ' bytes long');
		}
		saltBuf = salt;
	} else {
		if (Buffer.byteLength(salt, 'utf8') != binding.crypto_pwhash_scryptsalsa208sha256_SALTBYES){
			throw new TypeError('salt must be ' + binding.crypto_pwhash_scryptsalsa208sha256_SALTBYES + ' bytes long');
		}
		saltBuf = new Buffer(salt, 'utf8');
	}

	if (typeof keyLength != 'undefined' && !(typeof keyLength == 'number' && keyLength == Math.round(keyLength) && keyLength > 0)) throw new TypeError('when defined, keyLength must be a positive integer');
	if (typeof opsLimit != 'undefined' && !(typeof opsLimit == 'number' && opsLimit == Math.round(opsLimit) && opsLimit > 0)) throw new TypeError('when defined, opsLimit must be a positive integer');
	if (typeof memLimit != 'undefined' && !(typeof memLimit == 'number' && memLimit == Math.round(memLimit) && memLimit > 0)) throw new TypeError('when defined, memLimit must be a positive integer');

	return binding.bind_crypto_pwhash_scryptsalsa208sha256(passwordBuf, saltBuf, keyLength, opsLimit, memLimit);

};
