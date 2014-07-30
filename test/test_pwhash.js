var assert = require('assert');
var Buffer = require('buffer').Buffer;

var binding = require('../build/Release/sodium');
var sodium = require('../lib/sodium');

//Checking constants values
assert.equal(sodium.Const.Pwhash.memlimitInteractive, binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE, 'Invalid bound value for crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE');
assert.equal(sodium.Const.Pwhash.memlimitSensitive, binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE, 'Invalid bound value for crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE');
assert.equal(sodium.Const.Pwhash.opslimitInteractive, binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, 'Invalid bound value for crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE');
assert.equal(sodium.Const.Pwhash.opslimitSensitive, binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE, 'Invalid bound value for crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE');

//Testing the high-level scrypt function

var hlVectors = [
	{
		pass: 'password',
		salt: new Buffer('5d97a42b80c546cbe340a1e6aed5178c3a0253ce391c090fae3a122b3e1501c7', 'hex'),
		result: 'c609b534d20c5f792df342b4c868c12efb2f08e08935c5adb9b1ed49d10a476e'
	},
	{
		pass: 'password',
		salt: new Buffer('66e70d6568c533819cc072eb249cf545bbf8b6e8011c6b20771c266ce35a70ae', 'hex'),
		keyLength: 64,
		memLimit: sodium.Const.Pwhash.memlimitInteractive,
		opsLimit: sodium.Const.Pwhash.opslimitInteractive,
		result: '3c78a5a56e0d9e8e51f89e5b4326e0946a3476a3b287c51011383653a3880b8f38964e6c5ebf54272ec3fa44ce6e904f1334fda0c64ff451781a778ae0aabae7'
	},
	{
		pass: 'I\'m fooling around with scrypt',
		salt: new Buffer('1586a0b0ed5fef82200b37819a79bd29e8a07e5c58e48248c277850c8845e7ae', 'hex'),
		keyLength: 32,
		memLimit: sodium.Const.Pwhash.memlimitInteractive,
		opsLimit: sodium.Const.Pwhash.opslimitSensitive,
		result: 'c7e30850e93a4b30a24c830d846d53a8a42285daf246e95e77aa226bbd61f649'
	}
	/*{ //Segfault because of memlimitSensitive
		pass: 'password',
		salt: new Buffer('61c1fd0362bacce387dc37b96dd0e084a4e4660ccf49c56da9276a272f382d85', 'hex'),
		keyLength: sodium.Const.Pwhash.memlimitSensitive,
		opsLimit: sodium.Const.Pwhash.opslimitInteractive
	}*/
	/*{
		pass: 'password',
		salt: new Buffer('bdc71ed8153080f57949121ef44cafa7b3c0783d74afdd0fc82e929bfa490481', 'hex'),
		keyLength: 32,
	}*/
];

for (var i = 0; i < hlVectors.length; i++){
	testScryptHl(hlVectors[i]);

}

function testScryptHl(v){
	var derivedKey = sodium.Pwhash.crypto_pwhash_scryptsalsa208sha256(v.pass, v.salt, v.keyLength, v.opsLimit, v.memLimit);
	//console.log('derivedKey.toHex: ' + derivedKey.toString('hex'));
	assert.ok(derivedKey.toString('hex') == v.result, 'Scrypt assertion fail, high level call with vector ' + JSON.stringify(v));
}

//Testing the low-level scrypt function
var llVectors = [
	/*{
		pass: new Buffer('', 'ascii'),
		salt: new Buffer('', 'ascii'),
		keyLength: 64,
		r: 1,
		p: 1,
		opsLimit: 16,
		memLimit: defaultMemLimit,
		result: '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906'
	},*/
	{
		pass: new Buffer('password', 'ascii'),
		salt: new Buffer('NaCl', 'ascii'),
		keyLength: 64,
		r: 8,
		p: 16,
		opsLimit: 1024,
		result: 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640'
	},
	{
		pass: new Buffer('pleaseletmein', 'ascii'),
		salt: new Buffer('SodiumChloride', 'ascii'),
		keyLength: 64,
		r: 8,
		p: 1,
		opsLimit: 16384,
		result: '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'
	},
	{
		pass: new Buffer('pleaseletmein', 'ascii'),
		salt: new Buffer('SodiumChloride', 'ascii'),
		keyLength: 64,
		r: 8,
		p: 1,
		opsLimit: 1048576,
		result: '2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4'
	}
];

for (var i = 0; i < llVectors.length; i++){
	testScryptLl(llVectors[i]);
}

function testScryptLl(v){
	var derivedKey = sodium.Pwhash.crypto_pwhash_scryptsalsa208sha256_ll(v.pass, v.salt, v.opsLimit, v.r, v.p, v.keyLength);
	assert.ok(derivedKey.toString('hex') == v.result, 'Scrypt assertion fail, low level call with vector ' + JSON.stringify(v));
}
