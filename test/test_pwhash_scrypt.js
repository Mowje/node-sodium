var should = require('assert');
var binding = require('../build/Release/sodium');
var Buffer = require('buffer').Buffer;

function testScrypt(opsLimit, memLimit){

	var testPass = 'test-pass';
	var testSalt = new Buffer('4bdf54d6a25d12e2d337b155201d2770d31e61777633370f9949e438fa471a6f', 'hex');

	var hashBuffer = binding.crypto_pwhash_scryptsalsa208sha256(testPass, testSalt, )

}

testScrypt(binding.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE, binding.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
