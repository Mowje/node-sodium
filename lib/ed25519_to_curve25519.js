var binding = require('../build/Release/sodium');

var Buffer = require('buffer').Buffer;

exports.ed25519_publicKey_to_curve25519 = function(ed25519_publicKey){
	var k;
	if (Buffer.isBuffer(ed25519_publicKey) && ed25519_publicKey.length == binding.crypto_sign_PUBLICKEYBYTES) k = ed25519_publicKey;
	else if (typeof ed25519_publicKey == 'string' && /^[0-9|a-f]+$/ig.test(ed25519_publicKey) && ed25519_publicKey.length == 2 * binding.crypto_sign_PUBLICKEYBYTES) k = new Buffer(ed25519_publicKey, 'hex');
	else return undefined;

	return binding.crypto_sign_ed25519_pk_to_curve25519(k);
};

exports.ed25519_secretKey_to_curve25519 = function(ed25519_secretKey){
	var k;
	if (Buffer.isBuffer(ed25519_secretKey) && ed25519_secretKey.length == binding.crypto_sign_SIGNKEYBYTES) k = ed25519_secretKey;
	else if (typeof ed25519_secretKey == 'string' && /^[0-9|a-f]+$/ig.test(ed25519_secretKey) && ed25519_secretKey.length == 2 * binding.crypto_sign_SECRETKEYBYTES) k = new Buffer(ed25519_secretKey, 'hex');
	else return undefined;

	return binding.crypto_sign_ed25519_sk_to_curve25519(k);
};
