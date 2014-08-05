var assert = require('assert');
var buffer = require('buffer').Buffer;
var fs = require('fs');
var sodium = require('../lib/sodium');

var keyring1 = new sodium.KeyRing();
var keyring2 = new sodium.KeyRing();

if (process.argv[2] && process.argv[2].toLowerCase() == 'delete'){
	if (fs.existsSync('./c25519-1-enc.key')) fs.unlinkSync('./c25519-1-enc.key');
	if (fs.existsSync('./c25519-2-enc.key')) fs.unlinkSync('./c25519-2-enc.key');
	if (fs.existsSync('./ed25519-1-enc.key')) fs.unlinkSync('./ed25519-1-enc.key');
	if (fs.existsSync('./ed25519-2-enc.key')) fs.unlinkSync('./ed25519-2-enc.key');
}

var v = false;
if (process.argv[2] && process.argv[2].toLowerCase() == 'verbose'){
	v = true;
	console.log('Testing encrypted key files');
}

var pubKey1, pubKey2;
//Testing Curve25519 stuff
if (fs.existsSync('./c25519-1-enc.key') && fs.existsSync('./c25519-2-enc.key')){
	if (v) console.log('Loading existing key files');
	pubKey1 = keyring1.load('./c25519-1-enc.key', undefined, 'password1');
	pubKey2 = keyring2.load('./c25519-2-enc.key', undefined, 'password2');
} else {
	if (v) console.log('Generating new curve25519 key pairs');
	pubKey1 = keyring1.createKeyPair('curve25519');
	pubKey2 = keyring2.createKeyPair('curve25519');
	if (v) console.log('Saving them');
	keyring1.save('./c25519-1-enc.key', undefined, 'password1');
	if (v) console.log('First key has been saved');
	keyring2.save('./c25519-2-enc.key', undefined, 'password2');
	if (v) console.log('Second kay has been saved');
}

var message1 = 'Message1', message2 = 'Message2';

var testCurve25519 = function(callback){
	if (v) {
		console.log('Public key 1 : ' + JSON.stringify(pubKey1) + '\nPublic key 2 : ' + JSON.stringify(pubKey2));
		console.log('Performing a key exchange');
	}
	var shared1 = keyring1.agree(new Buffer(pubKey2.publicKey, 'hex'));
	var shared2 = keyring2.agree(new Buffer(pubKey1.publicKey, 'hex'));
	if (v) {
		console.log('Shared key 1 : ' + shared1.toString('hex'));
		console.log('Shared key 2 : ' + shared2.toString('hex'));
	}
	assert.equal(shared1.toString('hex'), shared2.toString('hex'), 'Shared secret isn\'t the same!');

	//Crypto box
	if (v) console.log('Message 1 : ' + message1 + '\nMessage 2 : ' + message2);
	var nonce1 = new Buffer(sodium.Const.Box.nonceBytes), nonce2 = new Buffer(sodium.Const.Box.nonceBytes);
	sodium.Random.buffer(nonce1); sodium.Random.buffer(nonce2);
	if (v){
		console.log('Nonce 1 : ' + nonce1.toString('hex'));
		console.log('Nonce 2 : ' + nonce2.toString('hex'));
	}

	var cipher1 = keyring1.encrypt(new Buffer(message1), new Buffer(pubKey2.publicKey, 'hex'), nonce1);
	var cipher2 = keyring2.encrypt(new Buffer(message2), new Buffer(pubKey1.publicKey, 'hex'), nonce2);
	if (v) console.log('Cipher 1 : ' + cipher1.toString('hex') + '\nCipher 2 : ' + cipher2.toString('hex'));

	var plaintext1 = keyring2.decrypt(cipher1, new Buffer(pubKey1.publicKey, 'hex'), nonce1);
	var plaintext2 = keyring1.decrypt(cipher2, new Buffer(pubKey2.publicKey, 'hex'), nonce2);
	if (v) console.log('Plaintext 1 : ' + plaintext1.toString() + '\nPlaintext 2 : ' + plaintext2.toString());
	assert.equal(message1, plaintext1.toString(), 'Initial message 1 and decrypted message aren\'t identitcal!');
	assert.equal(message2, plaintext2.toString(), 'Initial message 2 and decrypted message aren\'t identitcal!');

	if (callback && typeof callback == 'function') callback();
};
//Ed25519 signatures


var testSignatures = function(callback){
	if (v) console.log('Public key 1 : ' + JSON.stringify(pubKey1) + '\nPublic key 2 : ' + JSON.stringify(pubKey2));
	var signature1 = keyring1.sign(new Buffer(message1));
	var signature2 = keyring2.sign(new Buffer(message2));
	if (v){
		console.log('Signature 1 : ' + signature1.toString('hex'));
		console.log('Signature 2 : ' + signature2.toString('hex'));
	}

	var isValid1 = sodium.api.crypto_sign_open(signature1, new Buffer(pubKey1.publicKey, 'hex'));
	var isValid2 = sodium.api.crypto_sign_open(signature2, new Buffer(pubKey2.publicKey, 'hex'));
	if (v){
		console.log('isValid1 : ' + isValid1.toString());
		console.log('isValid2 : ' + isValid2.toString());
	}
	assert.equal(isValid1.toString(), message1, 'Signature 1 is invalid');
	assert.equal(isValid2.toString(), message2, 'Signature 2 is invalid');

	if (callback && typeof callback == 'function') callback();
};

testCurve25519(function(){
	if (fs.existsSync('./ed25519-1-enc.key') && fs.existsSync('./ed25519-2-enc.key')){
		if (v) console.log('Loading existing ed25519 key pairs');
		pubKey1 = keyring1.load('./ed25519-1-enc.key', undefined, 'password1');
		pubKey2 = keyring2.load('./ed25519-2-enc.key', undefined, 'password2');
	} else {
		if (v) console.log('Generating new ed25519 key pairs');
		pubKey1 = keyring1.createKeyPair('ed25519');
		pubKey2 = keyring2.createKeyPair('ed25519');
		if (v) console.log('Saving the new keypairs to disk');
		keyring1.save('./ed25519-1-enc.key', undefined, 'password1');
		keyring2.save('./ed25519-2-enc.key', undefined, 'password2');
	}

	testSignatures(function(){
		//key saving and loading
		if (v) console.log('Reloading curve25519 keys')
		pubKey1 = keyring1.load('./c25519-1-enc.key', undefined, 'password1');
		pubKey2 = keyring2.load('./c25519-2-enc.key', undefined, 'password2');
		testCurve25519(function(){
			if (v) console.log('Reloading Ed25519 keys');
			pubKey1 = keyring1.load('./ed25519-1-enc.key', undefined, 'password1');
			pubKey2 = keyring2.load('./ed25519-2-enc.key', undefined, 'password2');
			testSignatures();
		});
	});
});
