var assert = require('assert');
var Buffer = require('buffer').Buffer;
var sodium = require('../build/Release/sodium');

var message1 = 'Message 1', message2 = 'Message 2';

var keyring1 = new sodium.KeyRing();
var keyring2 = new sodium.KeyRing();

var pubKey1, pubKey2

var generateCurve25519KeyPairs = function(callback){
	keyring1.createKeyPair('curve25519', undefined, function(pubKey1_){
		pubKey1 = pubKey1_;
		//console.log('Public key 1 : ' + JSON.stringify(pubKey1_));
		keyring2.createKeyPair('curve25519', undefined, function(pubKey2_) {
			pubKey2 = pubKey2_;
			//console.log('Public key 2 : ' + JSON.stringify(pubKey2_));
			if (callback && typeof callback == 'function') callback();
		});
	});
};

var testCurve25519Exchange = function(callback){
	keyring1.agree(new Buffer(pubKey2.publicKey, 'hex'), function(shared1){
		keyring2.agree(new Buffer(pubKey1.publicKey, 'hex'), function(shared2) {
			assert.equal(shared1.toString('hex'), shared2.toString('hex'), 'Shared secret isn\'t identical!');
			if (callback && typeof callback == 'function') callback();
		})
	});
};

var generateEd25519KeyPairs = function(callback){
	keyring1.createKeyPair('ed25519', undefined, function(pubKey1_){
		pubKey1 = pubKey1_;
		//console.log('Public key 1 : ' + JSON.stringify(pubKey1_));
		keyring2.createKeyPair('ed25519', undefined, function(pubKey2_){
			pubKey2 = pubKey2_;
			//console.log('Public key 2 : ' + JSON.stringify(pubKey2_));
			if (callback && typeof callback == 'function') callback();
		});
	});
}

var testEd25519Signatures = function(callback){
	keyring1.sign(new Buffer(message1), function(signature1){
		keyring2.sign(new Buffer(message2), function(signature2){
			var signedMessage1 = sodium.crypto_sign_open(signature1, new Buffer(pubKey1.publicKey, 'hex'));
			var signedMessage2 = sodium.crypto_sign_open(signature2, new Buffer(pubKey2.publicKey, 'hex'));
			assert.notEqual(typeof signedMessage1, 'undefined', 'The signature of the first message is invalid');
			assert.notEqual(typeof signedMessage2, 'undefined', 'The signature of the second message is invalid');
			assert.equal(signedMessage1.toString('utf8'), message1, 'The signed message 1 isn\'t the same as the original');
			assert.equal(signedMessage2.toString('utf8'), message2, 'The signed message 2 isn\'t the same as the original');
		});
	});
};

generateCurve25519KeyPairs(function(){
	testCurve25519Exchange(function(){
		generateEd25519KeyPairs(testEd25519Signatures);
	});
});