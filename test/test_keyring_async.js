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
		console.log('Public key 1 : ' + JSON.stringify(pubKey1_));
		keyring2.createKeyPair('curve25519', undefined, function(pubKey2_) {
			pubKey2 = pubKey2_;
			console.log('Public key 2 : ' + JSON.stringify(pubKey2_));
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
		console.log('Public key 1 : ' + JSON.stringify(pubKey1_));
		keyring2.createKeyPair('ed25519', undefined, function(pubKey2_){
			pubKey2 = pubKey2_;
			console.log('Public key 2 : ' + JSON.stringify(pubKey2_));
			if (callback && typeof callback == 'function') callback();
		});
	});
}

generateCurve25519KeyPairs(function(){
	testCurve25519Exchange(generateEd25519KeyPairs);
});