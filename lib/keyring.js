var binding = require('../build/Release/sodium');
var KeyRing = binding.KeyRing;

//A temporary wrapper script that will help users dodge a bug in key file writing.
//Will generate keys, save and load it, test its operations until one is valid

var fs = require('fs');
var path = require('path');
var Buffer = require('buffer').Buffer;

module.exports = function(filename, password){

	var _keyRing;
	if (filename && typeof filename == 'string'){
		if (!fs.existsSync(filename)) throw new TypeError('the key file doesn\'t exist');

		if (password && typeof password == 'string' && password.length > 0) _keyRing = new KeyRing(filename, password);
		else _keyRing = new KeyRing(filename);
	}


	this.createKeyPair = function(keyType, filename, callback){
		if (typeof keyType !== 'string') throw new TypeError('keyType must be a string');
		if (!(keyType == 'curve25519' || keyType == 'ed25519')) throw new TypeError('keyType must be either "curve25519" or "ed25519"');
		if (filename && typeof filename !== 'string') throw new TypeError('when defined, filename must be a string');
		if (callback && typeof callback !== 'function') throw new TypeError('when defined, callback must be a function');

		//If there already is a keyRing referenced, clear it before replacing it with a new one
		if (_keyRing) _keyRing.clear();

		var pubKey;
		_keyRing = new KeyRing();
		var isValidKeyFile = false;
		while (!isValidKeyFile){
			pubKey = _keyRing.createKeyPair(keyType);
			if (keyType == 'curve25519'){
				if (!testCurve25519()) continue;
			} else {
				if (!testEd25519()) continue;
			}
			try {
				_keyRing.save('./temp.key');
				_keyRing.load('./temp.key');
				if (keyType == 'curve25519'){
					if (!testCurve25519()) continue;
				} else {
					if (!testEd25519()) continue;
				}
			} catch (e){
				continue;
			}
			fs.unlinkSync('./temp.key');
			if (filename) _keyRing.save(filename);
			isValidKeyFile = true;
		}
		if (callback){
			callback(pubKey);
		} else return pubKey;

		function testCurve25519(){
			//Trying a curve25519 ECDH operation, to check that the reloaded key works
			var _keyRing2 = new KeyRing();
			var pubKey2 = _keyRing2.createKeyPair('curve25519');
			var sharedSecret1 = _keyRing.agree(new Buffer(pubKey2.publicKey, 'hex'));
			var sharedSecret2 = _keyRing2.agree(new Buffer(pubKey.publicKey, 'hex'));
			if (sharedSecret1.toString('hex') != sharedSecret2.toString('hex')) return false;
			else return true;
		}

		function testEd25519(){
			//Generate a random message to sign.
			var testMessage = new Buffer(250);
			var signature = _keyRing.sign(testMessage);
			var signedMessage = binding.crypto_sign_open(signature, new Buffer(pubKey.publicKey, 'hex'));
			if (!signedMessage) return false;
			if (signedMessage.toString('hex') == testMessage.toString('hex')) return true;
			else return false;
		}

	};

	this.encrypt = function(message, publicKey, nonce, callback){
		if (!_keyRing) throw new TypeError('No key pair is loaded into the key ring');
		if (!Buffer.isBuffer(message)) throw new TypeError('"message" must be a buffer');
		if (!Buffer.isBuffer(publicKey)) throw new TypeError('"publicKey" must be a buffer');
		if (!Buffer.isBuffer(nonce)) throw new TypeError('"nonce" must be a buffer');
		if (callback && typeof callback !== 'function') throw new TypeError('When defined, callback must be a function');

		if (!callback){
			return _keyRing.encrypt(message, publicKey, nonce);
 		} else {
 			_keyRing.encrypt(message, publicKey, nonce, callback);
 		}
	};

	this.decrypt = function(cipher, publicKey, nonce, callback){
		if (!_keyRing) throw new TypeError('No key pair is loaded into the key ring');
		if (!Buffer.isBuffer(cipher)) throw new TypeError('"cipher" must be a buffer');
		if (!Buffer.isBuffer(publicKey)) throw new TypeError('"publicKey" must be a buffer');
		if (!Buffer.isBuffer(nonce)) throw new TypeError('"nonce" must be a buffer');
		if (callback && typeof callback !== 'function') throw new TypeError('When defined, callback must be a function');

		if (!callback){
			return _keyRing.decrypt(cipher, publicKey, nonce);
		} else {
			_keyRing.decrypt(cipher, publicKey, nonce, callback);
		}
	};

	this.sign = function(message, callback){
		if (!_keyRing) throw new TypeError('No key pair is loaded in the key ring');
		if (!Buffer.isBuffer(message)) throw new TypeError('The "message" to be signed must be a buffer');
		if (callback && typeof callback != 'function') throw new TypeError('When defined, callback must be a function');

		var signature = _keyRing.sign(message);
		if (!callback){
			//var signature = _keyRing.sign(message);
			//if (signature.toString('hex') == binding.crypto_sign_open(signature, new Buffer(_keyRing.publicKeyInfo().publicKey, 'hex')).toString('hex'))
			return signature;
		} else {
			callback(signature);
		}
	};

	this.agree = function(publicKey, callback){
		if (!_keyRing) throw new TypeError('No key pair is loaded in the key ring');
		if (!Buffer.isBuffer(publicKey)) throw new TypeError('"publicKey" must be a buffer');
		if (callback && typeof callback != 'function') throw new TypeError('When defined, callback must be a function');

		if (!callback){
			return _keyRing.agree(publicKey);
		} else {
			_keyRing.agree(publicKey, callback);
		}
	};

	this.publicKeyInfo = function(callback){
		if (!_keyRing) throw new TypeError('No key pair is loaded in the key ring');
		if (callback && typeof callback != 'function') throw new TypeError('When defined, callback must be a function');
		if (!callback){
			return _keyRing.publicKeyInfo();
		} else {
			_keyRing.publicKeyInfo(callback);
		}
	};

	this.load = function(filename, callback, password, opsLimit){
		if (_keyRing) _keyRing.clear();
		if (!fs.existsSync(filename)) throw new TypeError('The key file doesn\'t exist');
		_keyRing = new KeyRing();
		if (!callback){
			return _keyRing.load(filename);
		} else {
			_keyRing.load(filename, callback);
		}

	};

	this.save = function(filename, callback, password, opsLimit, r, p){
		if (!_keyRing) throw new TypeError('No key pair is loaded in the key ring');
		if (!fs.existsSync(path.join(filename, '..'))) throw new TypeError('The folder where the key file will be saved doesn\'t exist');
		if (callback && typeof callback != 'function') throw new TypeError('When defined, callback must be a function');

		if (password && !(typeof password == 'string' || Buffer.isBuffer(password))) throw new TypeError('When defined, a password must either be a string or a buffer');
		if (typeof opsLimit != 'undefined' && !(typeof opsLimit == 'number' && opsLimit > 0 && Math.floor(opsLimit) == opsLimit)) throw new TypeError('When defined, opsLimit must be a positive integer number');
		if (typeof r != 'undefined' && !(typeof r == 'number' && r > 0 && Math.floor(r) == r)) throw new TypeError('When defined, r must be a positive integer number');

		if (!callback){
			return _keyRing.save(filename);
		} else {
			_keyRing.save(filename, callback);
		}
	};

	this.clear = function(){
		if (_keyRing){
			_keyRing.clear();
			_keyRing = undefined;
		}
	};

};
