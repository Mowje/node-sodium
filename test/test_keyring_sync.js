var assert = require('assert');
var buffer = require('buffer').Buffer;
var sodium = require('../build/Release/sodium');

var keyring1 = new sodium.KeyRing();
var keyring2 = new sodium.KeyRing();

//Testing Curve25519 stuff
var pubKey1 = keyring1.createKeyPair('curve25519');
var pubKey2 = keyring2.createKeyPair('curve25519');
console.log('Public key 1 : ' + JSON.stringify(pubKey1) + '\nPublic key 2 : ' + JSON.stringify(pubKey2));

console.log('Performing a key exchange');
var shared1 = keyring1.agree(new Buffer(pubKey2.publicKey, 'hex'));
var shared2 = keyring2.agree(new Buffer(pubKey1.publicKey, 'hex'));
console.log('Shared key 1 : ' + shared1.toString('hex'));
console.log('Shared key 2 : ' + shared2.toString('hex'));
assert.equal(shared1.toString('hex'), shared2.toString('hex'), 'Shared secret isn\'t the same!');

//Crypto box
var message1 = 'Message1', message2 = 'Message2';
console.log('Message 1 : ' + message1 + '\nMessage 2 : ' + message2);
var nonce1 = new Buffer(sodium.crypto_box_NONCEBYTES), nonce2 = new Buffer(sodium.crypto_box_NONCEBYTES);
sodium.randombytes_buf(nonce1); sodium.randombytes_buf(nonce2);
console.log('Nonce 1 : ' + nonce1.toString('hex'));
console.log('Nonce 2 : ' + nonce2.toString('hex'));

var cipher1 = keyring1.encrypt(new Buffer(message1), new Buffer(pubKey2.publicKey, 'hex'), nonce1);
var cipher2 = keyring2.encrypt(new Buffer(message2), new Buffer(pubKey1.publicKey, 'hex'), nonce2);
console.log('Cipher 1 : ' + cipher1.toString('hex') + '\nCipher 2 : ' + cipher2.toString('hex'));

var plaintext1 = keyring2.decrypt(cipher1, new Buffer(pubKey1.publicKey, 'hex'), nonce1);
var plaintext2 = keyring1.decrypt(cipher2, new Buffer(pubKey2.publicKey, 'hex'), nonce2);
console.log('Plaintext 1 : ' + plaintext1.toString() + '\nPlaintext 2 : ' + plaintext2.toString());
assert.equal(message1, plaintext1.toString(), 'Initial message 1 and decrypted message aren\'t identitcal!');
assert.equal(message2, plaintext2.toString(), 'Initial message 2 and decrypted message aren\'t identitcal!');