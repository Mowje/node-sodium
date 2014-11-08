var assert = require('assert');
var Buffer = require('buffer').Buffer;

var binding = require('../build/Release/sodium');
var sodium = require('../lib/sodium');

var randData = new Buffer(100), password = new Buffer(16);
sodium.Random.buffer(randData);
sodium.Random.buffer(password);

var testFileName = 'test.enc';

sodium.FileEncrypt.encryptFile(randData, password, testFileName);
//console.log('File encryption completed');
var plaintext = sodium.FileEncrypt.decryptFile(testFileName, password);
//console.log('File decryption completed');

assert(plaintext.toString('hex') == randData.toString('hex'), 'Error through encryption/decryption process. High level API');

//Regenerate new random data, and use low level api
sodium.Random.buffer(randData);
sodium.Random.buffer(password);

binding.encrypt_file(randData, password, testFileName);
plaintext = binding.decrypt_file(testFileName, password);

assert(plaintext.toString('hex') == randData.toString('hex'), 'Error through encryption/decryption process. Low level API');
