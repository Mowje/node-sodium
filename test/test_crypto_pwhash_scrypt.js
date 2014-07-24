var should = require('assert');
var binding = require('../build/Release/sodium');
var Buffer = require('buffer').Buffer;

var defaultMemLimit = Math.pow(2, 25);
// Test vectors extracted from the original paper on scrypt (look Appendix B). https://www.tarsnap.com/scrypt/scrypt.pdf
var vectors = [
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

for (var i = 0; i < vectors.length; i++){
	testScrypt(vectors[i]);
}


function testScrypt(vector){
	var hashBuffer = binding.crypto_pwhash_scryptsalsa208sha256_ll(vector.pass, vector.salt, vector.opsLimit, vector.r, vector.p, vector.keyLength);
	//console.log('hashedBuffer: ' + hashBuffer.toString('hex'));
	if (hashBuffer.toString('hex') != vector.result) console.error('Invalid hashed password for vector : ' + JSON.stringify(vector));
}
