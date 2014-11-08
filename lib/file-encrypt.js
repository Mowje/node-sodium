var binding = require('../build/Release/sodium');
var fs = require('fs');
var path = require('path');
var Buffer = require('buffer').Buffer;

/**
* Encrypts the provided fileContent based on the provided password and stores the result at the given filename
*
* @param {String|Buffer} fileContent
* @param {String|Buffer} password
* @param {String} filename
* @param {Function} [callback]
* @throws {TypeError} invalid parameter types
*/
exports.encryptFile = function(fileContent, password, filename, callback){
	if (!(typeof fileContent == 'string' || Buffer.isBuffer(fileContent))) throw new TypeError('fileContent must either be a string or a buffer');
	if (!(typeof password == 'string' || Buffer.isBuffer(password))) throw new TypeError('password must either be a string or a buffer');
	if (!(typeof filename == 'string' || Buffer.isBuffer(filename))) throw new TypeError('filename must either be a string or a buffer');

	if (callback && typeof callback != 'function') throw new TypeError('When defined, callback must be a function');

	var fileBuf, passBuf, filenameStr;
	if (Buffer.isBuffer(fileContent)){
		fileBuf = fileContent;
	} else {
		fileBuf = new Buffer(fileContent);
	}
	if (Buffer.isBuffer(password)){
		passBuf = password;
	} else {
		passBuf = new Buffer(password);
	}
	if (Buffer.isBuffer(filename)){
		filenameStr = filename.toString();
	} else {
		filenameStr = filename;
	}

	//Check that the path to the folder that will contain the resulting file exists; and if not, build it
	buildPath(path.join(filenameStr, '..'));

	if (callback){
		binding.encrypt_file(fileBuf, passBuf, filenameStr, callback);
	} else return binding.encrypt_file(fileBuf, passBuf, filenameStr);

};

exports.decryptFile = function(filename, password, callback){
	if (!(typeof filename == 'string' || Buffer.isBuffer(filename))) throw new TypeError('filename must either be a string or a buffer');
	if (!(typeof password == 'string' || Buffer.isBuffer(password))) throw new TypeError('password must either be a string or a buffer');

	if (callback && typeof callback != 'function') throw new TypeError('when defined, callback must be a function');

	var passBuf, filenameStr;
	if (Buffer.isBuffer(password)){
		passBuf = password;
	} else {
		passBuf = new Buffer(password);
	}
	if (Buffer.isBuffer(filename)){
		filenameStr = filename.toString();
	} else {
		filenameStr = filename
	}

	//Check that the file exists
	if (!(fs.existsSync(filenameStr) && fs.statSync(filenameStr).isFile())){
		var err = new Error('file cannot be found');
		if (callback) callback(err);
		else throw err;
	}

	var plaintext;
	try {
		plaintext = binding.decrypt_file(filenameStr, password);
	} catch (e){
		if (callback){
			callback(e);
			return;
		} else throw e;
	}
	if (callback) callback(null, plaintext);
	else return plaintext;

};

//Build a directory path for a given directory path (and not filepath)
function buildPath(folderPath){
	if (!(fs.existsSync(folderPath) && fs.statSync(folderPath).isDirectory())){
		if (!fs.existsSync(path.join(folderPath, '..'))) buildPath(path.join(folderPath, '..'));
		else fs.mkdirSync(folderPath);
	}
}
