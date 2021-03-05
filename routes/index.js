//define constants here to use in the html
//start server by cd to directory, then open cmd and type nodemon run start
var express = require('express');
var router = express.Router();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const password = 'androidencryption';
const salt = crypto.randomBytes(16).toString("hex")
const frontikpad = "0";
const backikpad = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
//backikpad is 223 bytes of 0
//placeholder
const dek = crypto.randomBytes(64).toString("hex")
const nonce_1 = crypto.randomBytes(16).toString("hex")
const nonce_2 = crypto.randomBytes(16).toString("hex")
const bitkey512_1 = crypto.randomBytes(64).toString("hex")
const ivforxts_1 = crypto.randomBytes(16).toString("hex")
const bitkey512_2 = crypto.randomBytes(64).toString("hex")
const ivforxts_2 = crypto.randomBytes(16).toString("hex")

//scrypt setup
const scrypt = crypto.scryptSync(password, salt, 32);
scrypt1hash = scrypt.toString('hex');

const ik1pad = (frontikpad+scrypt1hash+backikpad);


//RSA keys setup
const { generateKeyPairSync } = require('crypto');
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs1',
    format: 'pem',
    // passphrase: 'top secret'
  }
});

//RSA encrypt setup
const encryptedData = crypto.publicEncrypt(
	{
		key: publicKey,
	},
	// We convert the data string to a buffer using `Buffer.from`
	Buffer.from(scrypt1hash)
)
const rsaencrypted = encryptedData.toString("hex");

//IK3 setup
const scrypt2 = crypto.scryptSync(rsaencrypted, salt, 32);
scrypt2hash = scrypt2.toString('hex');

const kek = scrypt2hash.substring(0,32);
const iv = scrypt2hash.substring(32,65);



// //RSA decrypt setup
// const decryptedData = crypto.privateDecrypt(
// 	{
// 		key: privateKey,
// 	},
// 	encryptedData
// )

// const rsadecrypted = decryptedData.toString();
//keep this if want to show decrypt of RSA key. Rmb to add rsadecrypted to render

//Per File key Setup 1
var key_pfk_1 = Buffer.from(nonce_1,'hex');
var src_pfk1 = Buffer.from(dek,'hex');
cipher = crypto.createCipheriv("aes-128-ecb", key_pfk_1, null);
cipher.setAutoPadding(false);
pfk_1 = cipher.update(src_pfk1).toString('hex');
pfk_1 += cipher.final().toString('hex');

//Per File key Setup 2
var key_pfk_2 = Buffer.from(nonce_2,'hex');
var src_pfk2 = Buffer.from(dek,'hex');
cipher = crypto.createCipheriv("aes-128-ecb", key_pfk_2, null);
cipher.setAutoPadding(false);
pfk_2 = cipher.update(src_pfk2).toString('hex');
pfk_2 += cipher.final().toString('hex');

//aes-256-xts 1
var src_xts_1 = Buffer.from(pfk_1,'hex');
var key_xts_1 = Buffer.from(bitkey512_1,'hex');
var sectornumber_1 = Buffer.from(ivforxts_1,'hex');
cipherxts_1 = crypto.createCipheriv("aes-256-xts", key_xts_1,sectornumber_1);
cipherxts_1.setAutoPadding(false);
encryptcontent_1 = cipherxts_1.update(src_xts_1).toString('hex');
encryptcontent_1 += cipherxts_1.final().toString('hex');

//aes-256-xts 2
var src_xts_2 = Buffer.from(pfk_2,'hex');
var key_xts_2 = Buffer.from(bitkey512_2,'hex');
var sectornumber_2 = Buffer.from(ivforxts_2,'hex');
cipherxts_2 = crypto.createCipheriv("aes-256-xts", key_xts_2,sectornumber_2);
cipherxts_2.setAutoPadding(false);
encryptcontent_2 = cipherxts_2.update(src_xts_2).toString('hex');
encryptcontent_2 += cipherxts_2.final().toString('hex');

//encrypt file and decrypt file 1
function encryptFile_1(inputFile, outputFile) {
  const inputData = fs.readFileSync(inputFile);
  let cipherxts_1 = crypto.createCipheriv("aes-256-xts", key_xts_1,sectornumber_1); //"let" is important or else it causes errors. ????
  const output = Buffer.concat([cipherxts_1.update(inputData) , cipherxts_1.final()]); //cipherxts2 needs to be defined again or it has error?But encrypting with same key and IV will lead to the same cipher
  fs.writeFileSync(outputFile, output);
}

function decryptFile_1(inputFile, outputFile) {
  const inputData = fs.readFileSync(inputFile);
  const cipher = crypto.createDecipheriv("aes-256-xts", key_xts_1, sectornumber_1);
  const output = Buffer.concat([cipher.update(inputData) , cipher.final()]);
  fs.writeFileSync(outputFile, output);
}

//encrypt file and decrypt file 2
function encryptFile_2(inputFile, outputFile) {
  const inputData = fs.readFileSync(inputFile);
  let cipherxts_2 = crypto.createCipheriv("aes-256-xts", key_xts_2,sectornumber_2); //"let" is important or else it causes errors. ????
  const output = Buffer.concat([cipherxts_2.update(inputData) , cipherxts_2.final()]); //cipherxts2 needs to be defined again or it has error?But encrypting with same key and IV will lead to the same cipher
  fs.writeFileSync(outputFile, output);
}

function decryptFile_2(inputFile, outputFile) {
  const inputData = fs.readFileSync(inputFile);
  const cipher = crypto.createDecipheriv("aes-256-xts", key_xts_2, sectornumber_2);
  const output = Buffer.concat([cipher.update(inputData) , cipher.final()]);
  fs.writeFileSync(outputFile, output);
}
//tested txt and JPG encryption and decryption works
//text folder encrypt
const filetoencrypt_1 = "filetoencrypt.txt";
const encryptedfile_1 = "filetoencryptEncrypted.txt"; //show off in txt form to show it's encrypted gibberish. If not just remove the .txt extension
const decryptedfile_1 = "filetoencryptDecrypted.txt";
const subfolder_1 = "text";
encryptFile_1(path.join(__dirname, subfolder_1, filetoencrypt_1), path.join(__dirname, subfolder_1, encryptedfile_1));
decryptFile_1(path.join(__dirname, subfolder_1, encryptedfile_1), path.join(__dirname, subfolder_1, decryptedfile_1));

//jpg folder encrypt
const filetoencrypt_2 = "filetoencrypt.jpg";
const encryptedfile_2 = "filetoencryptEncrypted.txt"; //show off in txt form to show it's encrypted gibberish. If not just remove the .txt extension
const decryptedfile_2 = "filetoencryptDecrypted.jpg";
const subfolder_2 = "jpg";
encryptFile_2(path.join(__dirname, subfolder_2, filetoencrypt_2), path.join(__dirname, subfolder_2, encryptedfile_2));
decryptFile_2(path.join(__dirname, subfolder_2, encryptedfile_2), path.join(__dirname, subfolder_2, decryptedfile_2));

/* GET home page. */
router.get('/', function(req, res, next) {
   

  //render lets you import variables into the html file which is index.ejs
  res.render('index', { title: 'Express', password, salt,dek, frontikpad, backikpad, privateKey, publicKey, scrypt1hash,  rsaencrypted,ik1pad,scrypt2hash,kek,iv,nonce_1,nonce_2,pfk_1,pfk_2,ivforxts_1,ivforxts_2,encryptcontent_1,encryptcontent_2});
});

module.exports = router;

//const encOutput = fs.createWriteStream(path.join(__dirname, "filetoencrypt.txt.enc"));