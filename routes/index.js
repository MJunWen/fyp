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
const nonce1 = crypto.randomBytes(16).toString("hex")
const bitkey512 = crypto.randomBytes(64).toString("hex")
const ivforxts = crypto.randomBytes(16).toString("hex")

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
var key = Buffer.from(nonce1,'hex');
var src = Buffer.from(dek,'hex');
cipher = crypto.createCipheriv("aes-128-ecb", key, null);
cipher.setAutoPadding(false);
pfk1 = cipher.update(src).toString('hex');
pfk1 += cipher.final().toString('hex');

//aes-256-xts
var src2 = Buffer.from(pfk1,'hex');
var key2 = Buffer.from(bitkey512,'hex');
var sectornumber = Buffer.from(ivforxts,'hex');
cipherxts = crypto.createCipheriv("aes-256-xts", key2,sectornumber);
cipherxts.setAutoPadding(false);
encryptcontent = cipherxts.update(src2).toString('hex');
encryptcontent += cipherxts.final().toString('hex');

//encrypt file and decrypt file
function encryptFile(inputFile, outputFile) {
  const inputData = fs.readFileSync(inputFile);
  let cipherxts = crypto.createCipheriv("aes-256-xts", key2,sectornumber); //"let" is important or else it causes errors. ????
  const output = Buffer.concat([cipherxts.update(inputData) , cipherxts.final()]);
  fs.writeFileSync(outputFile, output);
}

function decryptFile(inputFile, outputFile) {
  const inputData = fs.readFileSync(inputFile);
  const cipher = crypto.createDecipheriv("aes-256-xts", key2, sectornumber);
  const output = Buffer.concat([cipher.update(inputData) , cipher.final()]);
  fs.writeFileSync(outputFile, output);
}
//tested txt and JPG encryption and decryption works
const filetoencrypt = "asdasdada.JPG";
const encryptedfile = "asdasdadaEncrypted.txt"; //show off in txt form to show it's encrypted gibberish. If not just remove the .txt extension
const decryptedfile = "asdasdadaDecrypted.JPG";
encryptFile(path.join(__dirname, filetoencrypt), path.join(__dirname, encryptedfile));
decryptFile(path.join(__dirname, encryptedfile), path.join(__dirname, decryptedfile));

/* GET home page. */
router.get('/', function(req, res, next) {
   

  //render lets you import variables into the html file which is index.ejs
  res.render('index', { title: 'Express', password, salt,dek, frontikpad, backikpad, privateKey, publicKey, scrypt1hash,  rsaencrypted,ik1pad,scrypt2hash,kek,iv,nonce1,pfk1,ivforxts,encryptcontent});
});

module.exports = router;

//const encOutput = fs.createWriteStream(path.join(__dirname, "filetoencrypt.txt.enc"));