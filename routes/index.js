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

//Disk encryption keys
const dek_fde = crypto.randomBytes(64).toString("hex")
const dek_fbe = crypto.randomBytes(64).toString("hex")
//Randomly generated ivs for AES-128-CBC
//Encrypting fde file contents
const ivforcbc_1 = crypto.randomBytes(16).toString("hex") //for txt fde
const ivforcbc_2 = crypto.randomBytes(16).toString("hex") //for jpg fde
//Randomly generated ivs for AES-256-XTS
//Encrypting fbe file contents
const ivforxts_1 = crypto.randomBytes(16).toString("hex") //for txt fbe
const ivforxts_2 = crypto.randomBytes(16).toString("hex") //for jpg fbe
//Randomly generated nonce for AES-256-XTS
const nonce_1 = crypto.randomBytes(16).toString("hex")
const nonce_2 = crypto.randomBytes(16).toString("hex")
//Randomly generated keys AES-256-XTS
const bitkey512_1 = crypto.randomBytes(64).toString("hex") //for txt fbe
const bitkey512_2 = crypto.randomBytes(64).toString("hex") //for jpg fbe
//Randomly generated keys AES-256-GCM
const auth_tag_gcm = crypto.randomBytes(96).toString("hex") //for txt fbe
const key_gcm = crypto.randomBytes(32).toString("hex") //for jpg fbe
const iv_gcm = crypto.randomBytes(32).toString("hex") //for jpg fbe



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

const kek = scrypt2hash.substring(0,32).toString("hex");;
const iv = scrypt2hash.substring(32,65).toString("hex");;



// //RSA decrypt setup
// const decryptedData = crypto.privateDecrypt(
// 	{
// 		key: privateKey,
// 	},
// 	encryptedData
// )

// const rsadecrypted = decryptedData.toString();
//keep this if want to show decrypt of RSA key. Rmb to add rsadecrypted to render

//Encrypted DEK for FDE
var key_dek_fde = Buffer.from(kek,'hex');
var src_dek_fde = Buffer.from(dek_fde,'hex');
var iv_dek_fde = Buffer.from(iv,'hex');
cipher = crypto.createCipheriv("aes-128-cbc", key_dek_fde, iv_dek_fde);
cipher.setAutoPadding(false);
DEK_encrypted_FDE = cipher.update(src_dek_fde).toString('hex');
DEK_encrypted_FDE += cipher.final().toString('hex');
//setup IV for AES-128-CBC for encrypting the files
var iv_cbc_fde_1 = Buffer.from(ivforcbc_1,'hex');
var iv_cbc_fde_2 = Buffer.from(ivforcbc_2,'hex');

//////////////////////////////////////////////FBE

//Encrypt DEK for FBE
var auth_tag = Buffer.from(auth_tag_gcm,'hex');
var src_dek_fbe = Buffer.from(dek_fbe,'hex');
var iv_gcm_fbe = Buffer.from(iv_gcm,'hex');
var key_gcm_fbe = Buffer.from(key_gcm,'hex');
cipher = crypto.createCipheriv("aes-256-gcm", key_gcm_fbe, iv_gcm_fbe,auth_tag);
cipher.setAutoPadding(false);
DEK_encrypted_FBE = cipher.update(src_dek_fbe).toString('hex');
DEK_encrypted_FBE += cipher.final().toString('hex');

//Per File key Setup 1
var key_pfk_1 = Buffer.from(nonce_1,'hex');
var src_pfk1 = Buffer.from(dek_fbe,'hex');
cipher = crypto.createCipheriv("aes-128-ecb", key_pfk_1, null);
cipher.setAutoPadding(false);
pfk_1 = cipher.update(src_pfk1).toString('hex');
pfk_1 += cipher.final().toString('hex');

//Per File key Setup 2
var key_pfk_2 = Buffer.from(nonce_2,'hex');
var src_pfk2 = Buffer.from(dek_fbe,'hex');
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

//encrypt file and decrypt file
function encryptfile(inputFile, outputFile,algo,key,sectornumber) {
  const inputData = fs.readFileSync(inputFile);
  let cipher = crypto.createCipheriv(algo, key,sectornumber); //"let" is important or else it causes errors. ????
  const output = Buffer.concat([cipher.update(inputData) , cipher.final()]); //cipherxts2 needs to be defined again or it has error?But encrypting with same key and IV will lead to the same cipher
  fs.writeFileSync(outputFile, output);
}

function decryptfile(inputFile, outputFile,algo,key,sectornumber) {
  const inputData = fs.readFileSync(inputFile);
  const cipher = crypto.createDecipheriv(algo, key, sectornumber);
  const output = Buffer.concat([cipher.update(inputData) , cipher.final()]);
  fs.writeFileSync(outputFile, output);
}


////////////////////////////////////////FDE encryptions
var filetoencrypt = "filetoencrypt.txt";
var encryptedfile = "filetoencryptEncrypted.txt"; //show off in txt form to show it's encrypted gibberish. If not just remove the .txt extension
var decryptedfile = "filetoencryptDecrypted.txt";
encryptfile(path.join(__dirname, "fde",  "text", filetoencrypt), path.join(__dirname, "fde",  "text", encryptedfile),"aes-128-cbc",key_dek_fde,iv_cbc_fde_1);
decryptfile(path.join(__dirname, "fde", "text", encryptedfile), path.join(__dirname, "fde",  "text", decryptedfile),"aes-128-cbc",key_dek_fde,iv_cbc_fde_1);

//jpg folder encrypt
filetoencrypt = "filetoencrypt.jpg";
encryptedfile = "filetoencryptEncrypted.txt"; //show off in txt form to show it's encrypted gibberish. If not just remove the .txt extension
decryptedfile = "filetoencryptDecrypted.jpg";
encryptfile(path.join(__dirname, "fde",  "jpg", filetoencrypt), path.join(__dirname, "fde",  "jpg", encryptedfile),"aes-128-cbc",key_dek_fde,iv_cbc_fde_2);
decryptfile(path.join(__dirname, "fde",  "jpg", encryptedfile), path.join(__dirname, "fde",  "jpg", decryptedfile),"aes-128-cbc",key_dek_fde,iv_cbc_fde_2);



///////////////////////////////////////////////FBE encryptions
//tested txt and JPG encryption and decryption works
//text folder encrypt
filetoencrypt = "filetoencrypt.txt";
encryptedfile = "filetoencryptEncrypted.txt"; //show off in txt form to show it's encrypted gibberish. If not just remove the .txt extension
decryptedfile = "filetoencryptDecrypted.txt";
encryptfile(path.join(__dirname, "fbe",  "text", filetoencrypt), path.join(__dirname, "fbe",  "text", encryptedfile),"aes-256-xts",key_xts_1,sectornumber_1);
decryptfile(path.join(__dirname, "fbe", "text", encryptedfile), path.join(__dirname, "fbe",  "text", decryptedfile),"aes-256-xts",key_xts_1,sectornumber_1);

//jpg folder encrypt
filetoencrypt = "filetoencrypt.jpg";
encryptedfile = "filetoencryptEncrypted.txt"; //show off in txt form to show it's encrypted gibberish. If not just remove the .txt extension
decryptedfile = "filetoencryptDecrypted.jpg";
encryptfile(path.join(__dirname, "fbe",  "jpg", filetoencrypt), path.join(__dirname, "fbe",  "jpg", encryptedfile),"aes-256-xts",key_xts_2,sectornumber_2);
decryptfile(path.join(__dirname, "fbe",  "jpg", encryptedfile), path.join(__dirname, "fbe",  "jpg", decryptedfile),"aes-256-xts",key_xts_2,sectornumber_2);


var list = crypto.getCiphers();
/* GET home page. */
router.get('/', function(req, res, next) {
   

  //render lets you import variables into the html file which is index.ejs
  res.render('index', { title: 'Express', password, salt,dek_fbe, dek_fde, frontikpad, backikpad, privateKey, publicKey, scrypt1hash,  rsaencrypted,ik1pad,scrypt2hash,kek,iv,DEK_encrypted_FDE,auth_tag_gcm,key_gcm,iv_gcm,DEK_encrypted_FBE,nonce_1,nonce_2,pfk_1,pfk_2,ivforxts_1,ivforxts_2,encryptcontent_1,encryptcontent_2});
});

module.exports = router;

//const encOutput = fs.createWriteStream(path.join(__dirname, "filetoencrypt.txt.enc"));