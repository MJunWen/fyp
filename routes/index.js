//define constants here to use in the html
//start server by cd to directory, then open cmd and type nodemon run start
var express = require('express');
var router = express.Router();
const crypto = require('crypto');

const password = 'androidencryption';
const salt = crypto.randomBytes(16).toString("hex")
const frontikpad = "0";
const backikpad = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
//backikpad is 223 bytes of 0
//placeholder
const dek = crypto.randomBytes(64).toString("hex")
const nonce1 = crypto.randomBytes(16).toString("hex")

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
cipher = crypto.createCipheriv("aes-128-ecb", key, null)
cipher.setAutoPadding(false)
result = cipher.update(src).toString('hex');
result += cipher.final().toString('hex');

/* GET home page. */
router.get('/', function(req, res, next) {
   

  //render lets you import variables into the html file which is index.ejs
  res.render('index', { title: 'Express', password, salt,dek, frontikpad, backikpad, privateKey, publicKey, scrypt1hash,  rsaencrypted,ik1pad,scrypt2hash,kek,iv,nonce1,result});
});

module.exports = router;
