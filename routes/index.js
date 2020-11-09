var express = require('express');
var router = express.Router();
const crypto = require('crypto');
const password = 'androidencryption';
const salt = 'F9DB886899A6B';



/* GET home page. */
router.get('/', function(req, res, next) {
   
  const scrypt = crypto.scryptSync(password, salt, 16);
  scrypt1hash = scrypt.toString('hex');

  res.render('index', { title: 'Express', password, salt, scrypt1hash });
});

module.exports = router;
