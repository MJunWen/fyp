var express = require('express');
var router = express.Router();
const crypto = require('crypto');

/* GET home page. */
router.get('/', function(req, res, next) {
   
  const secret = 'abcdefg';
  const hash = crypto.createHmac('sha256', secret)
                    .update('I love cupcakes')
                    .digest('hex');
  console.log(hash);

  res.render('index', { title: 'Express', hash });
});

module.exports = router;
