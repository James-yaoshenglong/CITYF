var express = require('express');
var router = express.Router();
var flag = "CITYF{c00ki3_Is_fun_123456}"

/* GET home page. */
router.get('/', function(req, res, next) {
  var buf = new Buffer(flag);
  res.cookie("flag", buf.toString("base64"));
  res.render('index', { title: 'BabyEcho' });
});


module.exports = router;
