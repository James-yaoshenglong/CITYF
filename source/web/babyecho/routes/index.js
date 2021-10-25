var express = require('express');
var router = express.Router();
var db = require('../db/db');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'BabyEcho' });
});

router.post('/', function(req, res, next) {
  const result = db.query(req.body.userName, res);
});


module.exports = router;
