var MongoClient = require('mongodb').MongoClient;
var url = 'mongodb://db/ctf';

const query = function (input, res) {
    console.log(input);
    var q = {"$where" : input };
    MongoClient.connect(url, function(err, db) {
        var cursor = db.db("ctf").collection('users').find(q).toArray(function(err, result) {
	console.log(result);
        res.render('index', { title: 'Welcome'+input});
}) ;
    }); 
}

const acquire = function (){
    MongoClient.connect(url, function(err, db) {
        var queryStr = {"userName" : "admin"};
        var admin = db.collection('Employee').find(queryStr).toArray(function (err, result) {
            return result[0];
        });
        return admin;
    }); 
}

module.exports = {query, acquire};
