/**
 * Created by tanyuan on 11/4/15.
 */
var crypto = require('crypto'),
    algorithm = 'aes-256-cbc',
    password = 'd6F3Efeqklsmhjkw8rt5d6svgh3j9K8H6D8',
    logger = require('./logFactory').getModuleLogger(module);

exports.encrypt = function(text, next){
    crypto.pbkdf2(text, 'salt', 4096, 64, 'sha256', function(err, key) {
        if (err) {
            next(err);
        }else {
            next(null, key.toString('hex'));
        }
    });
};

exports.password = function(req, res) {
    var pass = req.query.password;
    crypto.pbkdf2(pass, 'salt', 4096, 64, 'sha256', function(err, key) {
        if (err) {
            console.log(err)
        }else{
            res.send(key.toString('hex'));
        }
    });
};

init();

function init() {
    crypto.pbkdf2("130023", 'salt', 4096, 64, 'sha256', function(err, key) {
        if (err) {

        }else {
            console.log(key.toString('hex'));
        }
    });
}




