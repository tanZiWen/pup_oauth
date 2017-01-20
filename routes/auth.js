//var hipilife = require('../db/hipilife.js'),
//	dbcom = require('../db/common.js');
var pup = require('../db/pup.js'),
    idg = require('../db/idg.js'),
    async = require('async');

var _ = require('underscore'),
	_s = require('underscore.string');
var userDao = require('../db/upm/userDao');

var appModel = require('../app/portal/appModel');
var logger = require('../lib/logFactory').getModuleLogger(module);
var redis = require('redis');
var redisClient = redis.createClient(global.appCfg.redis.port, global.appCfg.redis.host, {});
var appCfg = require('../app.cfg.js');
var fnModel = require('../app/portal/fnModel');
var userOperateLogDao = require('../db/upm/userOperateLogDao');
var dictionary = require('../lib/dictionary');
var G = require('../lib/global');
var jwt = require('jsonwebtoken');
var extend = require('util')._extend;
var postgreHelper = require('../db/postgreHelper');
var http = require('http');
var mailHelper = require('../lib/mailHelper');
var cryptoHelper = require('../lib/cryptoHelper');


/*exports.checkAuth = function (req, res, next) {
    if(!req.session || !req.session.user) {
        if(req.xhr) {
            res.send({err : {code : 'unlogin', msg : '您当前未登录'}});
        } else {
            res.redirect('/login');
        }
    } else {
        userOperateLogDao.add(req, next);
    }
};*/

exports.checkAuth = jwtAuthCheck;

function jwtAuthCheck(req, res, next) {
    if(!req.jwt) {
        if(req.xhr) {
            res.send({err : {code : 'unlogin', msg : '您当前未登录'}});
        } else {
	    console.log('target url:', req.originalUrl);
	    if (req.originalUrl == '/') {
		res.redirect('/login')
	    } else {
            	res.redirect('/login?target=' + encodeURIComponent(req.originalUrl));
	    }
        }
    }else {
        var userKey = G.USER_KEY + req.jwt.aud;
        redisClient.get(userKey, function(err, reply) {
            if (err) {
                next(err);
                return;
            }
            user = JSON.parse(reply);
            req.session.user = user;
            res.locals.session = req.session;
            userOperateLogDao.add(req, next);
        });
    }
}

exports.loginForm = function (req, res) {
	if(req.session) {
		delete req.session.user;
	}

	res.render('auth/user/login', { layout: false});
};

exports.registerForm = function (req, res) {
	res.render('auth/user/register', { layout: false});
};

exports.logout = function (req, res) {
//	req.session = null;
//	res.redirect('/login');
    var logoutURLs = appModel.findAllLogoutUrls();
    res.render('auth/user/logout', {logoutURLs:logoutURLs})
};

exports.login = function (req, res) {
	var username = req.body.username,
		password = req.body.password,
        target   = req.query.target? req.query.target : (req.body.target ? req.body.target: null);

    if(_.isEmpty(username) || _.isEmpty(password)) {
        res.json({msg : {type : dictionary.resMsgType.error, body : '用户名或密码不能为空!'}});
    }
    var steps = [];

    steps[0] = function(next) {
            var queryString = "?grant_type=password&username=" + username + "&password=" + password;
            var options = extend({}, G.OAUTH_LOGIN);
            options.path = options.path + queryString;
            http.get(options, function(res) {
                res.on('data', function(data) {
                    authData = JSON.parse(data);
                    req.token = authData;
                    req.session = {id: authData.access_token};
                    next(null, authData);
                });
            }).on('error', function(e){
                next(e);
            });
        };
    steps[1] = function(token, next) {
            var data = "?code=" + token.access_token;
            var options = extend({}, G.OAUTH_USER);
            options.path = options.path + data;
            console.log(token.access_token)
            http.get(options, function(res) {
                var userStr = '';
                res.on('data', function (chunk){
                    userStr += chunk;
                });
                res.on('end',function(){
                    user = JSON.parse(userStr);
                    user.password = 0;
                    req.session.user = user;
                    var userKey = G.USER_KEY + user.username;
                    redisClient.set(userKey, userStr);
                    next(null, true)
                });
            }).on('error', function(e){
                console.log("load userinfo error:", e);
                next(e);
            });
        };

    // steps[2] = function(data, next) {
    //     req.priority = dictionary.userOperatePriority.level1;
    //     userOperateLogDao.add(req, function(err, result) {
    //         if(err) {
    //             next(err);
    //         }else {
    //             next(null, true);
    //         }
    //     });
    // };

    async.waterfall(steps, function(err, data) {
        if(err) {
            res.json({msg : {type : dictionary.resMsgType.error, body : '用户名和密码不匹配。若忘记密码,请点击下方的忘记密码找回密码!'}});
        }else {
            res.cookie("authorize_token", req.token.access_token, {httpOnly: false, path: '/'});
            if (target) {
                target = decodeURIComponent(target);
                if(target.indexOf('?') == -1) {
                    target += '?token=' + req.token.access_token;
                } else {
                    target += '&token=' + req.token.access_token;
                }
                res.json({msg: {type: dictionary.resMsgType.succ, target: target}});
            }
            res.json({msg: {type: dictionary.resMsgType.succ, target: '/'}})
        }
    });
};

exports.register = function (req, res) {
	var email = req.body.email,
		password = req.body.password,
		nickname = req.body.nickname;

	var user = {'email': email, 'pwd': password, 'nm': nickname};
	console.log('Register: ' + JSON.stringify(req.body));

	if (_s.isBlank(email)) {
		return res.render('auth/user/register', { layout: false, user: user, msg: 'email is required'});
	}

	if (_s.isBlank(password)) {
		return res.render('auth/user/register', { layout: false, user: user, msg: 'password is required'});
	}

	if (_s.isBlank(nickname)) {
		return res.render('auth/user/register', { layout: false, user: user, msg: 'nickname is required'});
	}
};

/**
 * 外部系统用户认证
 * @param req
 * @param res
 */
exports.externalAuth = function(req, res) {
    var username = req.param('username');
    var password = req.param('password');
    userModel.authentication(username, password, function(err, user) {
        if(err) {
            res.json({code : err.usrCode, msg : err.usrMsg});
        } else {
            res.json({code : 0, msg : '认证成功'});
        }
    });
};

exports.forgetPwd = function(req, res) {
    res.render('auth/user/forgetPwd', { layout: false});
};

exports.validateUsername = function(req, res) {
    var params = req.query;
    var selectQuery = "select user_id, email, user_name, real_name from upm_user where user_name = $1 and status = 'ok'";
    postgreHelper.userQuery(selectQuery, [params.username], function(err, result) {
        if (err) {
            logger.error('router.auth.validateUsername error:', err.stack);
            res.json(500, {err: err.stack});
        } else {
            var doc = result.rows[0];
            if (_.isEmpty(doc)) {
                res.json({msg: {type: dictionary.resMsgType.error, body: '账号不存在!'}});
            } else {
                if (!doc.email || result.doc == '') {
                    res.json({msg: {type: dictionary.resMsgType.info, body: '邮箱还未设置,请联系管理员设置邮箱后才能找回密码!'}})
                } else {
                    var user = {};
                    user._id = doc.user_id;
                    user.email = doc.email;
                    user.username = doc.user_name;
                    user.realName = doc.real_name;
                    res.json({user: user});
                }
            }
        }
    })
};

exports.sendVerifyCode = function(req, res) {
    var params = req.query;
    var verifyCode = generateCode();
    var cookie = generateCookie();
    var cacheVerifyCodeKey = 'ps:verifycode:' + cookie;
    redisClient.set(cacheVerifyCodeKey, verifyCode, function() {
        redisClient.expire(cacheVerifyCodeKey, appCfg.sessionTimeout.changePwd);
    });
    var con = {};
    con.verifyCode = verifyCode;
    con.email = params.email;
    con.realName = params.realName;
    con.type = 'reset';
    res.cookie("changepwd_token", cookie, {httpOnly: false, path: '/'});
    mailHelper.sendMail(con, function(err, result) {
        if(err) {
            logger.error('router.auth.sendVerifyCode error:', err.stack);
            res.json(500, {err: err.stack});
        }else {
            res.json({msg: {type: dictionary.resMsgType.succ, body: '验证码已发送到你的邮箱!'}});
        }
    });

};

exports.verifyCode = function(req, res) {
    var params = req.query;
    var cookie = parseCookies(req).changepwd_token;
    var cacheVerifyCodeKey = 'ps:verifycode:' + cookie;

    redisClient.get(cacheVerifyCodeKey, function(err, result) {
        if(err) {
            logger.error('router.auth.verifyCode error:', err.stack);
            res.json(500, {err: err.stack});
        }else {
            if(!result) {
                res.json({msg: {type: dictionary.resMsgType.error, body: '验证码已失效!'}});
            }else {
                if(params.verifyCode.trim() == result.trim()) {
                    redisClient.del(cacheVerifyCodeKey);
                    var cacheChangePwdKey = 'ps:changePwd:' + cookie;
                    redisClient.set(cacheChangePwdKey, params._id, function(err) {
                        redisClient.expire(cacheChangePwdKey, appCfg.sessionTimeout.changePwd);
                    });
                    res.json({msg: {type: dictionary.resMsgType.succ, body: '验证成功!'}});
                }else {
                    res.json({msg: {type: dictionary.resMsgType.error, body: '验证码错误!'}});
                }
            }
        }
    })
};

exports.changePwd= function(req, res){
    var params = req.body;
    var cookie = parseCookies(req).changepwd_token;
    var cacheChangePwdKey = 'ps:changePwd:' + cookie;

    var steps = {};

    steps.userid = function(next) {
        redisClient.get(cacheChangePwdKey, next);
    };

    steps.delKey = ['userid', function(next, data) {
        if(data.userid) {
            redisClient.del(cacheChangePwdKey, next);
        }else {
            next(null, false);
        }
    }];

    steps.encrypt = ['delKey', function(next, data) {
        if(data.userid) {
            cryptoHelper.encrypt(params.pwd, next);
        }else {
            next(null, false);
        }
    }];

    steps.updapt = ['encrypt', function(next, data) {
        if(data.encrypt) {
            var updateQuery = "update upm_user set password = $1 where user_id = $2";
            postgreHelper.userQuery(updateQuery, [data.encrypt, data.userid], next);
        }else {
            next(null ,false);
        }
    }];

    async.auto(steps, function(err, result) {
        if(err) {
            logger.error('router.auth.changePwd error:', err.stack);
            res.json(500, {err: err.stack});
        }else {
            if(!result) {
                res.json({msg: {type: dictionary.resMsgType.error, body: '操作超时，请刷新界面后重试!'}});
            }else {
                res.json({msg: {type: dictionary.resMsgType.succ, body: '验证成功!'}});
            }
        }
    });
};

exports.setPwd = function(req, res) {
    var params = req.query;
    var cookie = parseCookies(req).changepwd_token;
    var cacheChangePwdKey = 'ps:changePwd:' + cookie;

    redisClient.get(cacheChangePwdKey, function(err, result) {
        if(err) {
            res.json(500, {err: err.stack});
        }else {
            if(result) {
                redisClient.del(cacheChangePwdKey);
                cacheChangePwdKey = 'ps:changePwd:' + req.session.id;
                redisClient.set(cacheChangePwdKey, result, function(err) {
                    redisClient.expire(cacheChangePwdKey, appCfg.sessionTimeout.setPwd);
                });
                res.render('pwd/setPwd', { layout: false});
            }else {
                res.render('pwd/error', { layout: false, msg: '该链接已失效!'});
            }
        }
    });
};

function generateCode() {
    var code = "";
    var codeLength = 5;
    var selectChar = new Array(0,1,2,3,4,5,6,7,8,9);
    for(var i=0; i<codeLength; i++) {
        var charIndex = Math.floor(Math.random()*10);
        code += selectChar[charIndex];
    }
    return code
}

function generateCookie() {
    var cookie = "";
    var codeLength = 60;
    var selectChar = new Array('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','G','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z');
    for(var i=0; i<codeLength; i++) {
        var charIndex = Math.floor(Math.random()*selectChar.length);
        cookie += selectChar[charIndex];
    }
    return cookie
}

function parseCookies (request) {
    var list = {},
        rc = request.headers.cookie;

    rc && rc.split(';').forEach(function( cookie ) {
        var parts = cookie.split('=');
        list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
    return list;
}

