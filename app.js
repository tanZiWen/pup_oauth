/**
 * Module dependencies.
 */

//-init global
require('./globalExtention');

//-init app
var express = require('express');
var routes = require('./routes');
var http = require('http');
var path = require('path');
var moment = require('moment');
var jwt = require('express-jwt');
var fs = require('fs');

moment.lang('zh-cn');

var app = express(),
    server = http.createServer(app),
    G = require('./lib/global.js');

var _ = require('underscore'),
    userOperateLogDao = require('./db/upm/userOperateLogDao');
_s = require('underscore.string');


var redis = require('redis');
var sessionClient = redis.createClient(global.appCfg.redis.port, global.appCfg.redis.host, {"return_buffers": true});
var RedisStore = require('connect-redis')(express);
var session = express.session({ store: new RedisStore({client: sessionClient, prefix: "ps:", ttl: global.appCfg.sessionTimeout.redis}), key: 'pups', cookie: { maxAge: global.appCfg.sessionTimeout.cookie }});
var domain = require('domain');
var serverDomain = domain.create();
var appLogger = global.lib.logFactory.getAppLogger();
var logger = global.lib.logFactory.getModuleLogger(module);
var dbs = require('./db/dbs');
var multer = require('multer');
var groupHandlers = require('express-group-handlers');


serverDomain.on('error', function(err) {
    appLogger.error('[server domain] : ' + err.stack);
});

// all environments

app.set('port', process.env.PORT || 9088);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.json());
app.use(express.urlencoded());
app.use(express.methodOverride());
app.use(express.cookieParser('pups'));
app.use(function(req, res, next) {
    var serverDomain = domain.create();
    serverDomain.on('error', function(err) {
        if(!err) {
            err = {msg : "noting"};
        }
        appLogger.error('[server domain] : ' + JSON.stringify(err));
    });
    serverDomain.add(req);
    serverDomain.add(res);
    serverDomain.run(next);
});
//app.use(session);
//app.use(express.session({ store: new RedisStore }));


/**
 * App configuration.
 */


app.use('/auth/user', express.static(__dirname +'/heatcanvas'));

app.use(function (req, res, next) {
    res.set({
        'Access-Control-Allow-Origin' : res.get('Origin'),
        'Access-Control-Allow-Credentials' : 'true',
        'Access-Control-Allow-Methods' : 'POST, PUT, GET, OPTIONS, DELETE',
        'Access-Control-Max-Age' : '3600',
        'Access-Control-Allow-Headers' : 'Origin, No-Cache, X-Requested-With, If-Modified-Since, Pragma, Last-Modified, Cache-Control, Expires, Content-Type, X-E4M-With'
    });
    if(req.session && req.session.user) {
        res.locals.session = req.session;
        sessionClient.expire('ps:user:' + req.session.id, appCfg.sessionTimeout.redis);
    }
    next();
});

console.log(G.UPLOAD_TMP_PATH);

app.use(multer({ dest: G.UPLOAD_TMP_PATH}));
app.use(require('less-middleware')(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

groupHandlers.setup(app);

// development only
if ('product' == app.get('env')) {
    app.use(function(err, req, res, next) {
        logger.error(error);
        if(req.xhr) {
            res.send(500, {errMsg : err.msg});
        } else {
            res.status(500);
            res.render('error', {error : err});
        }
    });
} else {
    app.use(express.errorHandler());
}

//support reverse proxy in the front
if(appCfg.reverseProxy) {
    app.enable('trust proxy');
}


var auth = require('./routes/auth.js'),
    template = require('./routes/template'),
    changePwd = require('./app/upm/changePwd'),
    portal = require('./app/portal')


app.get('/login', auth.loginForm);
app.post('/login', auth.login);
app.get('/logout', auth.logout);

app.get('/forgetPwd', auth.forgetPwd);
app.get('/validateUsername', auth.validateUsername);
app.get('/sendVerifyCode', auth.sendVerifyCode);
app.get('/verifyCode', auth.verifyCode);
app.put('/changePwd', auth.changePwd);
app.get('/setPwd', auth.setPwd);
app.put('/setPwd', auth.changePwd);

app.get('/register', auth.registerForm);
app.post('/register', auth.register);

app.get('/template', template.get);
app.get('/template/config', template.getConfig);

var routeList = function(app) {
    app.post('/changePwd', changePwd.changePwd);
    app.get('/portal/appList', portal.listApp);
    app.get('/:appCode/main', portal.showApp);

    app.get('/external/auth', auth.externalAuth);

    app.get('/', routes.index);
};

function parseCookies (request) {
    var list = {},
        rc = request.headers.cookie;

    rc && rc.split(';').forEach(function( cookie ) {
        var parts = cookie.split('=');
        list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
    return list;
}

var jwtHandler = jwt({
    secret: fs.readFileSync(G.PRIVATE_KEY),
    credentialsRequired: false,
    userProperty: 'jwt',
    getToken: function(req) {
        var cookies = parseCookies(req);
        session = {};
        var token = "";
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            token = req.headers.authorization.split(' ')[1];
        } else if (cookies.authorize_token) {
            token = cookies.authorize_token;
        }else if (req.query && req.query.code) {
            token = req.query.code;
        }
        session.id = token;
        req.session = session;
        return token;
    }
});

app.beforeEach(jwtHandler, auth.checkAuth, routeList);


exports.server = server.listen(app.get('port'), function () {
    console.log('Express server listening on port ' + app.get('port'));
});
