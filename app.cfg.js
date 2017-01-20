/**
 * Created by wangnan on 14-4-15.
 */
var G = require('./lib/global');

exports.reverseProxy = false;

exports.mongodb = {
    upm : {
        url : 'mongodb://192.168.8.205:27017/upm',
        options : {
            db: { native_parser: true },
            server: { poolSize: 5 },
            replset: { rs_name: 'upm_test' }
            , user: 'prosnav'
            , pass: 'Pr0snav4332$'
        },
        keepAlive : 5
    }
};

exports.user_postgres = {
    url: "postgres://psoauth:Pr0nsav@1234@192.168.8.205:5432/oauth"
};

exports.redis = {'host': '127.0.0.1', 'port': 6379};

exports.page = {'sizeOfPhone': 20};

exports.UP_DIR = {'ROOT': '/var/www/', 'USER': 'u/'};

exports.TEMP_DIR = '/tmp/';

exports.IMG_SIZE = {
    'LARGE': {'width': 480, 'height': 480, 'quality': 89},
    'THUMBNAIL': {'width': 120, 'height': 90, 'quality': 89},
    'AVATAR': {'width': 180, 'height': 180, 'quality': 89}
};

exports.unCheckUrls = [
    '/',
    '/login',
    '/logout',
    '/template',
    '/template/config',
    '/register'
];

exports.callCenter = {
    valid : true,
    address : '218.80.1.68:8089',
    recordingAddress : '192.168.8.206:55503',
    uiAddress : '218.80.1.68:55505'
};

exports.server = {
    ip : '218.80.1.68',
    port : '10086'
};

exports.sessionTimeout = {
    setPwd: 1000 * 60 * 60 * 24,
    changePwd: 1000 * 60,
    redis : 12 * 60 * 60,
    cookie : 12 * 60 * 60 * 60 * 1000
};

exports.nodejsTogoRequestOptions = {
    host: G.NEW_SERVER_HOST,
    port: G.NEW_SERVER_PORT,
    method: 'POST',
    headers: {
        'Security-Key': G.KEYSECRET
    }
};
