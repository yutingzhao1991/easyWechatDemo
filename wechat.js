var http = require('http');
var crypto = require('crypto');

var config = require('./config');

var getReply = function(message) {
	// api doc : http://mp.weixin.qq.com/wiki/index.php?title=%E6%B6%88%E6%81%AF%E6%8E%A5%E5%8F%A3%E6%8C%87%E5%8D%97
	// you can rewrite this function to get you own wechat service.
	console.log('get user message : ' + message);
	return message;
};


//////////////////////////////////////////// Lib start ///////////
//查找queryString中key对应的value
var queryString = function(url, key) {
	var re = new RegExp('(?:\\?|&|#)' + key + '=(.*?)(?=&|$)', 'i');
    var r = '',
        m;
    if ((m = re.exec(url)) != null) r = decodeURIComponent(m[1]);
    return r;
};

//开发者通过检验signature对请求进行校验（下面有校验方式）。
//若确认此次GET请求来自微信服务器，请原样返回echostr参数内容，则接入生效，否则接入失败。
var judgeAuthentication = function(token, signature, timestamp, nonce) {
    //加密/校验流程：
    //1. 将token、timestamp、nonce三个参数进行字典序排序
    //2. 将三个参数字符串拼接成一个字符串进行sha1加密
    //3. 开发者获得加密后的字符串可与signature对比，标识该请求来源于微信
    var shasum = crypto.createHash('sha1');
    var arr = [token, timestamp, nonce].sort();
    shasum.update(arr.join(''));

    return shasum.digest('hex') === signature;
};

function decodeRequest(data){
    var result = {};
    try{
        result.msgType = data.match(/<MsgType><\!\[CDATA\[(\S+)\]\]><\/MsgType>/)[1];
        result.toUser = data.match(/<ToUserName><\!\[CDATA\[(\S+)\]\]><\/ToUserName>/)[1];
        result.fromUser = data.match(/<FromUserName><\!\[CDATA\[(\S+)\]\]><\/FromUserName>/)[1];
        result.content = data.match(/<Content><\!\[CDATA\[(.+)\]\]><\/Content>/)[1];
    } catch (e) {
        console.log(e);
    }
    return result;
};

function encodeResponse(data, userData) {
	// reply template
	var content = [
		'<xml>',
		   '<ToUserName><![CDATA[',
		   userData.fromUser,
		   ']]></ToUserName>',
		   '<FromUserName><![CDATA[',
		   userData.toUser,
		   ']]></FromUserName>',
		   '<CreateTime>',
		   Date.now(),
		   '</CreateTime>',
		   '<MsgType><![CDATA[text]]></MsgType>',
		   '<Content><![CDATA[',
		   data,
		   ']]></Content>',
		'</xml>'
	];
	return content.join('');
};
/////////////////////////////////////////////  start server /////////////

http.createServer(function (req, res) {
////////////////////// home page

	if (req.url == '/') {
		// default welcome page
		res.writeHead(200, {'Content-Type': 'text/plain'});
    	res.end('Hello World\n');
	}

//////////////////////  404 not found

	if (req.url != config.path) {
		// error path
		// return 404
		res.writeHead(404, {'Content-Type': 'text/plain'});
		res.end('404 Not Found!\n');
		return;
	}

///////////////////// service for wechat

	if (req.method == 'GET') {
		// authenticate
	    var signature = queryString(req.url, 'signature');//   微信加密签名
	    var timestamp = queryString(req.url, 'timestamp');//   时间戳
	    var nonce = queryString(req.url, 'nonce');//    随机数
	    var echostr = queryString(req.url, 'echostr'); //随机字符串
	    if(judgeAuthentication(config.token, signature, timestamp, nonce, echostr)) {
	        // authenticate success
	        res.writeHead(200, {'Content-Type': 'text/plain'});
    		res.end(echostr);
	    } else {
	    	// authenticate error
	    	res.writeHead(500, {'Content-Type': 'text/plain'});
			res.end('error untrusted!\n');
	    }
	} else if (req.method == 'POST') {
	    // parse
	    var data = '';
	    req.setEncoding('utf8');
	    req.on('data', function(chunk){ data += chunk });
	    req.on('end', function() {
	    	var userData = decodeRequest(data);
	        res.writeHead(200, {'Content-Type': 'text/xml'});
    		res.end(encodeResponse(getReply(userData.content || ''), userData));
	    });
	} else {
		// error method
		// return 500
		res.writeHead(500, {'Content-Type': 'text/plain'});
		res.end('error request method!\n');
	}

}).listen(80, '127.0.0.1');

console.log('Server has running ...');