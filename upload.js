var dateFormat = require('dateformat');
var hmacsha1 = require('hmacsha1');
var fs = require("fs");
var request = require("request");
const md5File = require('md5-file');
var crypto = require('crypto');
var md5 = crypto.createHash('md5');

// add your info here
var bucket = '';
var operator = '';
var password = '';
var local_path = ''; // current path
var save_path = '';
var post_url = 'http://v0.api.upyun.com/' + bucket;
var password_md5 = md5.update(password).digest('hex');
var local_file_md5 = md5File.sync( __dirname + local_path);

var expiration = Date.parse(new Date()) + 6000;
var date = dateFormat(new Date().getTime(),"GMT:ddd, dd mmm yyyy hh:MM:ss") + " GMT";


var create_policy = function (){
	var policy_before_md5 = {
		"bucket": bucket,
		"save-key":save_path,
		"expiration":expiration,
		"date":date,
		"content-md5":local_file_md5
	};

	var policy = new Buffer(JSON.stringify(policy_before_md5)).toString('base64')
	return policy;
};

var create_sign = function (){
	var hmacsha1 = require('hmacsha1');
	var encrypt_string = 'POST' + '&/' + bucket + '&' + date + '&' + create_policy() + '&' + local_file_md5;
	var hash = crypto.createHmac('sha1', password_md5).update(encrypt_string,'utf8').digest(); // HMAC-SHA1 输出的必须是原生的二进制数据
	var sign = new Buffer(hash).toString('base64');
	return sign;

};

var upload = function (){
	var formData = {
		authorization: "UPYUN " + operator + ":" + create_sign(),
		file: fs.createReadStream(__dirname + local_path),
		policy: create_policy(),
	};

	request.post({url:post_url, formData: formData}, function optionalCallback(err, httpResponse, body) {
	  if (err) {
	    return console.error('upload failed:', err);
	  }
	  if(httpResponse.statusCode != 200){
	  	console.log('Upload err!  err message:', body);
	  }else{
	  	 console.log('Upload successful!  Server responded with:', body);
	  }
	 
	});
};


if (require.main === module) {
	upload();
}