var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [
  /*
   * Enter client information here
   */
	 {
		 "client_id" : "oauth-client-1",
		 "client_secret" : "oauth-client-secret-1",
		 "redirect_uris" : ["http://localhost:9000/callback"],
	 }

];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){

	/*
	 * Process the request, validate the client, and send the user to the approval page
	 */
	var client = getClient(req.query.client_id);

	if (!client) {
		// there is no client with that name
		res.render('error', {error: 'Unknown client'});
		return;

	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		//The URI used is not in the list of registered URIs for this client
		console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	}

	var reqid = randomstring.generate(8);
	requests[reqid] = req.query;

	res.render('approve', {client : client, reqid: reqid});
	return;

});

app.post('/approve', function(req, res) {

	/*
	 * Process the results of the approval page, authorize the client
	 */

	 //Test if this id
	 var reqid = req.body.reqid;
	 var query = requests[reqid];

	 delete  requests[reqid];

	 if (!query) {
		 res.render('error', {error : 'No matching authorization request'});
		 return;
	 }

	 if (req.body.approve) {

		 //User approved
		 if (query.response_type == 'code') {

			 var code = randomstring.generate(8);
			 codes[code] = {request : query};
			 var urlParsed = buildUrl(query.redirect_uri, {code: code, state : query.state});
			 res.redirect(urlParsed);
			 return;

		 } else {

			 // Response type not supported
			 var urlParsed = buildUrl(query.redirect_uri, {error: 'unsupported_response_type'});
			 res.redirect(urlParsed);
			 return;
		 }

	 } else {

		 // User denied (or something else happened, no explicit approve is always a deny)
		 var urlParsed = buildUrl(query.redirect_uri, {error: 'access_denied'});
		 res.redirect(urlParsed);
		 return;
	 }

});

app.post("/token", function(req, res){

	/*
	 * Process the request, issue an access token
	 */

	 /*
 		Test valid client
 	*/

	//Try get client infor from headers
	var auth = req.headers['authorization'];
	if (auth) {
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}

	//Try get client id from form body
	if (req.body.client_id) {
		if (clientId) {
			//client tried to submit client info both in header and in form body
			console.log('ERROR: Client submitted client info in both header and form body')
			res.status(401).json({error : 'invalid_client'});
			return;
		}
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}

	//Test that client is registered
	var client = getClient(clientId);
	if (!client) {
		console.log('ERROR: Client %s not registered', clientId)
		res.status(401).json({error : 'invalid_client'});
		return;
	}

	//Test that client secret match
	if (client.client_secret != clientSecret) {
		console.log('ERROR: Client secret no match')
		res.status(401).json({error : 'invalid_client'});
		return;
	}

	// Test of valid client done

	/*
		Work on issuing the token
	*/

	if (req.body.grant_type == 'authorization_code') {

		var code = codes[req.body.code];

		if (code) {
			delete codes[req.body.code];
			if (code.request.client_id == clientId) {

				//Create token
				var access_token = randomstring.generate();

				//Save token in data base
				nosql.insert({access_token : access_token, client_id: clientId});

				//Send token back to user
				var token_response = {access_token: access_token, token_type: 'Bearer'};
				res.status(200).json(token_response);

			} else {
				//Code does not match this client
				console.log('ERROR: For code %s, expected client %s got client %s', code,code.request.client_id, clientId)
				res.status(400).json({error : 'invalid_grant'});
				return;
			}

		} else {
			//No valid code
			res.status(400).json({error : 'invalid_grant'});
			return;
		}

	} else {
		//Not recognized req.body.grant_type
		res.status(400).json({error : 'unsupported_grant_type'});
		return;
	}



});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}

	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);
	return { id: clientId, secret: clientSecret };
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
