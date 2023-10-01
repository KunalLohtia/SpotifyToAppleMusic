// Sets up routes and endpoints for handling Spotify and Apple Music authentication.
// It also generates JSON Web Tokens (JWTs) for Apple Music access.


// initalize packages including express.js, request modules for http requests, cors for allowing webpages to make requests to different domain

let express = require('express')
let request = require('request')
let querystring = require('querystring')
let cors = require('cors')

// instance of express app
let app = express()

// define redirect uri, spotify uses for callback about authentication
let login_redirect_uri = 'http://localhost:8888/callback'

require('dotenv').config();

// public identifier for this app
const client_id = process.env.CLIENT_ID

//used to make requests to spotify api
const secret_client_id = process.env.CLIENT_SECRET


// mount cors middleware to app, process requests before reaching app routes
app.use(cors())

//create login endpoints to redirect to spotfy authorize method

// following scopes needed from Spotify WEB API: 
// user-read-private: Read access to user’s subscription details (type of user account).
// user-read-email: Read access to user’s email address.
// user-library-read: Read access to a user's library.


//route for intiating spotify authentication, response is sending client to authorize accounts for spotify
app.get('/login', function (req, res){
    //pass in as params client id for confirmation, scopes (types of data to access for request), and redirect_uri to send response back
    const login_params = {
        type: 'code', // using OAuth 2.0 authorization code flow 
        client_id: client_id,
        scope: 'user-read-private user-read-email user-library-read',
        redirect_uri: login_redirect_uri
    
    }
    res.redirect( 'https://accounts.spotify.com/authorize?' +
    // encode params as url using stringify method
    querystring.stringify(login_params)
    )
})

// route for call back from spotify after user auth, spotify will send authorization code back, server will then need to use this code to send request Spotify's token endpoint

// Spotify from token endpoint, will send back access token to react app

app.get('/call_back', function(req,res) {
    // retrieve code parameter from query string of url (aka authorization code) that spotify sends back from authorize endpoint back to call back endpoint 
    const authorizationCode = req.query.code;

    // if authorization code not present
    if (!authorizationCode) {
        // return error code
        return res.status(400).send('Authorization code missing');
    }

    // parameters for token exchange request
    const token_exchange_params = {
        grant_type: 'authorization_code', //identifies that app wants authorization code and will exchange for access token
        code: authorizationCode,
        redirect_uri: login_redirect_uri,
        client_id: client_id,
        client_secret: secret_client_id
    }

    // using request module, use post request to spotify token endpoint
    // exchange authorization code for access token
    request.post(
        {
            // token endpoint url
            url: 'https://accounts.spotify.com/api/token',
            // form uses token_exchange_params
            form: tokenParams
        },
        // check if no error and response is 200
        function (error, response, body){
            if (!error && response.statusCode === 200){
                // if passed, parse response for access token
                token_response = JSON.parse(body)

                // successful, so send response to client
                // TO DO redirect client to success page
                res.send('Authorization successful!')

            } else {
                // send error otherwise with status code to client
                console.error('Token exchange failed:', error);
                res.status(response.statusCode).send('Token exchange failed');
            }
        }

    )
})

// generate an Apple Music json web token using the JSON Web Token (JWT) library
// fs module reads files from file system
const jwt = require('jsonwebtoken');
const fs = require('fs');

// json web token params

// my dev id
const dev_id = process.env.APPLE_TEAM_ID;
// TO DO
const key_id = process.env.APPLE_KEY_ID;

// reads private key from p8 file, converts key to string
const apple_priv_key = fs.readFileSync('appleprivkey.p8').toString();

// create jwt token using above params, sent to client to access Apple Music API
// signed with apple private key, payload empty 
const tk = jwt.sign({}, apple_priv_key,{
    algorithm: 'ES256', // using es256 signing algo
    expiresIn: '180d', // token expires 180 days
    issuer: dev_id, // issued by me
    header: {
        alg: 'ES256', // header includes signing algorithm and key id
        kid: key_id
    }
});

// create token endpoint for client to access token

app.get('/token', function(req,res){
    // let client know it is responding back json data in server response
    res.setHeader('Content-Type', 'application/json');
    // converts token to json string, used in response body
    res.send(JSON.stringify({token: tk}));
});

// initialize port and tell server to listen at that port
let port = 8888
console.log('Listening on port ${port}. Go to /login to start authentication process')
app.listen(port)

