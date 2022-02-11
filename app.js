
// SETTINGS - set to fit to your environment
const OIDC_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
const OIDC_TOKEN_ENDPOINT = "https://www.googleapis.com/oauth2/v4/token"
const OIDC_CLIENT_ID = "<YOUR CLIENT ID>.apps.googleusercontent.com"
const OIDC_CLIENT_SECRET = "<YOUR CLIENT SECRET>"
const OIDC_SCOPE = "openid profile email"
const OIDC_REDIRECT_URI = "http://localhost:3000/"


const express = require("express");
const app = express();

// Load external modules
const pkceChallenge = require("pkce-challenge");
const base64url = require('base64url');
const jwt = require('jsonwebtoken');
const webclient = require("request");
const crypto = require("crypto");

// Connect to session db
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('oidc_db.sqlite');
db.serialize();

// create session table
db.run("CREATE TABLE IF NOT EXISTS session (session_id TEXT UNIQUE NOT NULL, pkce_code TEXT, subject_id TEXT, user_info TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')))");


const server = app.listen(3000, function () {
    console.log("Node.js is listening to PORT:" + server.address().port);
});


////////////////////////////////////////////////////////////////////
// generate information needed to access authorization endpoint and return it to client(browser)
app.get("/api/login_info",
    generateSessionIdAtLogin,
    generatePkceAndSaveWithSessionId,
    generateOidcAuthorizationUrl
);

// Generate Session ID and Store to DB
async function generateSessionIdAtLogin(req, res, next) {

    // generate Session ID from random
    const buff = crypto.randomBytes(16);
    const session_id = base64url(buff);

    console.log("SESSION ID generated: " + session_id)

    // Just in case, make sure that no duplicate sessin id is created.
    try {
        const val = await sqlite_read('SELECT * FROM session WHERE session_id = ? ', [session_id]);

        // if duplicate found (that is a catastorophy!)
        if (val) {
            await sqlite_write(`UPDATE session SET active = 0 WHERE session_id = ?`, [session_id]);
            console.error("duplicate session id at generateSessionIdAtLogin: " + val);
            res.json({ error: "server error (0101)" });
            next("session id already exists")
        }

    } catch (err) {
        console.error("DB　error at generateSessionIdAtLogin: " + err);
        res.json({ error: "server error (0102)" });
        next("db error at validateSessionIdAtLogin")
    }

    // save session_id and go to next
    if (!req.oidcspa) req.oidcspa = new Object();
    req.oidcspa.session_id = session_id
    next();
}

// Generate PCKE code and save to DB
async function generatePkceAndSaveWithSessionId(req, res, next) {

    session_id = req.oidcspa.session_id;
    // generate PCKE
    const pkce = pkceChallenge();
    const challenge = pkce.code_challenge;
    const verifier = pkce.code_verifier;

    // save session_id and PKCE code(verifier)
    await sqlite_write(`INSERT INTO session (session_id, pkce_code) VALUES (?, ?)`, [session_id, verifier]);

    // save challenge
    req.oidcspa.pkce_challenge = challenge;

    next();

}

// generate OIDC URL and return
async function generateOidcAuthorizationUrl(req, res, next) {

    // if redirect_uri varies depends on the client type, do something here
    redirect_uri = OIDC_REDIRECT_URI

    // if Authorization endpoint already has query parameters, 
    // additional parameters should be concatenated with "&"
    if (OIDC_AUTH_ENDPOINT.includes('?')) {
        connector = '&'
    } else {
        connector = '?'
    }

    // generate OIDC request url
    oidc_url = OIDC_AUTH_ENDPOINT + connector + "response_type=code" +
        "&client_id=" + OIDC_CLIENT_ID +
        "&scope=" + encodeURIComponent(OIDC_SCOPE) +
        "&redirect_uri=" + encodeURIComponent(redirect_uri) +
        "&code_challenge=" + req.oidcspa.pkce_challenge +
        "&prompt=select_account" +
        "&code_challenge_method=S256";

    res.json({ url: oidc_url, session_id: req.oidcspa.session_id });

}



////////////////////////////////////////////////////////////////////
// get authorization code from client(browser) and send it to IDP to get id_token
app.get("/api/auth_code",
    getSessionIdFromRequest,
    getPkceVerifierWithSessionId,
    retrieveTokenFromIdp
);

// look up code_verifier
async function getPkceVerifierWithSessionId(req, res, next) {

    session_id = req.oidcspa.session_id;
    console.log("getPkceVerifierWithSessionId " + session_id);

    try {
        const val = await sqlite_read('SELECT * FROM session WHERE session_id = ? AND active = 1', [session_id]);
        console.log(val);
        if (val) {
            // pkce_verifier is found
            if (!req.oidcspa) req.oidcspa = new Object();
            req.oidcspa.pkce_verifier = val.pkce_code
            next()
        } else {
            res.json({ error: "server error(0201)" });
            next("pkce_code not found with sessionid");
        }
    } catch (err) {
        console.error("error at getPkceVerifierWithSessionId: " + err);
        res.json({ error: "server error (0202)" });
        next("error at getPkceVerifierWithSessionId ")
    }

}

// request id_token to IDP
async function retrieveTokenFromIdp(req, res, next) {

    // PKCE code_verifier
    const verifier = req.oidcspa.pkce_verifier;

    // authorization code
    const authCode = req.query.code;

    // token request to IDP
    webclient.post({
        url: OIDC_TOKEN_ENDPOINT,
        headers: {
            "content-type": "application/x-www-form-urlencoded"
        },
        body: "code=" + authCode +
            "&client_id=" + OIDC_CLIENT_ID +
            "&client_secret=" + OIDC_CLIENT_SECRET +
            "&redirect_uri=" + encodeURIComponent(OIDC_REDIRECT_URI) +
            "&code_verifier=" + verifier +
            "&grant_type=authorization_code"
    }, function (error, response, body) {
        if (error) {
            console.error("token endpoint request error: " + body)
            res.json({ error: "login error (0301)" });
        }

        console.log("IDP token response: " + body);
        var json = JSON.parse(body)

        // decode id_token
        var decoded = jwt.decode(json.id_token);
        if (!decoded) {
            console.error("jwt decode error: " + body)
            res.json({ error: "login error (0302)" });
        } else {
            // save user_info
            sqlite_write('update session set user_info = ?, subject_id = ? where session_id = ? ', [JSON.stringify(decoded), decoded.sub, session_id]);

            //return user_info
            res.json({ responce: decoded });
        }
    });

}


////////////////////////////////////////////////////////////////////
// get user_info saved in db and return to client(browser)
app.get("/api/user_info",
    getSessionIdFromRequest,
    getUserInfoWithSessionId
);

// lookup user_info from DB
async function getUserInfoWithSessionId(req, res, next) {

    session_id = req.oidcspa.session_id;
    console.log("getUserInfoWithSessionId " + session_id);

    try {
        const val = await sqlite_read('SELECT * FROM session WHERE session_id = ? AND active = 1', [session_id]);
        console.log(val);
        if (val) {
            res.json({ sub: val.subject_id, user_info: val.user_info });
        } else {
            console.error("user_info not found with sessionid ");
            res.json({ error: "server error (0401)" });
            next("user_info not found with sessionid");
        }
    } catch (err) {
        console.log("db error at getUserInfoWithSessionId: " + err);
        res.json({ error: "server error (0402)" });
        next("error at getUserInfoWithSessionId: ")
    }

}


////////////////////////////////////////////////////////////////////
// deactivate session
app.get("/api/logout",
    getSessionIdFromRequest,
    deactivateSessionId
);
// deactivate session
async function deactivateSessionId(req, res, next) {

    session_id = req.oidcspa.session_id;

    await sqlite_write(`UPDATE session SET active = 0 WHERE session_id = ?`, [session_id]);

    res.json({ success: "log out" });


}

////////////////////////////////////////////////////////////////////
// shared function: retrieve session_id from Authorization Header
function getSessionIdFromRequest(req, res, next) {
    //Authorization Hedder
    const authHeader = req.headers["authorization"];

    //is Authorization header set
    if (authHeader == undefined) {
        console.error("Authorization header not set");
        res.json({ error: "Authorization header not set" });
        next("Authorization header not set");
    }
    //is Bearer exists
    if (authHeader.split(" ")[0] !== "Bearer") {
        console.error("Bearer does not exists in Authorization header");
        res.json({ error: "Bearer does not exists in Authorization header " });
        next("Bearer does not exists in Authorization header");
    }

    // save session_id to request object
    if (!req.oidcspa) req.oidcspa = new Object();
    req.oidcspa.session_id = authHeader.split(" ")[1];
    next();
}

////////////////////////////////////////////////////////////////////
// shared founction: make sqlite async
// source: https://note.kiriukun.com/entry/20190915-sqlite3-on-nodejs-with-await

function sqlite_read(sql, params) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            console.log("sqlite_read: " + sql + JSON.stringify(params))
            if (err) {
                console.error("sqlite_read: " + err)
                reject(err);
            }
            console.log("sqlite_read: " + JSON.stringify(row))
            resolve(row);
        });
    });
}

function sqlite_write(sql, params) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, (err) => {
            console.log("sqlite_write: " + sql + JSON.stringify(params))
            if (err) {
                console.error("sqlite_write: " + err)
                reject(err);
            }
            resolve();
        });
    });
}


////////////////////////////////////////////////////////////////////
// render html

app.set('view engine', 'ejs');

app.get("/", function (req, res, next) {
    // please note that there is no dynamic content in html.
    res.render("index", {});
});

