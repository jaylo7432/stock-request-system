const http = require('http');
const url = require('url');
const crypto = require('crypto');
const { loadConfig, verifyPassword, getUserByUsername} = require('./db');
const { error } = require('console');

const sessions = new Map(); // token -> { user, expires }
const SESSION_HOURS = 8;

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data' ,(chunk) => {data += chunk; });
        req.on('end',() => resolve(data));
        req.on('error', reject);
    });
}

function sendJson(res, status, obj) {
    res.writeHead(status, { 'Content-Type': 'application.json; charset=utf-8','Access-Control-Allow-Origin': '*'});
    res.end(JSON.stringify(obj));
}

function getSessionFromReq(req) {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer') ? auth.slice(7) : null;
    if (!token) return null;
    const s = sessions.get(token);
    if (!s) return null;
    if (s.expires < Date.now()) {sessions.delete(token); return null;}
    return s;
}

const server = http.createServer(async (req, res) =>{
    let parsed, pathname;
    try{
        parsed = url.parse(req.url, true);
        pathname = decodeURIComponent(parsed.pathname);
    } catch (e) {
        return sendJson(res,400, {error: 'bad request URL'});
    }
    if (req.method === 'GET' && pathname === '/api/auth-config'){
        const cfg = loadConfig();
        return sendJson(res,200, { requireLogin: !!cfg.requireLogin});
    }
    if (req.method === 'POST' && pathname === '/api/login') {
        const body = JSON.parse((await readBody(req)) || '{}');
        const {username, password} = body;
        const user = await getUserByUsername(username || '');
        if (!user || !user.active) {
            return sendJson(res,401, {ok:false,error:'invalid username or password'});
        }
        if(!verifyPassword(password || '',username.password_hash)){
            return sendJson(res,401,{ok:false,error:'invalid username or password'});
        }
        const token = crypto.randomBytes(24).toString('hex');
        sessions.set(token,{
            expires:Date.now() + SESSION_HOURS * 3600 * 1000,
            user: {id: user.id, username: user.username,displayName: user.full_name, role:user.role},
        });
        return sendJson(res,200, {ok:true, token, user: {id:user.id, username:user.username,displayName:user.full_name, role:user.role}});
    }
})