const http = require('http');
const url = require('url');
const crypto = require('crypto');
const { loadConfig, verifyPassword, getUserByUsername} = require('./db');

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

const server = 