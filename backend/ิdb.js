const oracledb = require('oracledb');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

function loadConfig() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
}

let pool = null;
async function getPool() {
  if (pool) return pool;
  try {
    const cfg = loadConfig();
    pool = await oracledb.createPool({
      user: cfg.db.user,
      password: cfg.db.password,
      connectString: cfg.db.connectString,
      poolMin: 1,
      poolMax: 5,
    });
    return pool;
  } catch (e) {
    console.error('DB pool creation failed:', e.message);
    pool = null;
    return null;
  }
}

// ---- password hashing (scrypt) ----
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(plain, stored) {
  if (!stored || !stored.startsWith('scrypt:')) return false;
  const [, salt, hash] = stored.split(':');
  const check = crypto.scryptSync(plain, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

async function getUserByUsername(username) {
  const p = await getPool();
  if (!p) return null;
  const conn = await p.getConnection();
  try {
    const result = await conn.execute(
      `SELECT id, username, password_hash, full_name, department_id, branch_id, role, active
       FROM users WHERE username = :username`,
      { username }
    );
    return result.rows[0] || null;
  } finally {
    await conn.close();
  }
}

module.exports = { getPool, loadConfig, hashPassword, verifyPassword, getUserByUsername };