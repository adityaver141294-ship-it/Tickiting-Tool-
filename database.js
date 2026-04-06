const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

// Connect to SQLite database (will create a file if not exists)
const dbFile = process.env.DB_PATH || 'database.sqlite';
const dbPath = path.resolve(__dirname, dbFile);
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    initDb();
  }
});

// Run query and return a Promise
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) {
        console.error('Error running sql ' + sql, err.message);
        reject(err);
      } else {
        resolve({ id: this.lastID, changes: this.changes });
      }
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

const initDb = async () => {
  try {
    // Create Users Table
    await run(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        department TEXT,
        role TEXT DEFAULT 'user',
        active INTEGER DEFAULT 1,
        createdAt TEXT
      )
    `);

    // Create Tickets Table
    await run(`
      CREATE TABLE IF NOT EXISTS tickets (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        priority TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        userId TEXT NOT NULL,
        userName TEXT,
        userEmail TEXT,
        department TEXT,
        createdAt TEXT,
        updatedAt TEXT
      )
    `);

    // Create Comments/Activity Table
    await run(`
      CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticketId TEXT NOT NULL,
        by TEXT NOT NULL,
        text TEXT NOT NULL,
        isWorkNote INTEGER DEFAULT 0,
        at TEXT,
        FOREIGN KEY(ticketId) REFERENCES tickets(id) ON DELETE CASCADE
      )
    `);

    // Ensure there is at least one admin account
    const admin = await get(`SELECT id FROM users WHERE role = 'admin' LIMIT 1`);
    if (!admin) {
      const adminPass = process.env.INITIAL_ADMIN_PASSWORD || 'admin123';
      const hash = await bcrypt.hash(adminPass, 12);
      await run(`
        INSERT INTO users (id, name, email, password, department, role, active, createdAt) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, ['USR-Admin', 'System Admin', 'admin@ticketflow.com', hash, 'IT', 'admin', 1, new Date().toISOString()]);
      console.log(`Created default admin: System Admin / ${adminPass === 'admin123' ? 'admin123 (Change this!)' : '[HIDDEN]'}`);
    }
  } catch (error) {
    console.error("Failed setting up DB tables", error);
  }
};

module.exports = { db, run, all, get };
