'use strict';

const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const path         = require('path');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const jwt          = require('jsonwebtoken');
const db           = require('./database');

const app = express();

// JWT Secret Key — load from .env or use fallback for development
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_change_me_in_prod_123!';
const TOKEN_EXPIRY = '30d'; // Keep logged in on mobile for 30 days

// ================================================================
// MIDDLEWARE: AUTHENTICATION & AUTHORIZATION
// ================================================================

// Verify if the request has a valid JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired or invalid token.' });
    req.user = user;
    next();
  });
}

// Verify if the user has the 'admin' role
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Administrative access required.' });
  }
  next();
}

// ================================================================
// 1. SECURITY HEADERS — helmet sets 11 HTTP headers automatically
//    Prevents XSS, clickjacking, MIME sniffing, etc.
// ================================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"], // required for inline <script> blocks
      styleSrc:    ["'self'", "'unsafe-inline'"],
      fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:      ["'self'", 'data:'],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Allow emoji-based SVG icons
}));

// ================================================================
// 2. CORS — restrict to same origin only in production
//    In development allow localhost variants
// ================================================================
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:3000', 'http://localhost:8080', 'https://api.svmastt.com'];

app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server (no origin) and explicitly listed origins
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS: origin not allowed'));
  },
  methods:     ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: false,
}));

// ================================================================
// 3. REQUEST BODY SIZE LIMIT — prevent DoS via huge payloads
// ================================================================
app.use(express.json({ limit: '50kb' })); // Block payloads > 50 KB

// ================================================================
// 4. RATE LIMITERS
// ================================================================

// 4a. Login — max 10 attempts per 15 min per IP (brute-force protection)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again after 15 minutes.' },
  skipSuccessfulRequests: true, // Only count failures toward the limit
});

// 4b. General API — max 200 requests per 15 min per IP
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', loginLimiter);

// ================================================================
// 5. STATIC FILES — serve frontend
// ================================================================
app.use(express.static(__dirname));

// ================================================================
// 6. INPUT SANITISATION HELPER
// ================================================================
function sanitize(str, maxLen = 255) {
  if (str === null || str === undefined) return '';
  return String(str).trim().slice(0, maxLen);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

const ALLOWED_CATEGORIES   = ['IT Support', 'HR', 'Finance', 'Facilities', 'Software', 'Other'];
const ALLOWED_PRIORITIES   = ['low', 'medium', 'high', 'critical'];
const ALLOWED_STATUSES     = ['open', 'inprogress', 'resolved', 'closed'];
const ALLOWED_DEPARTMENTS  = ['IT', 'HR', 'Finance', 'Sales', 'Marketing', 'Engineering', 'Operations', 'Legal', 'General'];

// ================================================================
// ERROR RESPONSE HELPER — never leak stack traces in production
// ================================================================
const isProd = process.env.NODE_ENV === 'production';
function serverError(res, err, msg = 'Internal server error') {
  console.error('[ERROR]', err?.message || err);
  res.status(500).json({ error: isProd ? msg : (err?.message || msg) });
}

// ================================================================
// API ROUTES
// ================================================================

// ---- Authentication ----
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const username = sanitize(req.body?.username, 100);
    const password = req.body?.password;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    if (typeof password !== 'string' || password.length > 128) {
      return res.status(400).json({ error: 'Invalid credentials.' });
    }

    const user = await db.get(
      `SELECT * FROM users WHERE LOWER(name) = LOWER(?)`, [username]
    );

    // Use a constant-time comparison placeholder to prevent user-enumeration timing attacks
    if (!user) {
      await bcrypt.compare(password, '$2b$10$invalidhashpaddingtoconstanttime');
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    if (!user.active) {
      return res.status(403).json({ error: 'Account has been disabled. Contact your administrator.' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid username or password.' });

    // Login successful — generate signed JWT
    const payload = {
      id:   user.id,
      name: user.name,
      role: user.role,
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

    // Send back full user metadata (except password digest) + token
    delete user.password;
    res.json({ token, user });
  } catch (err) {
    serverError(res, err);
  }
});

// ---- Users (ADMIN ONLY) ----
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.all(
      `SELECT id, name, email, department, role, active, createdAt FROM users`
    );
    res.json(users);
  } catch (err) { serverError(res, err); }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const name       = sanitize(req.body?.name, 100);
    const email      = sanitize(req.body?.email, 200);
    const password   = req.body?.password;
    const department = sanitize(req.body?.department, 50);

    // Validate required fields
    if (!name)  return res.status(400).json({ error: 'Full name is required.' });
    if (!email) return res.status(400).json({ error: 'Email is required.' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'A valid email address is required.' });
    if (!password || typeof password !== 'string') return res.status(400).json({ error: 'Password is required.' });
    if (password.length < 6)  return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    if (password.length > 128) return res.status(400).json({ error: 'Password is too long.' });
    if (!ALLOWED_DEPARTMENTS.includes(department)) return res.status(400).json({ error: 'Invalid department.' });

    const existingEmail = await db.get(`SELECT id FROM users WHERE email = ?`, [email]);
    if (existingEmail) return res.status(409).json({ error: 'Email already in use.' });

    const existingName = await db.get(`SELECT id FROM users WHERE LOWER(name) = LOWER(?)`, [name]);
    if (existingName) return res.status(409).json({ error: 'Username (Full Name) already in use.' });

    const id   = `USR-${Date.now().toString().slice(-6)}`;
    const hash = await bcrypt.hash(password, 12); // cost factor 12 (up from 10)
    const at   = new Date().toISOString();

    await db.run(
      `INSERT INTO users (id, name, email, password, department, createdAt) VALUES (?, ?, ?, ?, ?, ?)`,
      [id, name, email, hash, department, at]
    );
    res.status(201).json({ id, name, email, department, role: 'user', active: 1, createdAt: at });
  } catch (err) { serverError(res, err); }
});

app.put('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const id         = sanitize(req.params.id, 50);
    const name       = req.body?.name       !== undefined ? sanitize(req.body.name, 100)       : undefined;
    const department = req.body?.department !== undefined ? sanitize(req.body.department, 50)   : undefined;
    const active     = req.body?.active     !== undefined ? req.body.active                     : undefined;
    const password   = req.body?.password;

    if (department !== undefined && !ALLOWED_DEPARTMENTS.includes(department)) {
      return res.status(400).json({ error: 'Invalid department.' });
    }
    if (password !== undefined) {
      if (typeof password !== 'string' || password.length < 6)  return res.status(400).json({ error: 'Password must be at least 6 characters.' });
      if (password.length > 128) return res.status(400).json({ error: 'Password is too long.' });
    }

    const updates = []; const params = [];
    if (name       !== undefined) { updates.push('name = ?');       params.push(name); }
    if (department !== undefined) { updates.push('department = ?'); params.push(department); }
    if (active     !== undefined) { updates.push('active = ?');     params.push(active ? 1 : 0); }
    if (password)                 { updates.push('password = ?');   params.push(await bcrypt.hash(password, 12)); }

    if (updates.length > 0) {
      params.push(id);
      await db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
    }
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const id = sanitize(req.params.id, 50);
    await db.run(`DELETE FROM users WHERE id = ?`, [id]);
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ---- Tickets (AUTHENTICATED ONLY) ----
const fetchTicketComments = async (ticketId) =>
  (await db.all(`SELECT * FROM comments WHERE ticketId = ? ORDER BY id ASC`, [ticketId])) || [];

app.get('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const tickets = await db.all(`SELECT * FROM tickets`);
    for (const t of tickets) {
      const raw = await fetchTicketComments(t.id);
      t.comments = raw.map(c => ({ by: c.by, text: c.text, at: c.at, isWorkNote: !!c.isWorkNote }));
    }
    res.json(tickets);
  } catch (err) { serverError(res, err); }
});

app.post('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const title       = sanitize(req.body?.title, 200);
    const description = sanitize(req.body?.description, 2000);
    const category    = sanitize(req.body?.category, 50);
    const priority    = sanitize(req.body?.priority, 20);
    const { user }    = req.body; // In future, use req.user.id instead of trust-body

    if (!title)       return res.status(400).json({ error: 'Title is required.' });
    if (!description) return res.status(400).json({ error: 'Description is required.' });
    if (!ALLOWED_CATEGORIES.includes(category)) return res.status(400).json({ error: 'Invalid category.' });
    if (!ALLOWED_PRIORITIES.includes(priority)) return res.status(400).json({ error: 'Invalid priority.' });
    if (!user?.id || !user?.name)               return res.status(400).json({ error: 'Valid user session required.' });

    const countRow = await db.get(`SELECT COUNT(*) as c FROM tickets`);
    const id = `TKT-${String(countRow.c + 1).padStart(3, '0')}`;
    const at = new Date().toISOString();

    const userId   = sanitize(user.id,         50);
    const userName = sanitize(user.name,       100);
    const userEmail= sanitize(user.email,      200);
    const userDept = sanitize(user.department, 50);

    await db.run(
      `INSERT INTO tickets (id, title, description, category, priority, status, userId, userName, userEmail, department, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)`,
      [id, title, description, category, priority, userId, userName, userEmail, userDept, at, at]
    );
    res.status(201).json({ id, title, description, category, priority, status: 'open', userId, userName, userEmail, department: userDept, createdAt: at, updatedAt: at, comments: [] });
  } catch (err) { serverError(res, err); }
});

app.put('/api/tickets/:id/status', authenticateToken, async (req, res) => {
  try {
    const id     = sanitize(req.params.id, 50);
    const status = sanitize(req.body?.status, 20);

    if (!ALLOWED_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'Invalid status value.' });
    }
    const at = new Date().toISOString();
    await db.run(`UPDATE tickets SET status = ?, updatedAt = ? WHERE id = ?`, [status, at, id]);
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.post('/api/tickets/:id/comments', authenticateToken, async (req, res) => {
  try {
    const ticketId  = sanitize(req.params.id, 50);
    const by        = sanitize(req.body?.by, 100);
    const text      = sanitize(req.body?.text, 2000);
    const isWorkNote= !!req.body?.isWorkNote;

    if (!by)   return res.status(400).json({ error: 'Author name is required.' });
    if (!text) return res.status(400).json({ error: 'Comment text is required.' });

    const at = new Date().toISOString();
    await db.run(
      `INSERT INTO comments (ticketId, by, text, isWorkNote, at) VALUES (?, ?, ?, ?, ?)`,
      [ticketId, by, text, isWorkNote ? 1 : 0, at]
    );
    await db.run(`UPDATE tickets SET updatedAt = ? WHERE id = ?`, [at, ticketId]);
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

app.delete('/api/tickets/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const id = sanitize(req.params.id, 50);
    await db.run(`DELETE FROM tickets WHERE id = ?`, [id]);
    res.json({ success: true });
  } catch (err) { serverError(res, err); }
});

// ================================================================
// FALLBACK & ERROR HANDLERS
// ================================================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Global error handler — never expose internals in production
app.use((err, req, res, _next) => {
  console.error('[UNHANDLED]', err);
  res.status(err.status || 500).json({
    error: isProd ? 'Something went wrong.' : err.message,
  });
});

// ================================================================
// START
// ================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[TicketFlow] Server running on port ${PORT} (${isProd ? 'production' : 'development'})`);
});
