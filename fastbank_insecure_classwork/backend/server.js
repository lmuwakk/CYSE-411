const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const csrf = require("csurf");
const bcrypt = require("bcrypt");

const app = express();

// ----------------------
// Global security config
// ----------------------

// Hide Express fingerprint header
app.disable("x-powered-by");

// Helmet with CSP that includes directives that don’t fall back
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; navigate-to 'self'"
  );
  next();
});

// Permissions Policy header (restrict all by default)
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), fullscreen=()"
  );
  next();
});

// Disable caching (banking app should not be cached by proxies)
app.use((req, res, next) => {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// --- BASIC CORS (clean, not vulnerable) ---
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

// CSRF protection (cookie-based token)
const csrfProtection = csrf({ cookie: true });

// Simple rate limiter for sensitive endpoints
const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

// ----------------------
// IN-MEMORY SQLITE DB
// ----------------------
const db = new sqlite3.Database(":memory:");
const BCRYPT_ROUNDS = 12;

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  // Use bcrypt for password hashing (slow, salted)
  const passwordHash = bcrypt.hashSync("password123", BCRYPT_ROUNDS);

  db.run(
    `INSERT INTO users (username, password_hash, email)
     VALUES (?, ?, ?)`,
    ["alice", passwordHash, "alice@example.com"]
  );

  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (1, 25.50, 'Coffee shop')`
  );
  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (1, 100, 'Groceries')`
  );
});

// ----------------------
// SESSION STORE
// ----------------------
const sessions = {};

function generateSessionId() {
  // Random, unpredictable session ID instead of username + timestamp
  return crypto.randomBytes(32).toString("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  req.user = { id: sessions[sid].userId };
  next();
}

// Optional route so a frontend could fetch a CSRF token if needed
app.get("/csrf-token", auth, csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ------------------------------------------------------------
// /login  (bcrypt + parameterized query + rate limit + CSRF)
// ------------------------------------------------------------
app.post("/login", sensitiveLimiter, csrfProtection, (req, res) => {
  const { username, password } = req.body;

  const sql = `SELECT id, username, password_hash FROM users WHERE username = ?`;

  db.get(sql, [username], (err, user) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!user) return res.status(404).json({ error: "Unknown username" });

    bcrypt.compare(password, user.password_hash, (err2, match) => {
      if (err2) return res.status(500).json({ error: "Hash error" });
      if (!match) {
        return res.status(401).json({ error: "Wrong password" });
      }

      const sid = generateSessionId();
      sessions[sid] = { userId: user.id };

      // Secure cookie flags would be best in production,
      // but we keep defaults here to avoid breaking the lab setup.
      res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });

      res.json({ success: true });
    });
  });
});

// ------------------------------------------------------------
// /me — parameterized query, auth-protected
// ------------------------------------------------------------
app.get("/me", auth, (req, res) => {
  const sql = `SELECT username, email FROM users WHERE id = ?`;
  db.get(sql, [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(row);
  });
});

// ------------------------------------------------------------
// /transactions — fixed SQL injection + rate limiting
// ------------------------------------------------------------
app.get("/transactions", auth, sensitiveLimiter, (req, res) => {
  const q = req.query.q || "";
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
  `;
  const params = [req.user.id, `%${q}%`];
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

// ------------------------------------------------------------
// /feedback — fixed SQL injection, basic stored XSS mitigation,
// CSRF protection, and rate limiting
// ------------------------------------------------------------
app.post("/feedback", auth, sensitiveLimiter, csrfProtection, (req, res) => {
  const comment = req.body.comment || "";
  const userId = req.user.id;

  // Very simple HTML escaping to reduce stored XSS risk
  const safeComment = comment.replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const getUserSql = `SELECT username FROM users WHERE id = ?`;
  db.get(getUserSql, [userId], (err, row) => {
    if (err || !row) return res.status(500).json({ error: "DB error" });
    const username = row.username;

    const insert = `
      INSERT INTO feedback (user, comment)
      VALUES (?, ?)
    `;
    db.run(insert, [username, safeComment], (err2) => {
      if (err2) return res.status(500).json({ error: "DB error" });
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, sensitiveLimiter, (req, res) => {
  db.all(
    "SELECT user, comment FROM feedback ORDER BY id DESC",
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows);
    }
  );
});

// ------------------------------------------------------------
// /change-email — SQLi fixed, CSRF + rate limit + auth
// ------------------------------------------------------------
app.post(
  "/change-email",
  auth,
  csrfProtection,
  sensitiveLimiter,
  (req, res) => {
    const newEmail = req.body.email;

    if (!newEmail || !newEmail.includes("@")) {
      return res.status(400).json({ error: "Invalid email" });
    }

    const sql = `UPDATE users SET email = ? WHERE id = ?`;
    db.run(sql, [newEmail, req.user.id], (err) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ success: true, email: newEmail });
    });
  }
);

// ------------------------------------------------------------
app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
