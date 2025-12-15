// server.js
// GMU Smart Scooter Charging System (INTENTIONALLY VULNERABLE LAB APP)
// DO NOT DEPLOY TO PRODUCTION AS-IS.
//


const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = 3001;

// --- DB SETUP --------------------------------------------------------------

const db = new sqlite3.Database("./scooter.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user',
      email TEXT,
      balance REAL DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS stations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      location TEXT,
      status TEXT DEFAULT 'available'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    )
  `);

  // Seed demo users (only if table empty)
  db.get("SELECT COUNT(*) AS c FROM users", (err, row) => {
    if (row && row.c === 0) {
      db.run(
        "INSERT INTO users (username, password, role, email, balance) VALUES ('alice', 'password123', 'user', 'alice@example.com', 10)"
      );
      db.run(
        "INSERT INTO users (username, password, role, email, balance) VALUES ('bob', 'password123', 'admin', 'bob@example.com', 50)"
      );
    }
  });

  // Seed some stations
  db.get("SELECT COUNT(*) AS c FROM stations", (err, row) => {
    if (row && row.c === 0) {
      db.run(
        "INSERT INTO stations (name, location, status) VALUES ('Downtown Hub', 'Main St', 'available')"
      );
      db.run(
        "INSERT INTO stations (name, location, status) VALUES ('Campus North', 'GMU North Gate', 'charging')"
      );
      db.run(
        "INSERT INTO stations (name, location, status) VALUES ('Mall Center', 'City Mall', 'available')"
      );
    }
  });
});

// --- SIMPLE IN-MEMORY SESSION STORE (INTENTIONALLY WEAK) -------------------

const sessions = {}; // sid -> { userId, username, role }

// --- MIDDLEWARE ------------------------------------------------------------

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// Authentication helper (also intentionally imperfect)
function getSession(req) {
  const sid = req.cookies.auth || req.headers["x-auth-token"];
  if (!sid) return null;
  return sessions[sid] || null;
}

// --- ROUTES ----------------------------------------------------------------

app.post("/api/register", (req, res) => {
  const { username, password, email } = req.body;

  const sql = `
    INSERT INTO users (username, password, email, balance)
    VALUES ('${username}', '${password}', '${email}', 0)
  `;
  db.run(sql, function (err) {
    if (err) {
      return res.status(400).json({ error: "Registration failed: " + err.message });
    }
    res.json({ success: true });
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  const sql = `SELECT id, username, password, role, email FROM users WHERE username = '${username}'`;

  db.get(sql, (err, user) => {
    if (err) {
      return res.status(500).json({ error: "DB error" });
    }

    if (!user) {
      return res.status(404).json({ error: "Unknown user" });
    }

    if (user.password !== password) {
      return res.status(401).json({ error: "Wrong password" });
    }

    const sid = `${user.username}-${Date.now()}`;
    sessions[sid] = {
      userId: user.id,
      username: user.username,
      role: user.role,
    };

    res.cookie("auth", sid); 
    res.json({
      success: true,
      token: sid, 
      username: user.username,
      role: user.role,
      email: user.email,
    });
  });
});

app.get("/api/me", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Not logged in" });
  }

  db.get(
    "SELECT id, username, role, email, balance FROM users WHERE id = ?",
    [session.userId],
    (err, row) => {
      if (err || !row) return res.status(404).json({ error: "User not found" });
      res.json(row);
    }
  );
});

app.get("/api/stations", (req, res) => {
  const q = req.query.q || "";

  const sql = `
    SELECT id, name, location, status
    FROM stations
    WHERE name LIKE '%${q}%' OR location LIKE '%${q}%'
  `;

  db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

app.get("/api/stations/regex-search", (req, res) => {
  const pattern = req.query.pattern || ".*";

 
  try {
    const regex = new RegExp(pattern);

    db.all("SELECT id, name, location, status FROM stations", (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });

      const matched = rows.filter((s) => regex.test(s.name));
      res.json(matched);
    });
  } catch (e) {
    res.status(400).json({ error: "Invalid regex: " + e.message });
  }
});


app.post("/api/feedback", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Login required" });
  }

  const { comment } = req.body;

  const sqlUser = `SELECT username FROM users WHERE id = ${session.userId}`;
  db.get(sqlUser, (err, userRow) => {
    const username = userRow ? userRow.username : "anonymous";

    const insert = `INSERT INTO feedback (user, comment) VALUES (?, ?)`;
    db.run(insert, [username, comment], (err2) => {
      if (err2) return res.status(500).json({ error: "Insert failed" });
      res.json({ success: true });
    });
  });
});

app.get("/api/feedback", (req, res) => {
  db.all("SELECT id, user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

app.post("/api/account/email", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Login required" });
  }

  const newEmail = req.body.email;

  
  const sql = `UPDATE users SET email = '${newEmail}' WHERE id = ${session.userId}`;
  db.run(sql, (err) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ success: true });
  });
});

app.get("/api/admin/users", (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: "Login required" });
  }

  db.all("SELECT id, username, role, email, balance FROM users", (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

app.post("/api/logout", (req, res) => {
  const sid = req.cookies.auth || req.headers["x-auth-token"];
  if (sid && sessions[sid]) {
    delete sessions[sid];
  }
  res.clearCookie("auth");
  res.json({ success: true });
});

// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`GMU scooter lab app listening on http://localhost:${PORT}`);
});
