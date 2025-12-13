const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const csrf = require("csurf");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

app.disable("x-powered-by");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
  );
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.get("/robots.txt", (req, res) => res.type("text/plain").send("User-agent: *\nDisallow:"));
app.get("/sitemap.xml", (req, res) =>
  res
    .type("application/xml")
    .send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`)
);

app.use(express.static("public"));

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12),
  },
];

const sessions = {};

function findUser(username) {
  return users.find((u) => u.username === username);
}

function issueSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions[token] = { userId };
  return token;
}

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  },
});

app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) return res.status(401).json({ authenticated: false });
  const user = users.find((u) => u.id === sessions[token].userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", csrfProtection, (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  const INVALID = "Invalid username or password";

  if (!user) return res.status(401).json({ success: false, message: INVALID });

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(401).json({ success: false, message: INVALID });

  const token = issueSession(user.id);

  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });

  res.json({ success: true });
});

app.post("/api/logout", csrfProtection, (req, res) => {
  const token = req.cookies.session;
  if (token) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

app.get("/", (req, res) => res.status(200).send("OK"));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
