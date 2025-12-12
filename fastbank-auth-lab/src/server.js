const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const csrf = require("csurf");

const app = express();
const PORT = 3001;

app.disable("x-powered-by");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join("; ")
  );

  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
  );

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

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

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const csrfProtection = csrf({
  cookie: {
    httpOnly: false,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  },
});

app.get("/api/csrf", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];
  if (Date.now() > session.expires) {
    delete sessions[token];
    res.clearCookie("session");
    return res.status(401).json({ authenticated: false });
  }

  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", authLimiter, csrfProtection, (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  const INVALID_MESSAGE = "Invalid username or password";

  if (!user) {
    return res.status(401).json({ success: false, message: INVALID_MESSAGE });
  }

  const passwordMatch = bcrypt.compareSync(password, user.passwordHash);
  if (!passwordMatch) {
    return res.status(401).json({ success: false, message: INVALID_MESSAGE });
  }

  for (const t in sessions) {
    if (sessions[t].userId === user.id) delete sessions[t];
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 30 * 60 * 1000;

  sessions[token] = { userId: user.id, expires: expiresAt };

  res.cookie("session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 30 * 60 * 1000,
  });

  res.json({ success: true });
});

app.post("/api/logout", csrfProtection, (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`App running at http://localhost:${PORT}`);
});
