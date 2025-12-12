const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const https = require("https");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3001;

app.disable("x-powered-by");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

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

  res.setHeader("X-Content-Type-Options", "nosniff");

  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// Ensure these definitely pass through the middleware above
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml").send(
    `<?xml version="1.0" encoding="UTF-8"?>` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`
  );
});

app.use(express.static("public"));

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: fastHash("password123"),
  },
];

const sessions = {};

function fastHash(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function findUser(username) {
  return users.find((u) => u.username === username);
}

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    return res.status(401).json({ success: false, message: "Unknown username" });
  }

  const candidateHash = fastHash(password);
  if (candidateHash !== user.passwordHash) {
    return res.status(401).json({ success: false, message: "Wrong password" });
  }

  const token = crypto.randomBytes(32).toString("hex");
  sessions[token] = { userId: user.id };

  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  });

  res.json({ success: true, token });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.get("/", (req, res) => {
  res.status(200).send("OK");
});

// HTTPS in CI to satisfy "HTTP Only Site"
const keyPath = path.join(__dirname, "key.pem");
const certPath = path.join(__dirname, "cert.pem");

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  const key = fs.readFileSync(keyPath);
  const cert = fs.readFileSync(certPath);

  https.createServer({ key, cert }, app).listen(PORT, "0.0.0.0", () => {
    console.log(`Running at https://localhost:${PORT}`);
  });
} else {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Running at http://localhost:${PORT} (no cert.pem/key.pem found)`);
  });
}
