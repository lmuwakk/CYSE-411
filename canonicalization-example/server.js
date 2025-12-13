const express = require("express");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

const app = express();
app.disable("x-powered-by");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

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
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=()"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const fileLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send("User-agent: *\nDisallow:\n");
});

app.get("/sitemap.xml", (req, res) => {
  res
    .type("application/xml")
    .send('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>');
});

app.use(express.static(path.join(__dirname, "public")));

const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

function sanitizeRelPath(input) {
  let s = String(input ?? "");
  try {
    s = decodeURIComponent(s);
  } catch (_) {}
  s = s.replace(/\\/g, "/").trim();
  if (!s) return null;
  if (s.includes("\0")) return null;
  if (s.startsWith("/")) return null;
  if (!/^[a-zA-Z0-9._\-\/]+$/.test(s)) return null;
  const norm = path.posix.normalize(s);
  if (norm === "." || norm.startsWith("../") || norm.includes("/../")) return null;
  return norm;
}

function resolveSafe(baseDir, userInput) {
  const rel = sanitizeRelPath(userInput);
  if (!rel) return null;
  const full = path.resolve(baseDir, rel);
  const base = baseDir.endsWith(path.sep) ? baseDir : baseDir + path.sep;
  if (!full.startsWith(base)) return null;
  return full;
}

const filenameValidator = body("filename")
  .exists()
  .bail()
  .isString()
  .bail()
  .custom((v) => sanitizeRelPath(v) !== null);

app.post("/read", fileLimiter, filenameValidator, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Invalid filename" });

  const resolved = resolveSafe(BASE_DIR, req.body.filename);
  if (!resolved) return res.status(403).json({ error: "Path traversal detected" });
  if (!fs.existsSync(resolved)) return res.status(404).json({ error: "File not found" });

  const content = fs.readFileSync(resolved, "utf8");
  res.json({ path: resolved, content });
});

app.post("/read-no-validate", fileLimiter, filenameValidator, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: "Invalid filename" });

  const resolved = resolveSafe(BASE_DIR, req.body.filename);
  if (!resolved) return res.status(403).json({ error: "Path traversal detected" });
  if (!fs.existsSync(resolved)) return res.status(404).json({ error: "File not found" });

  const content = fs.readFileSync(resolved, "utf8");
  res.json({ path: resolved, content });
});

app.post("/setup-sample", fileLimiter, (req, res) => {
  const samples = {
    "hello.txt": "Hello from safe file!\n",
    "notes/readme.md": "# Readme\nSample readme file",
  };

  Object.keys(samples).forEach((k) => {
    const rel = sanitizeRelPath(k);
    if (!rel) return;
    const p = path.resolve(BASE_DIR, rel);
    const base = BASE_DIR.endsWith(path.sep) ? BASE_DIR : BASE_DIR + path.sep;
    if (!p.startsWith(base)) return;
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], "utf8");
  });

  res.json({ ok: true, base: BASE_DIR });
});

if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, "0.0.0.0", () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
