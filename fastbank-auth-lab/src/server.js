const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
// bcrypt is installed but NOT used in the vulnerable baseline:
const bcrypt = require("bcrypt");
const app = express();
const PORT = 3001;
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));
/**
* VULNERABLE FAKE USER DB
* For simplicity, we start with a single user whose password is "password123".
* In the vulnerable version, we hash with a fast hash (SHA-256-like).
*/
const users = [
{
id: 1,
username: "student",
// VULNERABLE: fast hash without salt
passwordHash: bcrypt.hashSync("password123", 12) // students must replace this
scheme with bcrypt
}
];
// In-memory session store
const sessions = {}; // token -> { userId }
/**
* VULNERABLE FAST HASH FUNCTION
* Students MUST STOP using this and replace logic with bcrypt.
*/
// Helper: find user by username
function findUser(username) {
return users.find((u) => u.username === username);
}
// Home API just to show who is logged in
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
/**
* VULNERABLE LOGIN ENDPOINT
* - Uses fastHash instead of bcrypt
* - Error messages leak whether username exists
* - Session token is simple and predictable
* - Cookie lacks security flags
*/
app.post("/api/login", (req, res) => {
const { username, password } = req.body;
const user = findUser(username);
const INVALID_MESSAGE = "Invalid username or password";
if (!user) {
return res
.status(401)
.json({ success: false, message: INVALID_MESSAGE });
}
const passwordMatch = bcrypt.compareSync(password, user.passwordHash);
if (!passwordMatch) {
return res
.status(401)
.json({ success: false, message: INVALID_MESSAGE });
}
for (const t in sessions) {
if (sessions[t].userId === user.id) {
delete sessions[t];
}
}
// VULNERABLE: predictable token
const token = crypto.randomBytes(32).toString("hex");
// VULNERABLE: session stored without expiration
const expiresAt = Date.now() + 30 * 60 * 1000;
sessions[token] = {
userId: user.id,
expires: expiresAt
};
// VULNERABLE: cookie without httpOnly, secure, sameSite
res.cookie("session", token, {
httpOnly: true,
secure: false,
sameSite: "lax",
maxAge: 30 * 60 * 1000
// students must add: httpOnly: true, secure: true, sameSite: "lax"
});
// Client-side JS (login.html) will store this token in localStorage (vulnerable)
res.json({ success: true, token });
});
app.post("/api/logout", (req, res) => {
const token = req.cookies.session;
if (token && sessions[token]) {
if (Date.now() > sessions[token].expires) {
delete sessions[token];
} else {
delete sessions[token];
}
}
res.clearCookie("session");
res.json({ success: true });
});
app.listen(PORT, () => {
console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
