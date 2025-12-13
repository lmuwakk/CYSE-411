const express = require("express");
const app = express();

app.disable("x-powered-by"); // fixes ZAP "X-Powered-By: Express" leak :contentReference[oaicite:1]{index=1}
app.use(express.json());

// Basic security headers (also helps with ZAP "Spectre/site isolation" style lows if they show up)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  next();
});

// Fake "database"
const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

// Very simple "authentication" via headers:
//   X-User-Id: <user id>
function fakeAuth(req, res, next) {
  const idHeader = req.header("X-User-Id");
  const id = idHeader ? Number.parseInt(idHeader, 10) : NaN;

  if (!Number.isInteger(id)) {
    return res.status(401).json({ error: "Unauthenticated: set X-User-Id" });
  }

  const user = users.find((u) => u.id === id);
  if (!user) {
    return res.status(401).json({ error: "Unauthenticated: set X-User-Id" });
  }

  req.user = user;
  next();
}

app.use(fakeAuth);

// ✅ FIXED endpoint: enforce authorization (prevents IDOR)
app.get("/orders/:id", (req, res) => {
  const orderId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(orderId)) {
    return res.status(400).json({ error: "Invalid order id" });
  }

  const order = orders.find((o) => o.id === orderId);
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  // Authorization rules:
  // - customers can ONLY access their own orders
  // - support can access orders in their department/region
  const user = req.user;

  let allowed = false;
  if (user.role === "customer") {
    allowed = order.userId === user.id;
  } else if (user.role === "support") {
    allowed = order.region === user.department;
  }

  // Return 404 instead of 403 to reduce order-id probing/enumeration
  if (!allowed) {
    return res.status(404).json({ error: "Order not found" });
  }

  return res.json(order);
});

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Access Control Tutorial API", currentUser: req.user });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
