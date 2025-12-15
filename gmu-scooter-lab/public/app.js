// app.js – shared by index.html and dashboard.html

const API = "";

// Helper to POST JSON
async function postJSON(url, data) {
  const token = localStorage.getItem("authToken");
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Auth-Token": token || ""
    },
    body: JSON.stringify(data)
  });
  return res.json();
}

// Helper to GET JSON
async function getJSON(url) {
  const token = localStorage.getItem("authToken");
  const res = await fetch(url, {
    headers: {
      "X-Auth-Token": token || ""
    }
  });
  return res.json();
}

// Detect which page we're on
if (document.getElementById("login-form")) {
  // --- index.html logic (login/register) ---

  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const username = form.username.value;
    const password = form.password.value;

    const data = await postJSON("/api/login", { username, password });

    if (!data.success) {
      document.getElementById("login-error").textContent = data.error || "Login failed";
      return;
    }

    localStorage.setItem("authToken", data.token);
    window.location.href = "/dashboard.html";
  });

  document.getElementById("register-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const username = form.username.value;
    const password = form.password.value;
    const email = form.email.value;

    const data = await postJSON("/api/register", { username, password, email });
    document.getElementById("register-msg").textContent = data.success
      ? "Registered. You can now login."
      : data.error;
  });
}

// --- dashboard.html logic ---------------------------------------------------

if (document.getElementById("logout-btn")) {
  // Load current user info
  (async function initDashboard() {
    const me = await getJSON("/api/me");
    if (me.error) {
      window.location.href = "/";
      return;
    }
    const userInfo = document.getElementById("user-info");

    userInfo.innerHTML = `
      <strong>Logged in as:</strong> ${me.username} (${me.email})<br />
      <strong>Balance:</strong> $${me.balance.toFixed(2)}
    `;

    await loadStations();
    await loadFeedback();
  })();

  // Logout
  document.getElementById("logout-btn").addEventListener("click", async () => {
    await postJSON("/api/logout", {});
    localStorage.removeItem("authToken");
    window.location.href = "/";
  });

  // Station search
  document.getElementById("search-btn").addEventListener("click", async () => {
    await loadStations();
  });

  document.getElementById("regex-btn").addEventListener("click", async () => {
    const pattern = document.getElementById("regex-pattern").value;
    const stations = await getJSON("/api/stations/regex-search?pattern=" + encodeURIComponent(pattern));
    renderStations(stations, "stations-list");
  });

  async function loadStations() {
    const q = document.getElementById("station-search").value;
    const stations = await getJSON("/api/stations?q=" + encodeURIComponent(q));
    renderStations(stations, "stations-list");
  }

  function renderStations(stations, listId) {
    const ul = document.getElementById(listId);
    ul.innerHTML = "";
    stations.forEach((s) => {
      const li = document.createElement("li");
      li.textContent = `${s.name} – ${s.location} [${s.status}]`;
      ul.appendChild(li);
    });
  }

  // Feedback wall
  document.getElementById("feedback-btn").addEventListener("click", async () => {
    const text = document.getElementById("feedback-text").value;
    await postJSON("/api/feedback", { comment: text });
    document.getElementById("feedback-text").value = "";
    await loadFeedback();
  });

  async function loadFeedback() {
    const list = await getJSON("/api/feedback");
    const ul = document.getElementById("feedback-list");
    ul.innerHTML = "";
    list.forEach((f) => {
      const li = document.createElement("li");
      li.innerHTML = `<strong>${f.user}</strong>: ${f.comment}`;
      ul.appendChild(li);
    });
  }

  document.getElementById("email-btn").addEventListener("click", async () => {
    const email = document.getElementById("email-input").value;
    const res = await postJSON("/api/account/email", { email });
    alert(res.success ? "Email updated" : res.error);
  });

  // Admin users 
  document
    .getElementById("admin-users-btn")
    .addEventListener("click", async () => {
      const users = await getJSON("/api/admin/users");
      const ul = document.getElementById("admin-users-list");
      ul.innerHTML = "";
      if (users.error) {
        ul.textContent = users.error;
        return;
      }
      users.forEach((u) => {
        const li = document.createElement("li");
        li.textContent = `${u.id}: ${u.username} (${u.role}) – ${u.email} – $${u.balance}`;
        ul.appendChild(li);
      });
    });
}
