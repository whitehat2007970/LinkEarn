
const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Render runs behind a proxy.
app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Require the Render PostgreSQL connection URL.
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing. Add it in Render Environment Variables.");
  process.exit(1);
}

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error);
});

// Session configuration
app.use(
  session({
    name: "linkearn.sid",
    secret: process.env.SESSION_SECRET || "linkearn-local-testing-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

// Serve frontend files
app.use(express.static(__dirname));

// Create database tables
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS linkearn_users (
      id SERIAL PRIMARY KEY,
      phone VARCHAR(14) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      username VARCHAR(30) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS linkearn_wallets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL
        REFERENCES linkearn_users(id) ON DELETE CASCADE,
      available_balance_kobo BIGINT NOT NULL DEFAULT 0,
      total_earned_kobo BIGINT NOT NULL DEFAULT 0,
      pending_reward_kobo BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS linkearn_whatsapp (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL
        REFERENCES linkearn_users(id) ON DELETE CASCADE,
      status VARCHAR(30) NOT NULL DEFAULT 'not_connected',
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("LinkEarn database tables are ready.");
}

// Authentication middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }

  next();
}

// Normalize Nigerian phone number
function normalizePhone(value) {
  let phone = String(value || "").replace(/[\s()-]/g, "");

  if (phone.startsWith("+234")) {
    phone = phone.slice(4);
  } else if (phone.startsWith("234")) {
    phone = phone.slice(3);
  } else if (phone.startsWith("0")) {
    phone = phone.slice(1);
  }

  if (!/^[0-9]{10}$/.test(phone)) {
    return null;
  }

  return "+234" + phone;
}

// Frontend pages
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "signup.html"));
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "signup.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/home", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/login");
  }

  res.sendFile(path.join(__dirname, "home.html"));
});

// SIGN UP
app.post("/api/signup", async (req, res) => {
  const client = await pool.connect();

  try {
    const { phone, email, username, password } = req.body;

    const normalizedPhone = normalizePhone(phone);
    const normalizedEmail = String(email || "").trim().toLowerCase();
    const normalizedUsername = String(username || "").trim().toLowerCase();

    if (!normalizedPhone) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid Nigerian phone number."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    if (!/^[a-z0-9_]{3,20}$/.test(normalizedUsername)) {
      return res.status(400).json({
        success: false,
        message: "Username must be 3–20 characters using letters, numbers or underscores."
      });
    }

    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters."
      });
    }

    // Password intentionally remains plain text for isolated testing.
    await client.query("BEGIN");

    const result = await client.query(
      `INSERT INTO linkearn_users
       (phone, email, username, password)
       VALUES ($1, $2, $3, $4)
       RETURNING id, phone, email, username`,
      [normalizedPhone, normalizedEmail, normalizedUsername, password]
    );

    const user = result.rows[0];

    await client.query(
      "INSERT INTO linkearn_wallets (user_id) VALUES ($1)",
      [user.id]
    );

    await client.query(
      "INSERT INTO linkearn_whatsapp (user_id) VALUES ($1)",
      [user.id]
    );

    await client.query("COMMIT");

    req.session.userId = user.id;

    req.session.save((error) => {
      if (error) {
        console.error("Signup session error:", error);

        return res.status(500).json({
          success: false,
          message: "Account created, but login session could not be saved."
        });
      }

      return res.status(201).json({
        success: true,
        message: "Account created successfully.",
        redirect: "/home"
      });
    });

  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});

    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "That phone number, email or username is already registered."
      });
    }

    console.error("Signup error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create your account. Please try again."
    });

  } finally {
    client.release();
  }
});

// LOG IN
app.post("/api/login", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || "").trim().toLowerCase();
    const password = req.body.password;

    if (!identifier || typeof password !== "string") {
      return res.status(400).json({
        success: false,
        message: "Enter your login details."
      });
    }

    const result = await pool.query(
      `SELECT id, username, password
       FROM linkearn_users
       WHERE LOWER(email) = $1
          OR LOWER(username) = $1`,
      [identifier]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const user = result.rows[0];

    // Plain-text comparison retained for testing only.
    if (user.password !== password) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    req.session.userId = user.id;

    req.session.save((error) => {
      if (error) {
        console.error("Login session error:", error);

        return res.status(500).json({
          success: false,
          message: "Unable to save login session."
        });
      }

      return res.json({
        success: true,
        message: "Login successful.",
        redirect: "/home"
      });
    });

  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to log in. Please try again."
    });
  }
});

// DASHBOARD DATA
app.get("/api/dashboard", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.username,
         w.available_balance_kobo,
         w.total_earned_kobo,
         w.pending_reward_kobo,
         wa.status AS whatsapp_status
       FROM linkearn_users u
       LEFT JOIN linkearn_wallets w ON w.user_id = u.id
       LEFT JOIN linkearn_whatsapp wa ON wa.user_id = u.id
       WHERE u.id = $1`,
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      req.session.destroy(() => {});

      return res.status(401).json({
        success: false,
        message: "Account not found. Please log in again."
      });
    }

    const user = result.rows[0];

    res.json({
      user: {
        id: user.id,
        username: user.username
      },
      wallet: {
        availableBalanceKobo: Number(user.available_balance_kobo || 0),
        totalEarnedKobo: Number(user.total_earned_kobo || 0),
        pendingRewardKobo: Number(user.pending_reward_kobo || 0)
      },
      whatsapp: {
        status: user.whatsapp_status || "not_connected"
      },
      weeklyReward: {
        amountKobo: 0
      }
    });

  } catch (error) {
    console.error("Dashboard error:", error);

    res.status(500).json({
      success: false,
      message: "Unable to load dashboard data."
    });
  }
});

// LOG OUT
app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        success: false,
        message: "Unable to log out."
      });
    }

    res.clearCookie("linkearn.sid");

    res.json({
      success: true,
      redirect: "/login"
    });
  });
});

// Start server only after database is ready
async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`LinkEarn is running on port ${PORT}`);
    });

  } catch (error) {
    console.error("Could not start LinkEarn:", error);
    process.exit(1);
  }
}

startServer();
