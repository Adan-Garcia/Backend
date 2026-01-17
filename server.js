const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");

// --- Configuration ---
const PORT = process.env.PORT || 3001;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "planner.db");

// --- App Setup ---
const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Allow all origins for local dev (restrict in prod)
    methods: ["GET", "POST"],
  },
});

// --- Database Setup (better-sqlite3) ---
// verbose: console.log will log every query to the console (good for debugging)
const db = new Database(DB_PATH, { verbose: console.log });
console.log("Connected to SQLite database.");

// Initialize Tables (Synchronous)
const initDb = () => {
  // Rooms: Stores the public salt and the private Auth Hash
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      auth_hash TEXT NOT NULL,
      meta TEXT, -- JSON string for classColors, settings
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,
  ).run();

  // Events: Stores granular encrypted event data
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      iv TEXT NOT NULL,
      data TEXT NOT NULL, -- The encrypted blob
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
    )
  `,
  ).run();
};

initDb();

// --- REST API: Authentication & Initial Load ---

/**
 * 1. INIT: Client checks if room exists.
 */
app.post("/api/auth/init", (req, res) => {
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: "Missing roomId" });

  try {
    const room = db.prepare("SELECT salt FROM rooms WHERE id = ?").get(roomId);

    if (room) {
      return res.json({ salt: room.salt, isNew: false });
    } else {
      const newSalt = crypto.randomBytes(16).toString("hex");
      return res.json({ salt: newSalt, isNew: true });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * 2. LOGIN / REGISTER: Client sends Auth Hash.
 */
app.post("/api/auth/login", (req, res) => {
  const { roomId, authHash, salt } = req.body;
  if (!roomId || !authHash)
    return res.status(400).json({ error: "Missing credentials" });

  try {
    const room = db
      .prepare("SELECT auth_hash FROM rooms WHERE id = ?")
      .get(roomId);

    if (room) {
      // VERIFY: Compare client hash with stored hash
      if (room.auth_hash === authHash) {
        const token = Buffer.from(`${roomId}:${authHash}`).toString("base64");
        return res.json({ token, authorized: true });
      } else {
        return res.status(401).json({ error: "Incorrect Password" });
      }
    } else {
      // CREATE: Register new room
      if (!salt)
        return res.status(400).json({ error: "Missing salt for new room" });

      db.prepare(
        "INSERT INTO rooms (id, salt, auth_hash, meta) VALUES (?, ?, ?, ?)",
      ).run(roomId, salt, authHash, "{}");

      const token = Buffer.from(`${roomId}:${authHash}`).toString("base64");
      return res.json({ token, authorized: true, created: true });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Database error" });
  }
});

/**
 * 3. FETCH DATA: Get all events for a room.
 */
app.get("/api/rooms/:roomId/events", (req, res) => {
  const { roomId } = req.params;
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  try {
    const events = db
      .prepare("SELECT id, iv, data FROM events WHERE room_id = ?")
      .all(roomId);
    const room = db.prepare("SELECT meta FROM rooms WHERE id = ?").get(roomId);

    let meta = {};
    try {
      meta = JSON.parse(room?.meta || "{}");
    } catch (e) {}

    res.json({
      events: events,
      meta: meta,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Fetch error" });
  }
});

// --- Real-time Sync (Socket.io) ---

io.on("connection", (socket) => {
  socket.on("join", (roomId) => {
    socket.join(roomId);
  });

  // Handle Event Upsert (Add or Update)
  socket.on("event:save", ({ roomId, event }) => {
    if (!roomId || !event || !event.id) return;

    try {
      db.prepare(
        `
        INSERT INTO events (id, room_id, iv, data, updated_at) 
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
          iv=excluded.iv,
          data=excluded.data,
          updated_at=CURRENT_TIMESTAMP
      `,
      ).run(event.id, roomId, event.iv, event.data);

      socket.to(roomId).emit("event:sync", event);
    } catch (e) {
      console.error("Save error:", e);
    }
  });

  // Handle Event Delete
  socket.on("event:delete", ({ roomId, eventId }) => {
    if (!roomId || !eventId) return;

    try {
      db.prepare("DELETE FROM events WHERE id = ? AND room_id = ?").run(
        eventId,
        roomId,
      );
      socket.to(roomId).emit("event:remove", eventId);
    } catch (e) {
      console.error("Delete error:", e);
    }
  });

  // Handle Meta Update (Colors)
  socket.on("meta:save", ({ roomId, meta }) => {
    if (!roomId || !meta) return;
    try {
      const jsonMeta = JSON.stringify(meta);
      db.prepare("UPDATE rooms SET meta = ? WHERE id = ?").run(
        jsonMeta,
        roomId,
      );
      socket.to(roomId).emit("meta:sync", meta);
    } catch (e) {
      console.error("Meta save error:", e);
    }
  });
});

// Start Server
server.listen(PORT, () => {
  console.log(`Planner Server running on port ${PORT}`);
});
