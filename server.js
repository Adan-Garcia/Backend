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
app.use(express.json({ limit: "10mb" }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
  maxHttpBufferSize: 1e8,
});

// --- Database Setup ---
const db = new Database(DB_PATH, { verbose: console.log });

const initDb = () => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      auth_hash TEXT NOT NULL,
      meta TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      iv TEXT NOT NULL,
      data TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
    )
  `,
  ).run();
};

initDb();

// --- OPTIMIZATION: Prepared Statements & Transactions ---

const insertManyEvents = db.transaction((roomId, events) => {
  const stmt = db.prepare(`
    INSERT INTO events (id, room_id, iv, data, updated_at) 
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      iv=excluded.iv,
      data=excluded.data,
      updated_at=CURRENT_TIMESTAMP
  `);

  for (const event of events) {
    stmt.run(event.id, roomId, event.iv, event.data);
  }
});

// --- REST API ---

app.post("/api/auth/init", (req, res) => {
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: "Missing roomId" });
  try {
    const room = db.prepare("SELECT salt FROM rooms WHERE id = ?").get(roomId);
    if (room) return res.json({ salt: room.salt, isNew: false });
    const newSalt = crypto.randomBytes(16).toString("hex");
    return res.json({ salt: newSalt, isNew: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", (req, res) => {
  const { roomId, authHash, salt } = req.body;
  if (!roomId || !authHash)
    return res.status(400).json({ error: "Missing credentials" });
  try {
    const room = db
      .prepare("SELECT auth_hash FROM rooms WHERE id = ?")
      .get(roomId);
    if (room) {
      if (room.auth_hash === authHash) {
        const token = Buffer.from(`${roomId}:${authHash}`).toString("base64");
        return res.json({ token, authorized: true });
      }
      return res.status(401).json({ error: "Incorrect Password" });
    } else {
      if (!salt) return res.status(400).json({ error: "Missing salt" });
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
    res.json({ events, meta });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Fetch error" });
  }
});

// --- Real-time Sync & Auto-Cleanup ---

// Map to track pending deletions (RoomID -> Timeout)
const roomCleanupTimers = new Map();

io.on("connection", (socket) => {
  socket.on("join", (roomId) => {
    socket.join(roomId);

    // If this room was scheduled for deletion (e.g. user refreshed page), cancel it!
    if (roomCleanupTimers.has(roomId)) {
      console.log(`[Room ${roomId}] User reconnected. Cancelling cleanup.`);
      clearTimeout(roomCleanupTimers.get(roomId));
      roomCleanupTimers.delete(roomId);
    }
  });

  socket.on("disconnecting", () => {
    // Check all rooms this socket was in
    for (const room of socket.rooms) {
      if (room !== socket.id) {
        // Check how many people are left.
        // Note: socket.rooms includes the current socket, so we check if size <= 1
        const roomSize = io.sockets.adapter.rooms.get(room)?.size || 0;

        if (roomSize <= 1) {
          console.log(`[Room ${room}] Empty. Scheduling cleanup in 10s...`);

          // Schedule cleanup for 10 seconds later
          const timer = setTimeout(() => {
            console.log(
              `[Room ${room}] Cleanup executing. Deleting event data ONLY.`,
            );
            try {
              // Delete Events (Ephemeral data)
              db.prepare("DELETE FROM events WHERE room_id = ?").run(room);

              // NOTE: We do NOT delete the room metadata (rooms table)
              // This allows the room ID & Password/Salt to persist so users can rejoin
              // db.prepare("DELETE FROM rooms WHERE id = ?").run(room);

              roomCleanupTimers.delete(room);
            } catch (e) {
              console.error(`[Room ${room}] Cleanup failed:`, e);
            }
          }, 10000); // 10 Second Grace Period

          roomCleanupTimers.set(room, timer);
        }
      }
    }
  });

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

  socket.on("event:bulk_save", ({ roomId, events }) => {
    if (!roomId || !events || !Array.isArray(events)) return;
    try {
      insertManyEvents(roomId, events);
      socket.to(roomId).emit("event:bulk_sync", events);
    } catch (e) {
      console.error("Bulk save error:", e);
    }
  });

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

server.listen(PORT, () => {
  console.log(`Planner Server running on port ${PORT}`);
});
