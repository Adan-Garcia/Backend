//
const express = require("express");
const http = require("http");
const https = require("https"); // Added for external proxy requests
const { URL } = require("url"); // Added for URL parsing
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
const deleteManyEvents = db.transaction((roomId, ids) => {
  const stmt = db.prepare("DELETE FROM events WHERE id = ? AND room_id = ?");
  for (const id of ids) {
    stmt.run(id, roomId);
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

// --- NEW: iCal Proxy ---
app.get("/api/proxy/ical", (req, res) => {
  const { url } = req.query;
  const origin = req.get("origin") || req.get("referer");

  // 1. Security Check: Ensure request is from our site
  const allowedDomains = ["planner.adangarcia.com", "localhost", "127.0.0.1"];
  let isTrusted = false;
  
  if (origin) {
    try {
      const originHostname = new URL(origin).hostname;
      if (allowedDomains.includes(originHostname)) {
        isTrusted = true;
      }
    } catch (e) {
      // Invalid origin URL
    }
  }

  if (!isTrusted) {
    console.log(`[Proxy] Blocked request from unauthorized origin: ${origin}`);
    return res.status(403).json({ error: "Access denied. Invalid origin." });
  }

  if (!url) {
    return res.status(400).json({ error: "Missing url parameter" });
  }

  let targetUrl;
  try {
    targetUrl = new URL(url);
    if (!["http:", "https:"].includes(targetUrl.protocol)) {
      throw new Error("Invalid protocol");
    }
  } catch (e) {
    return res.status(400).json({ error: "Invalid URL provided" });
  }

  const client = targetUrl.protocol === "https:" ? https : http;

  client.get(url, (proxyRes) => {
    if (proxyRes.statusCode !== 200) {
      proxyRes.resume(); // consume response to free memory
      return res.status(proxyRes.statusCode).json({ error: "Remote server error" });
    }

    // 2. Content Validation Check: Look for magic string
    let hasValidated = false;
    let buffer = Buffer.alloc(0);
    const MAX_BUFFER = 4096; // Only check first 4KB

    proxyRes.on("data", (chunk) => {
      // If we've already validated, just stream chunks directly
      if (hasValidated) {
        return res.write(chunk);
      }

      // Buffer initial chunks to check content
      buffer = Buffer.concat([buffer, chunk]);

      // Check for iCalendar signature
      if (buffer.toString("utf8").includes("BEGIN:VCALENDAR")) {
        hasValidated = true;
        res.writeHead(200, {
          "Content-Type": "text/calendar",
          "Access-Control-Allow-Origin": "*",
        });
        res.write(buffer);
        buffer = null; // release memory
      } else if (buffer.length > MAX_BUFFER) {
        // If we read 4KB and didn't find the tag, abort
        proxyRes.destroy();
        if (!res.headersSent) {
          res.status(400).json({ error: "Target URL is not a valid iCalendar file." });
        }
      }
    });

    proxyRes.on("end", () => {
      // Handle case where file is smaller than one chunk/buffer limit but valid
      if (!hasValidated && buffer) {
        if (buffer.toString("utf8").includes("BEGIN:VCALENDAR")) {
          res.writeHead(200, {
            "Content-Type": "text/calendar",
            "Access-Control-Allow-Origin": "*",
          });
          res.write(buffer);
        } else if (!res.headersSent) {
          res.status(400).json({ error: "Target URL is not a valid iCalendar file." });
        }
      }
      if (!res.writableEnded) res.end();
    });

  }).on("error", (err) => {
    console.error("Proxy request failed:", err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: "Failed to fetch external calendar." });
    }
  });
});

// --- Real-time Sync & Auto-Cleanup ---
const roomCleanupTimers = new Map();

io.on("connection", (socket) => {
  socket.on("join", (roomId) => {
    socket.join(roomId);
    if (roomCleanupTimers.has(roomId)) {
      clearTimeout(roomCleanupTimers.get(roomId));
      roomCleanupTimers.delete(roomId);
    }
  });

  socket.on("disconnecting", () => {
    for (const room of socket.rooms) {
      if (room !== socket.id) {
        const roomSize = io.sockets.adapter.rooms.get(room)?.size || 0;
        if (roomSize <= 1) {
          const timer = setTimeout(() => {
            try {
              db.prepare("DELETE FROM events WHERE room_id = ?").run(room);
              roomCleanupTimers.delete(room);
            } catch (e) {
              console.error(`[Room ${room}] Cleanup failed:`, e);
            }
          }, 600000);
          roomCleanupTimers.set(room, timer);
        }
      }
    }
  });

  // --- UPDATED LISTENERS WITH ACKNOWLEDGEMENTS ---

  socket.on("event:save", ({ roomId, event }, callback) => {
    if (!roomId || !event || !event.id) {
      if (typeof callback === "function") callback({ error: "Invalid data" });
      return;
    }
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
      // ACK SUCCESS
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Save error:", e);
      // ACK FAILURE
      if (typeof callback === "function") callback({ error: "Database error" });
    }
  });

  socket.on("event:bulk_save", ({ roomId, events }, callback) => {
    if (!roomId || !events || !Array.isArray(events)) {
      if (typeof callback === "function") callback({ error: "Invalid data" });
      return;
    }
    try {
      insertManyEvents(roomId, events);
      socket.to(roomId).emit("event:bulk_sync", events);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Bulk save error:", e);
      if (typeof callback === "function")
        callback({ error: "Bulk save failed" });
    }
  });

  socket.on("event:delete", ({ roomId, eventId }, callback) => {
    if (!roomId || !eventId) return;
    try {
      db.prepare("DELETE FROM events WHERE id = ? AND room_id = ?").run(
        eventId,
        roomId,
      );
      socket.to(roomId).emit("event:remove", eventId);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Delete error:", e);
      if (typeof callback === "function") callback({ error: "Delete failed" });
    }
  });
  socket.on("event:bulk_delete", ({ roomId, eventIds }, callback) => {
    if (!roomId || !eventIds || !Array.isArray(eventIds)) {
      if (typeof callback === "function") callback({ error: "Invalid data" });
      return;
    }
    try {
      deleteManyEvents(roomId, eventIds);

      // Notify others to remove these specific IDs
      socket.to(roomId).emit("event:bulk_remove", eventIds);

      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Bulk delete error:", e);
      if (typeof callback === "function")
        callback({ error: "Bulk delete failed" });
    }
  });
  // UPDATED: Added callback support
  socket.on("meta:save", ({ roomId, meta }, callback) => {
    if (!roomId || !meta) return;
    try {
      const jsonMeta = JSON.stringify(meta);
      db.prepare("UPDATE rooms SET meta = ? WHERE id = ?").run(
        jsonMeta,
        roomId,
      );
      socket.to(roomId).emit("meta:sync", meta);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Meta save error:", e);
      if (typeof callback === "function")
        callback({ error: "Meta save failed" });
    }
  });
});

server.listen(PORT, () => {
  console.log(`Planner Server running on port ${PORT}`);
});