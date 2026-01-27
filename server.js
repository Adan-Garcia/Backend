const express = require("express");
const http = require("http");
const https = require("https");
const { URL } = require("url");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const dns = require("dns");

// --- Configuration ---
const PORT = process.env.PORT || 3001;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "planner.db");

// --- App Setup ---
const app = express();

// SECURITY: Trust the first proxy (Cloudflare Tunnel)
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json({ limit: "10mb" }));

const server = http.createServer(app);

// --- Database Setup ---
const db = new Database(DB_PATH, { verbose: console.log });

const initDb = () => {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      auth_hash TEXT NOT NULL,
      meta TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      iv TEXT NOT NULL,
      data TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
    )
  `).run();

  // SECURITY: New Session Table
  db.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
    )
  `).run();
};

initDb();

// --- SECURITY: Rate Limiting (In-Memory) ---
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_ATTEMPTS = 10;

const rateLimiter = (req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, start: now };

  if (now - record.start > RATE_LIMIT_WINDOW) {
    record.count = 0;
    record.start = now;
  }

  if (record.count >= MAX_ATTEMPTS) {
    return res.status(429).json({ error: "Too many login attempts. Try again later." });
  }

  record.count++;
  loginAttempts.set(ip, record);
  next();
};

// --- SECURITY: Session Verification ---
const verifySession = (token) => {
  if (!token) return null;
  const session = db.prepare("SELECT room_id FROM sessions WHERE token = ?").get(token);
  return session ? session.room_id : null;
};

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

// --- SOCKET.IO CONFIGURATION ---
const io = new Server(server, {
  path: "/backend/socket.io",
  cors: {
    origin: [
      "https://planner.adangarcia.com",
      "http://localhost:3000",
      "http://127.0.0.1:3000"
    ],
    methods: ["GET", "POST"],
    credentials: true
  },
  maxHttpBufferSize: 1e7, // Reduced to 1MB for safety
});

const nsp = io.of("/backend");

// --- SECURITY: Socket Authentication Middleware ---
nsp.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const roomId = socket.handshake.query.roomId || socket.handshake.auth.roomId;

  if (!token || !roomId) {
    return next(new Error("Authentication error: Missing credentials"));
  }

  try {
    // 1. Verify Session Token against Database
    const sessionRoomId = verifySession(token);

    if (!sessionRoomId) {
      return next(new Error("Authentication error: Invalid Session"));
    }

    // 2. Verify Token belongs to the requested Room
    if (sessionRoomId !== roomId) {
      return next(new Error("Authentication error: Room Mismatch"));
    }

    // 3. Attach verified room ID
    socket.data.roomId = roomId;
    next();
  } catch (e) {
    console.error("Auth Middleware Error:", e);
    next(new Error("Authentication error: Server check failed"));
  }
});

// --- REST API (Prefixed with /backend) ---

app.post("/backend/api/auth/init", (req, res) => {
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

app.post("/backend/api/auth/login", rateLimiter, (req, res) => {
  const { roomId, authHash, salt } = req.body;
  if (!roomId || !authHash)
    return res.status(400).json({ error: "Missing credentials" });

  try {
    // SECURITY: Hash the incoming authHash (effectively a password)
    const storageHash = crypto.createHash('sha256').update(authHash).digest('hex');

    const room = db.prepare("SELECT auth_hash FROM rooms WHERE id = ?").get(roomId);

    if (room) {
      // SECURITY: Timing-safe comparison
      const savedBuffer = Buffer.from(room.auth_hash);
      const attemptBuffer = Buffer.from(storageHash);

      // Protect against length mismatch crashing timingSafeEqual
      const match = savedBuffer.length === attemptBuffer.length &&
                    crypto.timingSafeEqual(savedBuffer, attemptBuffer);

      if (match) {
        // Generate secure random session token
        const token = crypto.randomUUID();
        db.prepare("INSERT INTO sessions (token, room_id) VALUES (?, ?)").run(token, roomId);
        return res.json({ token, authorized: true });
      }
      return res.status(401).json({ error: "Incorrect Password" });
    } else {
      if (!salt) return res.status(400).json({ error: "Missing salt" });
      
      // Store the HASHED version
      db.prepare("INSERT INTO rooms (id, salt, auth_hash, meta) VALUES (?, ?, ?, ?)").run(roomId, salt, storageHash, "{}");
      
      const token = crypto.randomUUID();
      db.prepare("INSERT INTO sessions (token, room_id) VALUES (?, ?)").run(token, roomId);
      return res.json({ token, authorized: true, created: true });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/backend/api/rooms/:roomId/events", (req, res) => {
  const { roomId } = req.params;
  const authHeader = req.headers.authorization;
  
  // SECURITY: Expect "Bearer <uuid>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const sessionRoomId = verifySession(token);

  if (!sessionRoomId || sessionRoomId !== roomId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const events = db.prepare("SELECT id, iv, data FROM events WHERE room_id = ?").all(roomId);
    const room = db.prepare("SELECT meta FROM rooms WHERE id = ?").get(roomId);
    let meta = {};
    try { meta = JSON.parse(room?.meta || "{}"); } catch (e) {}
    res.json({ events, meta });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Fetch error" });
  }
});

// --- SECURE iCal Proxy (SSRF Protected) ---

const isPrivateIP = (ip) => {
  const parts = ip.split('.').map(Number);
  if (parts.length === 4) {
    if (parts[0] === 0) return true;
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
  } else if (ip.includes(':')) {
    if (ip === '::1') return true;
    if (ip.toLowerCase().startsWith('fe80::')) return true;
    if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true;
  }
  return false;
};

app.get("/backend/api/proxy/ical", (req, res) => {
  const { url: urlParam } = req.query;
  const origin = req.get("origin") || req.get("referer");

  const allowedDomains = ["planner.adangarcia.com", "localhost", "127.0.0.1"];
  let isTrusted = false;
  if (origin) {
    try {
      const originHostname = new URL(origin).hostname;
      if (allowedDomains.includes(originHostname)) isTrusted = true;
    } catch (e) {}
  }
  if (!isTrusted && origin) return res.status(403).json({ error: "Access denied. Invalid origin." });

  if (!urlParam) return res.status(400).json({ error: "Missing url parameter" });

  let targetUrl;
  try {
    targetUrl = new URL(urlParam);
    if (!["http:", "https:"].includes(targetUrl.protocol)) {
      throw new Error("Invalid protocol");
    }
  } catch (e) {
    return res.status(400).json({ error: "Invalid URL provided" });
  }

  dns.lookup(targetUrl.hostname, (err, address) => {
    if (err) return res.status(400).json({ error: "Failed to resolve hostname" });
    
    if (isPrivateIP(address)) {
      console.warn(`[SSRF Block] Blocked attempt to access ${address} (${targetUrl.hostname})`);
      return res.status(403).json({ error: "Access denied. Internal network." });
    }

    const client = targetUrl.protocol === "https:" ? https : http;

    const proxyRequest = client.get(urlParam, (proxyRes) => {
      if (proxyRes.statusCode !== 200) {
        proxyRes.resume(); 
        return res.status(proxyRes.statusCode).json({ error: "Remote server error" });
      }

      let hasValidated = false;
      let buffer = Buffer.alloc(0);
      const MAX_BUFFER = 4096; 

      proxyRes.on("data", (chunk) => {
        if (hasValidated) {
          return res.write(chunk);
        }
        buffer = Buffer.concat([buffer, chunk]);

        if (buffer.toString("utf8").includes("BEGIN:VCALENDAR")) {
          hasValidated = true;
          res.writeHead(200, {
            "Content-Type": "text/calendar",
            "Access-Control-Allow-Origin": "*",
          });
          res.write(buffer);
          buffer = null; 
        } else if (buffer.length > MAX_BUFFER) {
          proxyRes.destroy();
          if (!res.headersSent) {
            res.status(400).json({ error: "Target URL is not a valid iCalendar file." });
          }
        }
      });

      proxyRes.on("end", () => {
        if (!hasValidated && buffer && !res.headersSent) {
          if (buffer.toString("utf8").includes("BEGIN:VCALENDAR")) {
            res.writeHead(200, {
              "Content-Type": "text/calendar",
              "Access-Control-Allow-Origin": "*",
            });
            res.write(buffer);
          } else {
            res.status(400).json({ error: "Target URL is not a valid iCalendar file." });
          }
        }
        if (!res.writableEnded) res.end();
      });
    });
    
    proxyRequest.on("error", (err) => {
      if (!res.headersSent) {
        res.status(500).json({ error: "Failed to fetch external calendar." });
      }
    });
  });
});

// --- Real-time Sync & Auto-Cleanup ---
const roomCleanupTimers = new Map();

const broadcastRoomCount = (roomId) => {
  const room = nsp.adapter.rooms.get(roomId);
  const count = room ? room.size : 0;
  nsp.to(roomId).emit("room:count", count);
};

nsp.on("connection", (socket) => {
  const roomId = socket.data.roomId;

  socket.on("join", (requestedRoom) => {
    if (requestedRoom !== roomId) {
        socket.emit("error", { message: "Unauthorized: You cannot join this room." });
        return;
    }

    socket.join(roomId);
    if (roomCleanupTimers.has(roomId)) {
      clearTimeout(roomCleanupTimers.get(roomId));
      roomCleanupTimers.delete(roomId);
    }
    broadcastRoomCount(roomId);
  });

  socket.on("disconnecting", () => {
    const roomSize = nsp.adapter.rooms.get(roomId)?.size || 0;
    nsp.to(roomId).emit("room:count", Math.max(0, roomSize - 1));

    if (roomSize <= 1) {
      const timer = setTimeout(() => {
        try {
          db.prepare("DELETE FROM events WHERE room_id = ?").run(roomId);
          db.prepare("DELETE FROM sessions WHERE room_id = ?").run(roomId); // CLEANUP SESSIONS TOO
          roomCleanupTimers.delete(roomId);
        } catch (e) {
          console.error(`[Room ${roomId}] Cleanup failed:`, e);
        }
      }, 600000); // 10 minutes
      roomCleanupTimers.set(roomId, timer);
    }
  });

  socket.on("event:save", ({ roomId: targetRoom, event }, callback) => {
    if (targetRoom !== roomId) return;
    if (!event || !event.id) {
      if (typeof callback === "function") callback({ error: "Invalid data" });
      return;
    }
    try {
      db.prepare(`
        INSERT INTO events (id, room_id, iv, data, updated_at) 
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
          iv=excluded.iv,
          data=excluded.data,
          updated_at=CURRENT_TIMESTAMP
      `).run(event.id, roomId, event.iv, event.data);

      socket.to(roomId).emit("event:sync", event);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Save error:", e);
      if (typeof callback === "function") callback({ error: "Database error" });
    }
  });

  socket.on("event:bulk_save", ({ roomId: targetRoom, events }, callback) => {
    if (targetRoom !== roomId) return;
    if (!events || !Array.isArray(events)) {
      if (typeof callback === "function") callback({ error: "Invalid data" });
      return;
    }
    // SECURITY: Limit batch size
    if (events.length > 2000) {
      if (typeof callback === "function") callback({ error: "Batch too large (max 2000)" });
      return;
    }

    try {
      insertManyEvents(roomId, events);
      socket.to(roomId).emit("event:bulk_sync", events);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Bulk save error:", e);
      if (typeof callback === "function") callback({ error: "Bulk save failed" });
    }
  });

  socket.on("event:delete", ({ roomId: targetRoom, eventId }, callback) => {
    if (targetRoom !== roomId) return;
    if (!eventId) return;
    try {
      db.prepare("DELETE FROM events WHERE id = ? AND room_id = ?").run(eventId, roomId);
      socket.to(roomId).emit("event:remove", eventId);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Delete error:", e);
      if (typeof callback === "function") callback({ error: "Delete failed" });
    }
  });
  
  socket.on("event:bulk_delete", ({ roomId: targetRoom, eventIds }, callback) => {
    if (targetRoom !== roomId) return;
    if (!eventIds || !Array.isArray(eventIds)) {
      if (typeof callback === "function") callback({ error: "Invalid data" });
      return;
    }
    try {
      deleteManyEvents(roomId, eventIds);
      socket.to(roomId).emit("event:bulk_remove", eventIds);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Bulk delete error:", e);
      if (typeof callback === "function") callback({ error: "Bulk delete failed" });
    }
  });

  socket.on("meta:save", ({ roomId: targetRoom, meta }, callback) => {
    if (targetRoom !== roomId) return;
    if (!meta) return;
    try {
      const jsonMeta = JSON.stringify(meta);
      db.prepare("UPDATE rooms SET meta = ? WHERE id = ?").run(jsonMeta, roomId);
      socket.to(roomId).emit("meta:sync", meta);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      console.error("Meta save error:", e);
      if (typeof callback === "function") callback({ error: "Meta save failed" });
    }
  });
});

server.listen(PORT, () => {
  console.log(`Planner Server running on port ${PORT}`);
});
