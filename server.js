const express = require("express");
const http = require("http");
const https = require("https");
const fs = require("fs");
const { URL } = require("url");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const dns = require("dns");
const net = require('net');
const helmet = require("helmet");

// --- Configuration ---
const PORT = process.env.PORT || 3001;
const USE_HTTPS = process.env.USE_HTTPS === 'true';
const SSL_KEY_PATH = process.env.SSL_KEY_PATH;
const SSL_CERT_PATH = process.env.SSL_CERT_PATH;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "planner.db");
let APIORIGINS = process.env.ORIGINS ? process.env.ORIGINS.split(',').map(s => s.trim()) : [
      "https://planner.adangarcia.com",
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "https://api.adangarcia.com",
      "https://homework.adangarcia.com",
    ];

const ALLOWED_HOSTNAMES = APIORIGINS.map(o => {
  try { return (new URL(o)).hostname; } catch (e) { return o; }
});

// --- App Setup ---
const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      "default-src": ["'self'"],
      "base-uri": ["'self'"],
      "font-src": ["'self'"],
      "form-action": ["'self'"],
      "frame-ancestors": ["'none'"],
      "img-src": ["'self'", "data:"],
      "object-src": ["'none'"],
      "script-src": ["'self'"],
      "style-src": ["'self'"],
      "connect-src": ["'self'"]
    }
  },
  crossOriginResourcePolicy: { policy: "same-origin" },
  crossOriginEmbedderPolicy: { policy: "require-corp" },
  crossOriginOpenerPolicy: { policy: "same-origin" }
}));
// Helmet v8+ does not include permissionsPolicy. Set Permissions-Policy header manually.
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "accelerometer=(), autoplay=(), camera=(), display-capture=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
  );
  next();
});
app.set('trust proxy', 1);

// CORS Configuration
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, Postman, or same-origin)
    if (!origin) return callback(null, true);
    
    if (APIORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      console.log('CORS rejected origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Content-Length', 'Content-Type'],
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Enable pre-flight for all routes
app.use(express.json({ limit: "10mb" }));

// Cache-Control for sensitive routes
app.use((req, res, next) => {
  if (req.path === "/backend/api/health" || req.path === "/backend/api/auth/login") {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
});

// Debug middleware to log requests and CORS headers
app.use((req, res, next) => {
  const origin = req.get('origin');
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${origin || 'none'}`);
  
  // Ensure CORS headers are set even if cors() middleware didn't catch it
  if (origin && APIORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  }
  
  next();
});

// --- Server Setup ---
let server;
if (USE_HTTPS && SSL_KEY_PATH && SSL_CERT_PATH) {
  try {
    const sslOptions = {
      key: fs.readFileSync(SSL_KEY_PATH),
      cert: fs.readFileSync(SSL_CERT_PATH)
    };
    server = https.createServer(sslOptions, app);
    console.log('HTTPS server enabled');
  } catch (error) {
    console.error('Failed to load SSL certificates, falling back to HTTP:', error.message);
    server = http.createServer(app);
  }
} else {
  server = http.createServer(app);
  console.log('HTTP server enabled');
}

// --- Database Setup ---
const db = new Database(DB_PATH, process.env.NODE_ENV !== 'production' ? { verbose: console.log } : {});
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON'); // CRITICAL: Enables Cascade Delete

const initDb = () => {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      auth_hash TEXT NOT NULL,
      meta TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_active DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS events (
      room_id TEXT NOT NULL,
      id TEXT NOT NULL,
      iv TEXT NOT NULL,
      data TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE,
      PRIMARY KEY (room_id, id)
    )
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
    )
  `).run();

  // OPTIMIZATION: Indexes for performance
  db.prepare(`CREATE INDEX IF NOT EXISTS idx_events_room_id ON events(room_id)`).run();
  db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at)`).run();

  // Migration: ensure composite primary key on events (room_id, id)
  try {
    const eventColumns = db.prepare("PRAGMA table_info(events)").all();
    const pkCols = eventColumns.filter((c) => c.pk > 0).map((c) => c.name);
    const hasCompositePk = pkCols.length === 2 && pkCols.includes("room_id") && pkCols.includes("id");

    if (!hasCompositePk) {
      db.exec(`
        BEGIN TRANSACTION;
        CREATE TABLE IF NOT EXISTS events_new (
          room_id TEXT NOT NULL,
          id TEXT NOT NULL,
          iv TEXT NOT NULL,
          data TEXT NOT NULL,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE,
          PRIMARY KEY (room_id, id)
        );
        INSERT OR IGNORE INTO events_new (room_id, id, iv, data, updated_at)
          SELECT room_id, id, iv, data, updated_at FROM events;
        DROP TABLE events;
        ALTER TABLE events_new RENAME TO events;
        COMMIT;
      `);
      db.prepare(`CREATE INDEX IF NOT EXISTS idx_events_room_id ON events(room_id)`).run();
    }
  } catch (e) {
    console.error("[DB Migration] Failed to ensure composite PK on events:", e);
  }
};

initDb();

// --- Prepared Statements ---
const stmts = {
  // Sessions
  selectSession: db.prepare("SELECT room_id, created_at FROM sessions WHERE token = ?"),
  insertSession: db.prepare("INSERT INTO sessions (token, room_id) VALUES (?, ?)"),
  deleteSession: db.prepare("DELETE FROM sessions WHERE token = ?"),
  deleteExpiredSessions: db.prepare("DELETE FROM sessions WHERE created_at < datetime('now', ?)"),
  
  // Rooms
  selectRoomSalt: db.prepare("SELECT salt FROM rooms WHERE id = ?"),
  selectRoomAuthHash: db.prepare("SELECT auth_hash FROM rooms WHERE id = ?"),
  selectRoomMeta: db.prepare("SELECT meta FROM rooms WHERE id = ?"),
  insertRoom: db.prepare("INSERT INTO rooms (id, salt, auth_hash, meta) VALUES (?, ?, ?, ?)"),
  updateRoomLastActive: db.prepare("UPDATE rooms SET last_active = CURRENT_TIMESTAMP WHERE id = ?"),
  updateRoomMeta: db.prepare("UPDATE rooms SET meta = ? WHERE id = ?"),
  deleteExpiredRooms: db.prepare("DELETE FROM rooms WHERE last_active < datetime('now', ?)"),
  
  // Events
  selectRoomEvents: db.prepare("SELECT id, iv, data FROM events WHERE room_id = ?"),
  insertOrUpdateEvent: db.prepare(`
    INSERT INTO events (id, room_id, iv, data, updated_at) 
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(room_id, id) DO UPDATE SET iv=excluded.iv, data=excluded.data, updated_at=CURRENT_TIMESTAMP
  `),
  deleteEvent: db.prepare("DELETE FROM events WHERE id = ? AND room_id = ?"),
};

// --- SECURITY: Rate Limiting ---
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_ATTEMPTS = 10;

const rateLimiter = (req, res, next) => {
  const key = `${req.ip}:${req.body.roomId || ''}`;

  const now = Date.now();
  const record = loginAttempts.get(key) || { count: 0, start: now };

  if (now - record.start > RATE_LIMIT_WINDOW) {
    record.count = 0;
    record.start = now;
  }

  if (record.count >= MAX_ATTEMPTS) {
    return res.status(429).json({ error: "Too many login attempts. Try again later." });
  }

  record.count++;
  loginAttempts.set(key, record);
  next();
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of loginAttempts) {
    if (now - rec.start > RATE_LIMIT_WINDOW * 5) {
      loginAttempts.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW);

// --- SECURITY: Session Verification ---
const SESSION_TTL = parseInt(process.env.SESSION_TTL_MS, 10) || 24 * 60 * 60 * 1000;
const verifySession = (token) => {
  if (!token) return null;
  const session = stmts.selectSession.get(token);
  if (!session) return null;
  const created = new Date(session.created_at).getTime();
  if (Date.now() - created > SESSION_TTL) {
    try { stmts.deleteSession.run(token); } catch (e) {}
    return null;
  }
  return session.room_id;
};

// --- Meta Validation ---
const MAX_META_SIZE = parseInt(process.env.MAX_META_SIZE, 10) || 2048;
const validateMeta = (meta) => {
  if (meta === null || typeof meta !== 'object' || Array.isArray(meta)) return { valid: false, error: 'meta must be an object' };
  const keys = Object.keys(meta);
  if (keys.length > 20) return { valid: false, error: 'meta has too many keys' };
  for (const k of keys) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(k)) return { valid: false, error: `Invalid meta key: ${k}` };
    const v = meta[k];
    const t = typeof v;
    if (!(v === null || t === 'string' || t === 'number' || t === 'boolean')) return { valid: false, error: `Invalid meta value for key ${k}` };
  }
  try {
    const s = JSON.stringify(meta);
    if (s.length > MAX_META_SIZE) return { valid: false, error: 'meta too large' };
  } catch (e) { return { valid: false, error: 'meta serialization failed' }; }
  return { valid: true };
};

// --- Input Validation ---
const MAX_ROOM_ID_LENGTH = 128;
const MAX_EVENT_ID_LENGTH = 128;
const MAX_IV_LENGTH = 64;
const MAX_DATA_LENGTH = 100000; // 100KB per event

const validateEventInput = (event) => {
  if (!event || typeof event !== 'object') return { valid: false, error: 'Invalid event object' };
  if (!event.id || typeof event.id !== 'string' || event.id.length > MAX_EVENT_ID_LENGTH) return { valid: false, error: 'Invalid event.id' };
  if (!event.iv || typeof event.iv !== 'string' || event.iv.length > MAX_IV_LENGTH) return { valid: false, error: 'Invalid event.iv' };
  if (!event.data || typeof event.data !== 'string' || event.data.length > MAX_DATA_LENGTH) return { valid: false, error: 'Invalid event.data' };
  return { valid: true };
};

const validateEventId = (eventId) => {
  return !!(eventId && typeof eventId === 'string' && eventId.length <= MAX_EVENT_ID_LENGTH);
};

const validateRoomId = (roomId) => {
  if (!roomId || typeof roomId !== 'string') return false;
  if (roomId.length === 0 || roomId.length > MAX_ROOM_ID_LENGTH) return false;
  return /^[a-zA-Z0-9_-]+$/.test(roomId);
};

// --- OPTIMIZATION: Transactions ---
const insertManyEvents = db.transaction((roomId, events) => {
  for (const event of events) {
    stmts.insertOrUpdateEvent.run(event.id, roomId, event.iv, event.data);
  }
});

const deleteManyEvents = db.transaction((roomId, ids) => {
  for (const id of ids) {
    stmts.deleteEvent.run(id, roomId);
  }
});

// --- SOCKET SECURITY: Connection + Event Rate Limits ---
const SOCKET_CONN_WINDOW = 60 * 1000;
const SOCKET_MAX_CONN_PER_WINDOW = parseInt(process.env.SOCKET_MAX_CONN_PER_WINDOW, 10) || 30;
const SOCKET_MAX_SOCKETS_PER_IP = parseInt(process.env.SOCKET_MAX_SOCKETS_PER_IP, 10) || 20;
const SOCKET_EVENT_WINDOW = 10 * 1000;
const SOCKET_MAX_EVENTS_PER_WINDOW = parseInt(process.env.SOCKET_MAX_EVENTS_PER_WINDOW, 10) || 80;

const socketConnectionAttempts = new Map(); // ip -> { count, start }
const socketConnectionCounts = new Map(); // ip -> count

const getClientIpFromSocket = (socket) => {
  const headers = socket.handshake?.headers || {};
  const cfIp = headers["cf-connecting-ip"];
  const xff = headers["x-forwarded-for"];
  if (cfIp) return cfIp;
  if (xff) return xff.split(",")[0].trim();
  return socket.handshake?.address || socket.conn?.remoteAddress || "unknown";
};

const getClientIpFromRequest = (req) => {
  const headers = req.headers || {};
  const cfIp = headers["cf-connecting-ip"];
  const xff = headers["x-forwarded-for"];
  if (cfIp) return cfIp;
  if (xff) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
};

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of socketConnectionAttempts) {
    if (now - record.start > SOCKET_CONN_WINDOW * 5) {
      socketConnectionAttempts.delete(ip);
    }
  }
}, SOCKET_CONN_WINDOW);

// --- SOCKET.IO ---
const io = new Server(server, {
  path: "/backend/socket.io",
  cors: {
    origin: APIORIGINS,
    methods: ["GET", "POST"],
    credentials: true
  },
  maxHttpBufferSize: 1e7, // 1MB
  allowRequest: (req, callback) => {
    const ip = getClientIpFromRequest(req);
    if (!ip || ip === "unknown") return callback("Unable to determine client IP", false);

    const isHandshake = !(req._query && req._query.sid) && !(req.url && req.url.includes("sid="));
    if (!isHandshake) return callback(null, true);

    const now = Date.now();
    const record = socketConnectionAttempts.get(ip) || { count: 0, start: now };
    if (now - record.start > SOCKET_CONN_WINDOW) {
      record.count = 0;
      record.start = now;
    }
    if (record.count >= SOCKET_MAX_CONN_PER_WINDOW) {
      return callback("Rate limit: too many connections", false);
    }
    record.count++;
    socketConnectionAttempts.set(ip, record);

    const currentCount = socketConnectionCounts.get(ip) || 0;
    if (currentCount >= SOCKET_MAX_SOCKETS_PER_IP) {
      return callback("Connection limit exceeded", false);
    }

    return callback(null, true);
  }

});

const nsp = io.of("/backend");

nsp.use((socket, next) => {
  const ip = getClientIpFromSocket(socket);
  if (!ip || ip === "unknown") return next(new Error("Unable to determine client IP"));
  socket.data.clientIp = ip;

  const now = Date.now();
  const record = socketConnectionAttempts.get(ip) || { count: 0, start: now };
  if (now - record.start > SOCKET_CONN_WINDOW) {
    record.count = 0;
    record.start = now;
  }
  if (record.count >= SOCKET_MAX_CONN_PER_WINDOW) {
    return next(new Error("Rate limit: too many connections"));
  }
  record.count++;
  socketConnectionAttempts.set(ip, record);

  const currentCount = socketConnectionCounts.get(ip) || 0;
  if (currentCount >= SOCKET_MAX_SOCKETS_PER_IP) {
    return next(new Error("Connection limit exceeded"));
  }

  next();
});

nsp.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const roomId = socket.handshake.query.roomId || socket.handshake.auth.roomId;

  if (!token || !roomId) return next(new Error("Authentication error: Missing credentials"));

  try {
    const sessionRoomId = verifySession(token);
    if (!sessionRoomId) return next(new Error("Authentication error: Invalid Session"));
    if (sessionRoomId !== roomId) return next(new Error("Authentication error: Room Mismatch"));

    socket.data.roomId = roomId;
    next();
  } catch (e) {
    console.error("Auth Middleware Error:", e);
    next(new Error("Authentication error: Server check failed"));
  }
});

// --- REST API ---

// Health check endpoint
app.get("/backend/api/health", (req, res) => {
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});

app.post("/backend/api/auth/init", (req, res) => {
  const { roomId } = req.body;
  if (!validateRoomId(roomId)) return res.status(400).json({ error: "Invalid roomId" });
  try {
    const room = stmts.selectRoomSalt.get(roomId);
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
  if (!validateRoomId(roomId) || !authHash) return res.status(400).json({ error: "Invalid credentials" });

  try {
    const storageHash = crypto.createHash('sha512').update(authHash).digest('hex');
    const room = stmts.selectRoomAuthHash.get(roomId);

    if (room) {
      const savedBuffer = Buffer.from(room.auth_hash, 'hex');
      const attemptBuffer = Buffer.from(storageHash, 'hex');
      const match = savedBuffer.length === attemptBuffer.length && crypto.timingSafeEqual(savedBuffer, attemptBuffer);

      if (match) {
        const token = crypto.randomUUID();
        stmts.insertSession.run(token, roomId);
        return res.json({ token, authorized: true });
      }
      return res.status(401).json({ error: "Incorrect Password" });
    } else {
      if (!salt) return res.status(400).json({ error: "Missing salt" });
      stmts.insertRoom.run(roomId, salt, storageHash, "{}");
      const token = crypto.randomUUID();
      stmts.insertSession.run(token, roomId);
      return res.json({ token, authorized: true, created: true });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/backend/api/auth/logout", (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(400).json({ error: "Missing token" });
  try {
    const deleted = stmts.deleteSession.run(token);
    res.json({ success: true, revoked: deleted.changes > 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Logout failed" });
  }
});

app.get("/backend/api/rooms/:roomId/events", (req, res) => {
  const { roomId } = req.params;
  if (!validateRoomId(roomId)) return res.status(400).json({ error: "Invalid roomId" });
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const sessionRoomId = verifySession(token);
  if (!sessionRoomId || sessionRoomId !== roomId) return res.status(401).json({ error: "Unauthorized" });

  try {
    const events = stmts.selectRoomEvents.all(roomId);
    const room = stmts.selectRoomMeta.get(roomId);
    let meta = {};
    try { meta = JSON.parse(room?.meta || "{}"); } catch (e) {}
    res.json({ events, meta });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Fetch error" });
  }
});

// --- SECURE PROXY (SSRF PROTECTED) ---

const isPrivateIP = (ip) => {
  if (!ip) return false;
  if (ip.includes('::ffff:')) ip = ip.split('::ffff:').pop();
  const family = net.isIP(ip);
  if (family === 4) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 0 || parts[0] === 10 || parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
  } else if (family === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower.startsWith('fe80') || lower.startsWith('fc') || lower.startsWith('fd')) return true;
    return false;
  }
  return false;
};

app.get("/backend/api/proxy/ical", (req, res) => {
  const { url: urlParam } = req.query;
  const origin = req.get("origin") || req.get("referer");

  let isTrusted = false;
  if (origin) {
    try {
      const originHostname = new URL(origin).hostname;
      if (APIORIGINS.includes(origin) || ALLOWED_HOSTNAMES.includes(originHostname)) isTrusted = true;
    } catch (e) {}
  }
  if (!isTrusted && origin) return res.status(403).json({ error: "Access denied. Invalid origin." });

  if (!urlParam) return res.status(400).json({ error: "Missing url parameter" });

  const MAX_REDIRECTS = 5;
  const REQUEST_TIMEOUT = 10000;

  const makeRequest = (currentUrl, redirectsLeft) => {
    let urlObj;
    try { urlObj = new URL(currentUrl); } catch (e) { 
      if (!res.headersSent) return res.status(400).json({ error: "Invalid URL" }); return; 
    }
    if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") {
      if (!res.headersSent) return res.status(400).json({ error: "Unsupported URL protocol" });
      return;
    }

    // 1. Resolve DNS to get IP
    dns.lookup(urlObj.hostname, { all: true }, (err, addresses) => {
      if (err || !addresses || addresses.length === 0) {
        if (!res.headersSent) return res.status(400).json({ error: "Failed to resolve hostname" });
        return;
      }

      // 2. Validate IP (SSRF Check)
      for (const addr of addresses) {
      if (isPrivateIP(addr.address)) {
        return res.status(403).json({ error: "Access denied. Internal network." });
      }
      }
      const safeAddress = addresses[0].address;


      const client = urlObj.protocol === "https:" ? https : http;
      
      // 3. Connect DIRECTLY to the validated IP (Avoids DNS Rebinding)
      const options = {
        hostname: safeAddress,
        port: urlObj.port || (urlObj.protocol === "https:" ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        headers: {
          'Host': urlObj.hostname, // Spoof Host header for virtual hosts
          'User-Agent': 'PlannerProxy/1.0'
        },
        servername: urlObj.hostname, // Required for HTTPS SNI
      };

      const req = client.request(options, (proxyRes) => {
        if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
          proxyRes.resume();
          if (redirectsLeft <= 0) return res.status(400).json({ error: "Too many redirects" });
          let nextUrl;
          try { nextUrl = new URL(proxyRes.headers.location, urlObj); } catch (e) { return res.status(400).json({ error: "Invalid redirect" }); }
          return makeRequest(nextUrl.toString(), redirectsLeft - 1);
        }

        if (proxyRes.statusCode !== 200) {
          proxyRes.resume();
          return res.status(proxyRes.statusCode).json({ error: "Remote server error" });
        }

        let hasValidated = false;
        let buffer = Buffer.alloc(0);
        const MAX_BUFFER = 4096;

        proxyRes.on("data", (chunk) => {
          if (hasValidated) return res.write(chunk);
          buffer = Buffer.concat([buffer, chunk]);

          if (buffer.toString("utf8").includes("BEGIN:VCALENDAR")) {
            hasValidated = true;
            const headers = { "Content-Type": "text/calendar" };
            if (origin && isTrusted) headers["Access-Control-Allow-Origin"] = origin;
            res.writeHead(200, headers);
            res.write(buffer);
            buffer = null;
          } else if (buffer.length > MAX_BUFFER) {
            proxyRes.destroy();
            if (!res.headersSent) res.status(400).json({ error: "Target URL is not a valid iCalendar file." });
          }
        });

        proxyRes.on("end", () => {
          if (!hasValidated && buffer && !res.headersSent) {
            if (buffer.toString("utf8").includes("BEGIN:VCALENDAR")) {
              const headers = { "Content-Type": "text/calendar" };
              if (origin && isTrusted) headers["Access-Control-Allow-Origin"] = origin;
              res.writeHead(200, headers);
              res.write(buffer);
            } else {
              res.status(400).json({ error: "Target URL is not a valid iCalendar file." });
            }
          }
          if (!res.writableEnded) res.end();
        });

        proxyRes.on("error", () => {
          if (!res.headersSent) res.status(500).json({ error: "Failed to fetch external calendar." });
        });
      });

      req.setTimeout(REQUEST_TIMEOUT, () => {
        req.destroy();
        if (!res.headersSent) res.status(504).json({ error: "External request timed out." });
      });

      req.on("error", () => {
        if (!res.headersSent) res.status(500).json({ error: "Failed to fetch external calendar." });
      });

      req.end();
    });
  };

  makeRequest(urlParam, MAX_REDIRECTS);
});

// --- Error Handling (no stack traces) ---
app.use((err, req, res, next) => {
  if (!err) return next();
  const status = err.status || err.statusCode || 500;
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({ error: "Malformed JSON" });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Payload too large" });
  }
  console.error("Unhandled error:", err);
  return res.status(status).json({ error: "Server error" });
});

// --- REAL-TIME SYNC ---

// Helper: now accepts an offset (e.g., -1 for disconnecting)
const broadcastRoomCount = (roomId, offset = 0) => {
  const room = nsp.adapter.rooms.get(roomId);
  const count = room ? Math.max(0, room.size + offset) : 0;
  nsp.to(roomId).emit("room:count", count);
};

nsp.on("connection", (socket) => {
  const clientIp = socket.data.clientIp || "unknown";
  const currentCount = socketConnectionCounts.get(clientIp) || 0;
  socketConnectionCounts.set(clientIp, currentCount + 1);

  const eventRate = { count: 0, start: Date.now() };
  socket.use((packet, next) => {
    const now = Date.now();
    if (now - eventRate.start > SOCKET_EVENT_WINDOW) {
      eventRate.count = 0;
      eventRate.start = now;
    }
    eventRate.count++;
    if (eventRate.count > SOCKET_MAX_EVENTS_PER_WINDOW) {
      socket.emit("error", { message: "Rate limit exceeded" });
      return socket.disconnect(true);
    }
    next();
  });

  const roomId = socket.data.roomId;

  socket.on("join", (requestedRoom) => {
    if (requestedRoom !== roomId) {
        socket.emit("error", { message: "Unauthorized: You cannot join this room." });
        return;
    }
    socket.join(roomId);
    broadcastRoomCount(roomId);
  });

  socket.on("disconnecting", () => {
    // Subtract 1 manually using the offset
    broadcastRoomCount(roomId, -1);
  });

  socket.on("disconnect", () => {
    const count = socketConnectionCounts.get(clientIp) || 1;
    const nextCount = Math.max(0, count - 1);
    if (nextCount === 0) socketConnectionCounts.delete(clientIp);
    else socketConnectionCounts.set(clientIp, nextCount);
  });

  socket.on("event:save", ({ roomId: targetRoom, event }, callback) => {
    if (targetRoom !== roomId) return;
    const validation = validateEventInput(event);
    if (!validation.valid) { if (typeof callback === "function") callback({ error: validation.error }); return; }
    try {
      stmts.insertOrUpdateEvent.run(event.id, roomId, event.iv, event.data);
      stmts.updateRoomLastActive.run(roomId);
      socket.to(roomId).emit("event:sync", event);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      if (typeof callback === "function") callback({ error: "Database error" });
    }
  });

  socket.on("event:bulk_save", ({ roomId: targetRoom, events }, callback) => {
    if (targetRoom !== roomId) return;
    if (!events || !Array.isArray(events) || events.length > 1000) {
      if (typeof callback === "function") callback({ error: "Invalid data" });
      return;
    }
    for (const event of events) {
      const validation = validateEventInput(event);
      if (!validation.valid) {
        if (typeof callback === "function") callback({ error: `Batch validation failed: ${validation.error}` });
        return;
      }
    }
    try {
      insertManyEvents(roomId, events);
      stmts.updateRoomLastActive.run(roomId);
      socket.to(roomId).emit("event:bulk_sync", events);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      if (typeof callback === "function") callback({ error: "Bulk save failed" });
    }
  });

  socket.on("event:delete", ({ roomId: targetRoom, eventId }, callback) => {
    if (targetRoom !== roomId) return;
    if (!validateEventId(eventId)) {
      if (typeof callback === "function") callback({ error: "Invalid eventId" });
      return;
    }
    try {
      stmts.deleteEvent.run(eventId, roomId);
      socket.to(roomId).emit("event:remove", eventId);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      if (typeof callback === "function") callback({ error: "Delete failed" });
    }
  });

  socket.on("event:bulk_delete", ({ roomId: targetRoom, eventIds }, callback) => {
    if (targetRoom !== roomId) return;
    if (!eventIds || !Array.isArray(eventIds) || eventIds.length > 1000) { if (typeof callback === "function") callback({ error: "Invalid data" }); return; }
    for (const eventId of eventIds) {
      if (!validateEventId(eventId)) {
        if (typeof callback === "function") callback({ error: "Invalid eventId" });
        return;
      }
    }
    try {
      deleteManyEvents(roomId, eventIds);
      socket.to(roomId).emit("event:bulk_remove", eventIds);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      if (typeof callback === "function") callback({ error: "Bulk delete failed" });
    }
  });

  socket.on("meta:save", ({ roomId: targetRoom, meta }, callback) => {
    if (targetRoom !== roomId) return;
    if (!meta) return;
    const validation = validateMeta(meta);
    if (!validation.valid) { if (typeof callback === "function") callback({ error: "Invalid meta" }); return; }
    try {
      stmts.updateRoomMeta.run(JSON.stringify(meta), roomId);
      stmts.updateRoomLastActive.run(roomId);
      // Broadcast to OTHER clients only — sender already has the latest state
      socket.to(roomId).emit("meta:sync", meta);
      if (typeof callback === "function") callback({ success: true });
    } catch (e) {
      if (typeof callback === "function") callback({ error: "Meta save failed" });
    }
  });
});

const CLEANUP_INTERVAL = 60 * 66 * 1000;
const EXPIRY_TIME = '-10 hours';

setInterval(() => {
  const now = new Date().toISOString();
  console.log(`[${now}] Running maintenance...`);
  try {
    db.pragma('wal_checkpoint(TRUNCATE)');
    const result = stmts.deleteExpiredRooms.run(EXPIRY_TIME);
    if (result.changes > 0) console.log(`[Maintenance] Cleaned up ${result.changes} expired rooms.`);
    
    const sessionSeconds = Math.max(60, Math.floor(SESSION_TTL / 1000));
    const sessionResult = stmts.deleteExpiredSessions.run(`-${sessionSeconds} seconds`);
    if (sessionResult.changes > 0) console.log(`[Maintenance] Purged ${sessionResult.changes} expired sessions.`);
  } catch (e) {
    console.error("[Maintenance] Error during cleanup:", e);
  }
}, CLEANUP_INTERVAL);

const shutdown = () => {
  console.log('Shutting down gracefully...');
  server.close(() => {
    try { db.close(); } catch (e) {}
    process.exit(0);
  });
  setTimeout(() => { console.error('Forcing shutdown'); process.exit(1); }, 10000);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

server.listen(PORT, () => {
  const protocol = USE_HTTPS ? 'HTTPS' : 'HTTP';
  console.log(`Planner Server running on ${protocol} port ${PORT}`);
});
