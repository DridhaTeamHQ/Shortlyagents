const crypto = require("crypto");
const path = require("path");

const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");

dotenv.config();

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 4173);
const mongoUri = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017";
const mongoDbName = process.env.MONGODB_DB || "shortly_agents";
const adminUsername = process.env.ADMIN_USERNAME || "Shortly";
const adminPassword = process.env.ADMIN_PASSWORD || "Shortly@4321";
const sessionCookieName = process.env.SESSION_COOKIE || "shortly_admin_session";
const sessionLifetimeMs = 1000 * 60 * 60 * 12;
const sessionSecret =
  process.env.SESSION_SECRET ||
  process.env.ADMIN_PASSWORD ||
  "shortly-local-session-secret";
const agentAccessSecret =
  process.env.AGENT_ACCESS_SECRET ||
  process.env.SESSION_SECRET ||
  process.env.ADMIN_PASSWORD ||
  "shortly-local-agent-access-secret";
const agentAuthOrigins = new Set(
  (process.env.AGENT_AUTH_ORIGINS ||
    "https://pix-agent.vercel.app,https://shortly-email-agent.vercel.app,https://shortly-ai-emailer.vercel.app")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

const baseDir = __dirname;

const launchCards = [
  {
    id: "pix-agent",
    name: "Pix Agent",
    href: "https://pix-agent.vercel.app/",
    live: true
  },
  {
    id: "shortly-ai-agent",
    name: "Shortly AI Agent",
    href: "https://aishortlywebupdate-i1yc.vercel.app/login",
    live: true
  },
  {
    id: "daily-digest-agent",
    name: "Daily Wrap Email Agent",
    href: "https://shortly-email-agent.vercel.app/dashboard",
    live: true
  }
];

const starterLogins = [
  {
    agentId: "pix-agent",
    displayName: "Pix Editor",
    username: "pix.editor",
    password: "Pix@1234",
    email: "pix.editor@shortly.ai"
  },
  {
    agentId: "shortly-ai-agent",
    displayName: "Shortly Operator",
    username: "shortly.operator",
    password: "ShortlyAI@123",
    email: "operator@shortly.ai"
  },
  {
    agentId: "daily-digest-agent",
    displayName: "Daily Wrap Operator",
    username: "daily.wrap",
    password: "Digest@1234",
    email: "daily.wrap@shortly.ai"
  }
];

const starterAdmin = {
  username: adminUsername,
  password: adminPassword
};

let dbContextPromise;

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derivedKey}`;
}

function verifyPassword(password, storedHash) {
  const [salt, key] = String(storedHash || "").split(":");
  if (!salt || !key) {
    return false;
  }

  const derivedKey = crypto.scryptSync(password, salt, 64);
  const storedKey = Buffer.from(key, "hex");
  return (
    storedKey.length === derivedKey.length &&
    crypto.timingSafeEqual(storedKey, derivedKey)
  );
}

function normalizeLogin(document) {
  return {
    id: String(document._id),
    agentId: document.agentId,
    displayName: document.displayName,
    username: document.username,
    email: document.email
  };
}

function encodeSessionPayload(payload) {
  return Buffer.from(JSON.stringify(payload)).toString("base64url");
}

function signSessionPayload(encodedPayload) {
  return crypto
    .createHmac("sha256", sessionSecret)
    .update(encodedPayload)
    .digest("base64url");
}

function createSessionToken() {
  const payload = encodeSessionPayload({
    role: "admin",
    expiresAt: Date.now() + sessionLifetimeMs
  });
  return `${payload}.${signSessionPayload(payload)}`;
}

function createAgentAccessToken(login) {
  const payload = encodeSessionPayload({
    type: "agent-access",
    agentId: login.agentId,
    loginId: String(login._id),
    displayName: login.displayName,
    username: login.username,
    email: login.email,
    expiresAt: Date.now() + sessionLifetimeMs
  });
  const signature = crypto
    .createHmac("sha256", agentAccessSecret)
    .update(payload)
    .digest("base64url");
  return `${payload}.${signature}`;
}

function readSessionToken(token) {
  const [encodedPayload, signature] = String(token || "").split(".");
  if (!encodedPayload || !signature) {
    return null;
  }

  const expectedSignature = signSessionPayload(encodedPayload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
  } catch (error) {
    return null;
  }
}

function createSession(res) {
  const token = createSessionToken();

  res.cookie(sessionCookieName, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: sessionLifetimeMs
  });
}

function clearSession(res) {
  res.clearCookie(sessionCookieName, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/"
  });
}

function isAdminAuthenticated(req) {
  const token = req.cookies[sessionCookieName];
  if (!token) {
    return false;
  }

  const session = readSessionToken(token);
  if (!session || session.role !== "admin") {
    return false;
  }

  if (session.expiresAt < Date.now()) {
    return false;
  }

  return true;
}

function requireAdmin(req, res, next) {
  if (!isAdminAuthenticated(req)) {
    res.status(401).json({ error: "Admin authentication required." });
    return;
  }

  next();
}

function allowAgentAuthCors(req, res, next) {
  const origin = req.headers.origin;
  if (origin && agentAuthOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  next();
}

async function seedLoginsIfNeeded(collection) {
  const count = await collection.countDocuments();
  if (count > 0) {
    return;
  }

  const seedDocuments = starterLogins.map((login) => ({
    agentId: login.agentId,
    displayName: login.displayName,
    username: login.username,
    email: login.email,
    passwordHash: createPasswordHash(login.password),
    createdAt: new Date(),
    updatedAt: new Date()
  }));

  await collection.insertMany(seedDocuments);
}

async function seedAdminIfNeeded(collection) {
  await collection.updateOne(
    { username: starterAdmin.username },
    {
      $set: {
        passwordHash: createPasswordHash(starterAdmin.password),
        updatedAt: new Date()
      },
      $setOnInsert: {
        createdAt: new Date()
      }
    },
    { upsert: true }
  );
}

async function getDbContext() {
  if (!dbContextPromise) {
    dbContextPromise = (async () => {
      const client = new MongoClient(mongoUri);
      await client.connect();

      const db = client.db(mongoDbName);
      const loginsCollection = db.collection("agent_logins");
      const adminsCollection = db.collection("admin_users");

      await loginsCollection.createIndex({ agentId: 1, username: 1 }, { unique: true });
      await adminsCollection.createIndex({ username: 1 }, { unique: true });
      await seedLoginsIfNeeded(loginsCollection);
      await seedAdminIfNeeded(adminsCollection);

      return { client, db, loginsCollection, adminsCollection };
    })().catch((error) => {
      dbContextPromise = null;
      throw error;
    });
  }

  return dbContextPromise;
}

function createApp() {
  const app = express();

  app.use(express.json());
  app.use(cookieParser());
  app.use("/api/agent-login", allowAgentAuthCors);
  app.use(express.static(baseDir));

  app.get("/api/session", (req, res) => {
    res.json({ adminAuthenticated: isAdminAuthenticated(req) });
  });

  app.post("/api/admin/login", async (req, res) => {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    const { adminsCollection } = await getDbContext();
    const adminUser = await adminsCollection.findOne({ username });

    if (!adminUser || !verifyPassword(password, adminUser.passwordHash)) {
      res.status(401).json({ error: "Invalid admin username or password." });
      return;
    }

    createSession(res);
    res.json({ ok: true });
  });

  app.post("/api/admin/logout", (req, res) => {
    clearSession(res);
    res.json({ ok: true });
  });

  app.get("/api/admin/logins", requireAdmin, async (req, res) => {
    const { loginsCollection } = await getDbContext();
    const documents = await loginsCollection
      .find({}, { sort: { agentId: 1, username: 1 } })
      .toArray();

    res.json({ logins: documents.map(normalizeLogin) });
  });

  app.post("/api/admin/logins", requireAdmin, async (req, res) => {
    const { loginsCollection } = await getDbContext();
    const payload = {
      agentId: String(req.body?.agentId || "").trim(),
      displayName: String(req.body?.displayName || "").trim(),
      username: String(req.body?.username || "").trim(),
      password: String(req.body?.password || ""),
      email: String(req.body?.email || "").trim().toLowerCase()
    };

    if (!payload.agentId || !payload.displayName || !payload.username || !payload.password || !payload.email) {
      res.status(400).json({ error: "All login fields are required." });
      return;
    }

    if (!launchCards.find((card) => card.id === payload.agentId)) {
      res.status(400).json({ error: "Unknown agent id." });
      return;
    }

    try {
      const result = await loginsCollection.insertOne({
        agentId: payload.agentId,
        displayName: payload.displayName,
        username: payload.username,
        email: payload.email,
        passwordHash: createPasswordHash(payload.password),
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const inserted = await loginsCollection.findOne({ _id: result.insertedId });
      res.status(201).json({ login: normalizeLogin(inserted) });
    } catch (error) {
      if (error && error.code === 11000) {
        res.status(409).json({ error: "That username already exists for this agent." });
        return;
      }

      res.status(500).json({ error: "Unable to save login." });
    }
  });

  app.delete("/api/admin/logins/:id", requireAdmin, async (req, res) => {
    const { loginsCollection } = await getDbContext();
    let loginId;

    try {
      loginId = new ObjectId(req.params.id);
    } catch (error) {
      res.status(400).json({ error: "Invalid login id." });
      return;
    }

    const result = await loginsCollection.deleteOne({ _id: loginId });
    if (!result.deletedCount) {
      res.status(404).json({ error: "Login not found." });
      return;
    }

    res.json({ ok: true });
  });

  app.post("/api/agent-login", async (req, res) => {
    const { loginsCollection } = await getDbContext();
    const agentId = String(req.body?.agentId || "").trim();
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "").trim();

    if (!agentId || !username || !password) {
      res.status(400).json({ error: "Agent id, username, and password are required." });
      return;
    }

    const login = await loginsCollection.findOne({
      agentId,
      $or: [
        { username },
        { displayName: username },
        { email: username.toLowerCase() }
      ]
    });
    if (!login || !verifyPassword(password, login.passwordHash)) {
      res.status(401).json({ error: "Invalid login for this agent." });
      return;
    }

    res.json({
      login: normalizeLogin(login),
      accessToken: createAgentAccessToken(login)
    });
  });

  app.get("*", (req, res) => {
    res.sendFile(path.join(baseDir, "index.html"));
  });

  return app;
}

const app = createApp();

module.exports = {
  app,
  host,
  port,
  getDbContext
};
