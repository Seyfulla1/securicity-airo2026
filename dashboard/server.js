/*
 * SecuriVillage - SIEM Event Engine + Real-Time Dashboard Server
 * ==============================================================
 *
 * This Node.js service plays two roles:
 *
 *   1. SIEM ingest  -  It exposes POST /api/ingest, the "webhook" the Flask
 *      security router fires for every packet. Each event is folded into an
 *      in-memory model of the 5 village devices: their live status, traffic
 *      counts, risk score, and a rolling history of transactions split into
 *      INBOUND (what Core Utilities received) and OUTBOUND (what the device
 *      attempted).
 *
 *   2. Live dashboard  -  It serves the operator UI from /public and pushes
 *      every state change to connected browsers instantly over WebSockets
 *      (socket.io). No polling, no refresh - the SOC panel updates the moment
 *      the router makes a decision.
 *
 * NEW IN THIS VERSION: AI Enrichment Fields
 * ==========================================
 * The router now sends three additional fields with every event:
 *   - ai_risk_score:  The local Ollama AI's per-packet risk score (0-100).
 *   - ai_insight:     A human-readable sentence explaining the AI's reasoning.
 *   - scoring_source: "ollama_ai" or "static_acm" (tells the UI which badge
 *                     to display — live AI or static fallback).
 *
 * These are stored on both the device state (latest values) and inside each
 * transaction record (per-event history), so the modal can show the AI's
 * reasoning for every individual packet that ever passed through the router.
 */

const path = require("path");
const http = require("http");
const express = require("express");
const cors = require("cors");
const { Server } = require("socket.io");

const PORT    = parseInt(process.env.PORT || "3000", 10);
const MAX_LOG = 100; // keep the most recent N transactions per direction, per device

// --------------------------------------------------------------------------- //
// In-memory "database"                                                         //
// --------------------------------------------------------------------------- //
// The 5 known devices are pre-seeded so every card is visible immediately, even
// before any traffic arrives.
const DEVICE_SEED = [
  { id: "agri_soil_01",      label: "Soil Moisture Sensor", icon: "🌱", zone: "North Field" },
  { id: "env_weather_01",    label: "Weather Station",      icon: "🌦️", zone: "Village Square" },
  { id: "cctv_gate_01",      label: "Gate CCTV Camera",     icon: "📹", zone: "Main Gate" },
  { id: "well_pump_01",      label: "Well Water Pump",      icon: "💧", zone: "Water House" },
  { id: "solar_inverter_01", label: "Solar Inverter",       icon: "☀️", zone: "Power Shed" },
];

function freshDevice(seed) {
  return {
    id:   seed.id,
    label: seed.label,
    icon:  seed.icon,
    zone:  seed.zone,

    // Security state (updated from router events)
    status:       "NOMINAL",
    risk:         0,           // Cumulative ACM-based risk score
    inboundCount:  0,
    outboundCount: 0,
    blockedCount:  0,
    lastSeen:      null,

    // NEW: Latest AI analysis fields.
    // These hold the MOST RECENT AI result for this device.
    // The dashboard shows these on the device card and at the top of the modal.
    aiRiskScore:   null,   // The AI's score for the last packet (0-100 or null if not yet seen)
    aiInsight:     "Awaiting first AI analysis…", // The AI's latest reasoning sentence
    scoringSource: "none", // "ollama_ai", "static_acm", or "none" (before first event)

    // Transaction history (rolling buffer, newest entries pushed, oldest shifted out)
    inbound:  [],  // transactions Core Utilities received (ALLOWED + DELIVERED)
    outbound: [],  // transactions the device attempted (all packets)
  };
}

const devices = {};
DEVICE_SEED.forEach((seed) => { devices[seed.id] = freshDevice(seed); });

const globals = {
  totalEvents: 0,
  allowed:     0,
  blocked:     0,
  isolated:    0,
  startedAt:   new Date().toISOString(),
};

// A short global feed of the most recent events (for the live console panel).
const liveFeed  = [];
const MAX_FEED  = 60;

// --------------------------------------------------------------------------- //
// Express + socket.io setup                                                    //
// --------------------------------------------------------------------------- //
const app = express();
app.use(cors());
app.use(express.json({ limit: "256kb" }));
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

function snapshot() {
  // Returns a serializable snapshot of all current state.
  // This is sent to browsers on connect and after every mutation.
  return { devices: Object.values(devices), globals };
}

// --------------------------------------------------------------------------- //
// The webhook the router POSTs to for every packet                             //
// --------------------------------------------------------------------------- //
app.post("/api/ingest", (req, res) => {
  const e  = req.body || {};
  const id = e.device_id || "unknown";

  // Auto-create a card for any device we haven't seen before (e.g. a rogue,
  // unknown device the router rejected).
  if (!devices[id]) {
    devices[id] = freshDevice({
      id,
      label: e.device_label || "Unknown Device",
      icon:  "❓",
      zone:  "Unregistered",
    });
  }
  const d = devices[id];

  // --------------------------------------------------------------------- //
  // Build the transaction row we store in the device's history.
  //
  // NEW: We now capture three AI fields from the event:
  //   - aiRiskScore:   The Ollama AI's dynamic score for this specific packet.
  //   - aiInsight:     The AI's one-sentence reasoning. This is the text that
  //                    will appear in the device modal next to this transaction.
  //   - scoringSource: Tells the UI whether to show "AI LIVE" or "STATIC" badge.
  //
  // We store these on the transaction object so operators can scroll back
  // through history and see the AI's reasoning for every past packet.
  // --------------------------------------------------------------------- //
  const tx = {
    ts:            e.ts || new Date().toISOString(),
    direction:     e.direction  || "outbound",
    action:        e.action     || "",
    payload:       e.payload    || "",
    headers:       e.headers    || {},
    decision:      e.decision   || "",
    reason:        e.reason     || "",
    anomalies:     e.anomalies  || [],
    sourceIp:      e.source_ip  || "",
    risk:          typeof e.risk_score === "number" ? e.risk_score : d.risk,
    aiRiskScore:   typeof e.ai_risk_score === "number" ? e.ai_risk_score : null,
    aiInsight:     e.ai_insight    || null,
    scoringSource: e.scoring_source || "static_acm",
  };

  // File the transaction into the correct table and update counts.
  if (e.direction === "inbound") {
    d.inbound.push(tx);
    if (d.inbound.length > MAX_LOG) d.inbound.shift();
    d.inboundCount += 1;
  } else {
    d.outbound.push(tx);
    if (d.outbound.length > MAX_LOG) d.outbound.shift();
    d.outboundCount += 1;
    if (e.decision !== "ALLOWED") d.blockedCount += 1;
  }

  // The router is the source of truth for risk/status; mirror it here.
  if (typeof e.risk_score === "number") d.risk   = e.risk_score;
  if (e.status)                         d.status = e.status;
  d.lastSeen = tx.ts;

  // NEW: Update the device's "latest AI analysis" fields.
  // We update on ALL events (both inbound and outbound) so the device card
  // always shows the most recent AI insight, regardless of direction.
  // Only overwrite if the new event actually has AI data (not null/empty).
  if (typeof e.ai_risk_score === "number") {
    d.aiRiskScore = e.ai_risk_score;
  }
  if (e.ai_insight && e.ai_insight.trim()) {
    // SECURITY: We do NOT sanitize here — that is the browser's responsibility.
    // The HTML template uses textContent (not innerHTML) for all AI text, so
    // even if the AI or the router somehow produced HTML/JS in the insight string,
    // it would be rendered as literal text, not executed. XSS-safe by design.
    d.aiInsight = e.ai_insight;
  }
  if (e.scoring_source) {
    d.scoringSource = e.scoring_source;
  }

  // Update global counters (count each ATTEMPTED packet once = outbound events).
  if (e.direction !== "inbound") {
    globals.totalEvents += 1;
    if (e.decision === "ALLOWED")   globals.allowed  += 1;
    else if (e.decision === "ISOLATED") globals.isolated += 1;
    else                            globals.blocked  += 1;
  }

  // Push to the live feed (newest first).
  // The live feed shows all events in a scrolling console-style panel.
  // We include AI fields here too so the feed rows can show the AI score inline.
  const feedItem = {
    ...tx,
    deviceId:  id,
    label:     d.label,
    direction: e.direction || "outbound",
  };
  liveFeed.unshift(feedItem);
  if (liveFeed.length > MAX_FEED) liveFeed.pop();

  // Broadcast the new state + the single event to every connected operator.
  // `state`: the full snapshot, used by the device cards and global counters.
  // `event`: the single new transaction, used to prepend to the live feed.
  io.emit("state", snapshot());
  io.emit("event", feedItem);

  // Log a concise line so `docker compose logs dashboard` is easy to read.
  const aiLabel = e.ai_insight
    ? `AI[${e.scoring_source === "ollama_ai" ? "LIVE" : "STATIC"}]="${e.ai_insight.substring(0, 40)}..."`
    : "AI[none]";
  console.log(
    `[INGEST] ${id} | ${e.direction || "OUT"} | ${e.decision || "?"} | ` +
    `risk=${e.risk_score ?? "?"} | ai=${e.ai_risk_score ?? "?"} | ${aiLabel}`
  );

  res.json({ ok: true });
});

// REST endpoints (handy for debugging or serving history on demand).
app.get("/api/state",       (_req, res) => res.json(snapshot()));
app.get("/api/feed",        (_req, res) => res.json(liveFeed));
app.get("/api/device/:id",  (req, res) => {
  const d = devices[req.params.id];
  if (!d) return res.status(404).json({ error: "unknown device" });
  res.json(d);
});

// --------------------------------------------------------------------------- //
// WebSocket lifecycle                                                          //
// --------------------------------------------------------------------------- //
io.on("connection", (socket) => {
  console.log(`[SOCKET] operator connected: ${socket.id}`);
  // Send the full current picture the instant a dashboard connects.
  // This means the UI is fully populated on first load, not blank.
  socket.emit("state", snapshot());
  socket.emit("feed",  liveFeed);
  socket.on("disconnect", () => console.log(`[SOCKET] operator left: ${socket.id}`));
});

server.listen(PORT, () => {
  console.log(`[BOOT] SecuriVillage SIEM dashboard on http://0.0.0.0:${PORT}`);
});
