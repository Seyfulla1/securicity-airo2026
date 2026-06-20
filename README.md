# VillageShield — Smart-Village IoT Security Monitoring Platform

A small but complete **zero-trust security stack** for a fictional smart village,
now upgraded with a **100 % free, locally-hosted AI risk-scoring engine** powered
by [Ollama](https://ollama.com/) and the `llama3.2:1b` open-source model.

Every command from an IoT device passes through a single security gateway that
checks *who* is talking, *what* they are allowed to do, and *what data* they are
sending — before anything reaches the real control plane. The gateway then asks a
local large language model to explain *why* the traffic looks safe or suspicious.
Every decision, including the AI's plain-English reasoning, streams live to a
Security Operations Center (SOC) dashboard.

This is a **defensive** project: a miniature WAF + SIEM + access-control system,
an AI SOC analyst, and a test harness that attacks **your own** local stack to
prove the defenses fire.

---

## What's inside

| Service | Tech | Role | Host port |
|---|---|---|---|
| **router** (`172.28.0.20`) | Python / Flask | Policy Enforcement Point: action-based access control, deep payload inspection, thread-safe quarantine, cumulative risk scoring, **local AI query with auto-fallback**. The only door devices may knock on. | `8080 → 5000` |
| **dashboard** (`172.28.0.10`) | Node.js / Express / Socket.io | SIEM event engine + live SOC UI. Ingests webhooks, keeps per-device inbound/outbound history including AI fields, broadcasts over WebSockets. | `3000 → 3000` |
| **core** (`172.28.0.30`) | Python / Flask | The protected backend ("crown jewels"). No security logic, **no host port** — only reachable through the router on the private bridge. | *(none)* |
| **ollama** (`172.28.0.40`) | Ollama / llama3.2:1b | **Local open-source AI engine.** Runs a 1-billion-parameter LLM inside Docker. The router queries it for a dynamic risk score (0-100) and a plain-English insight sentence per packet. **No internet required after the first pull. No API key. No cost.** | *(none — internal only)* |
| **mock_devices** | Python (stdlib only) | 4-phase attack/demo script that role-plays the village devices. | *(run on host)* |

All services sit on the private Docker bridge `village_net` (`172.28.0.0/24`).
`core` and `ollama` have no published host ports — they are unreachable from
your laptop and only accessible to the router inside the bridge.

---

## Quickstart

**Requirements:** Docker + Docker Compose, and Python 3 on the host (for the
demo script — it uses only the standard library).

```bash
# 1) Build and start the whole stack.
#
#    FIRST RUN: Ollama will download llama3.2:1b (~1.3 GB). This takes
#    2-5 minutes on a normal connection. Progress is visible in the logs.
#    The router will not start until the model is fully ready (health-gated).
#
#    SUBSEQUENT RUNS: the model is cached in a Docker volume and loads in ~10s.
docker compose up --build

# 2) Open the SOC dashboard and log in with the demo PIN.
#    URL:  http://localhost:3000
#    PIN:  1234

# 3) In a SECOND terminal, run the 4-phase demo against the router.
python3 mock_devices/attack_script.py
```

Watch the dashboard update live as the script runs. Click any device card to open
its modal and see the **AI Risk Analysis** panel — the local model's real-time
reasoning is displayed there in plain English, updated with every packet.

> Targeting a non-default host?
> `PROXY_URL=http://192.168.1.50:8080/command python3 mock_devices/attack_script.py`

---

## Architecture

```
                                 ┌──────────────────────────────────────────────────┐
                                 │                village_net (bridge)               │
                                 │                  172.28.0.0/24                    │
                                 │                                                   │
  IoT / mock devices             │  ┌─────────────────┐      ┌──────────────────┐   │
  (attack_script.py)             │  │  Security Router │      │  Core Utilities  │   │
        │                        │  │  (PEP) Flask     │      │  Flask           │   │
        │  HTTP POST             │  │  172.28.0.20     │─────▶│  172.28.0.30     │   │
        │  /command  ────────────┼─▶│  :5000           │      │  :6000           │   │
        │  host:8080             │  │                  │      │  (no host port)  │   │
        │                        │  │  1. ACM check    │      └──────────────────┘   │
        │                        │  │  2. Payload scan │                             │
        │                        │  │  3. Risk update  │      ┌──────────────────┐   │
        │                        │  │  4. AI query ────┼─────▶│  Ollama AI       │   │
        │                        │  │                  │◀─────│  llama3.2:1b     │   │
        │                        │  │  5. Emit event   │      │  172.28.0.40     │   │
        │                        │  │     + AI fields  │      │  :11434          │   │
        │                        │  └────────┬─────────┘      │  (no host port)  │   │
        │                        │           │ webhook         └──────────────────┘   │
        │                        │           │ POST /api/ingest                       │
        │                        │           ▼                                        │
        │                        │  ┌─────────────────┐                              │
        │                        │  │  SIEM Dashboard  │                              │
        │                        │  │  Node.js         │                              │
        │                        │  │  172.28.0.10     │                              │
        │                        │  │  :3000           │                              │
        │                        │  └────────┬─────────┘                              │
        │                        └───────────┼────────────────────────────────────────┘
        │                                    │ WebSocket (socket.io)
        ▼                                    ▼
  operator's browser  ◀──────  http://localhost:3000  (live SOC + AI insights)
```

**Flow:** a device sends a command to the router. The router runs the Access
Control Matrix check and payload inspection under a lock (fast, deterministic),
then releases the lock and queries the local Ollama AI engine for a contextual
risk score and insight sentence. If Ollama is unavailable the system falls back
to static ACM scoring silently — no crash, no 500 error. The enriched event
(including `ai_risk_score`, `ai_insight`, `scoring_source`) is POSTed to the
dashboard and broadcast via WebSockets to all connected browsers.

---

## The 4-phase demo

The script compromises one device — **`well_pump_01`** — and walks through four
phases to exercise each layer of defense:

1. **Nominal traffic** — all five devices send allowed commands. Everything is
   `ALLOWED`, forwarded to Core, and risk stays at `0`. The AI returns low scores
   with explanations like *"Normal pump operation within expected parameters."*
2. **Forbidden action** — `well_pump_01` tries `device_shutdown`. Blocked by the
   ACM (`ACM_VIOLATION`), risk climbs. The AI adds context like *"Pump attempting
   unauthorised shutdown action — high anomaly signal."*
3. **Malicious payload** — the attacker hides bad data (`pressure=999%`,
   `state=ERROR_OVERFLOW`) inside otherwise-allowed actions. Deep Payload
   Inspection flags it, blocks it, and auto-quarantines the device. AI score spikes.
4. **Isolation proof** — `well_pump_01` retries a normal command. Still refused
   (`DEVICE_ISOLATED`). The AI notes the quarantine context in its insight.

After the run, the pump's card shows an `ISOLATED` status with a pulsing red ring,
an AI score in the 80-100 range, and the AI's latest insight. Its modal shows the
purple **AI Risk Analysis** panel at the top with the model's plain-English reasoning,
and a comparison of inbound vs. outbound transaction counts that tells the whole story.

---

## AI engine details

| Property | Value |
|---|---|
| Runtime | [Ollama](https://ollama.com/) inside Docker |
| Model | `llama3.2:1b` (Meta Llama 3.2, 1 billion parameters, 4-bit quantized) |
| Disk size | ~1.3 GB (downloaded once, cached in Docker volume `villageshield_ollama_models`) |
| RAM required | ~2 GB for the model |
| Endpoint | `http://172.28.0.40:11434/api/chat` (internal only) |
| API format | Ollama `/api/chat` with `format: "json"` constrained decoding |
| Timeout | 8 seconds — automatic fallback to static ACM scoring on timeout |
| Internet | Required on first run for model download only. Zero dependency after. |

**To switch models** (e.g., for better reasoning quality at the cost of more RAM):

```bash
# In docker-compose.yml, change both OLLAMA_MODEL lines:
#   - OLLAMA_MODEL=phi3:mini       # 3.8B params, ~2.3 GB, better reasoning
#   - OLLAMA_MODEL=llama3.2:3b     # 3B params, ~2.0 GB, good balance
#   - OLLAMA_MODEL=llama3.1:8b     # 8B params, ~4.7 GB, near GPT-3.5 quality

# Wipe the old model volume and rebuild:
docker compose down
docker volume rm villageshield_ollama_models
docker compose up --build
```

---

## Project layout

```
villageshield/
├── docker-compose.yml          # private bridge network + 4 services, static IPs
├── .gitignore
├── README.md
├── ollama/                     # Local AI engine startup
│   └── entrypoint.sh           # Starts ollama serve, waits for ready, pulls model
├── router/                     # Security Router / Policy Enforcement Point
│   ├── Dockerfile
│   ├── requirements.txt
│   └── router.py               # ACM + payload inspection + Ollama AI query
├── core/                       # Protected backend (no security logic, no host port)
│   ├── Dockerfile
│   ├── requirements.txt
│   └── core.py
├── dashboard/                  # SIEM engine + real-time SOC dashboard
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js               # Webhook ingest + Socket.io broadcast (AI-aware)
│   └── public/
│       └── index.html          # Tailwind SOC UI: PIN gate + device cards + AI panel
└── mock_devices/
    └── attack_script.py        # 4-phase demo (standard library only)
```

---

## Notes & future development

- **Two scoring systems:** the cumulative ACM risk score (`router.py` `RISK` dict)
  grows over time as a device commits violations and drives quarantine. The AI's
  `ai_risk_score` is a fresh per-packet contextual assessment. Both are visible in
  the dashboard — the card gauge shows the cumulative score; the modal AI panel
  shows the dynamic score.
- **Graceful AI fallback:** if Ollama is still loading, times out (>8 s), or returns
  unparseable output, the router automatically uses static ACM-based scores. The
  dashboard shows a yellow `STATIC` badge instead of the purple `AI LIVE` badge.
- **Risk model constants** (in `router/router.py`): forbidden action `+45`,
  malicious payload `+50` (plus instant quarantine), each isolated retry `+5`.
  Quarantine triggers at score `≥ 70`. Adjust at the top of the file.
- **Single Flask process, many threads** (`threaded=True`): the in-memory
  quarantine list is shared across threads and guarded by `threading.Lock()`.
  Running multiple worker *processes* would give each its own copy and silently
  break isolation — deliberately avoided.
- **No database:** all state is in memory and resets when containers restart.
  Swap in Redis/Postgres for anything persistent.
- **Demo PIN `1234`** is hard-coded for the jury and is **not** real authentication.
