# SecuriVillage

**Team:** Securicity
**Task:** 2 — Smart Village IoT Security Monitoring

---

## The Problem

Smart villages connect critical infrastructure — water pumps, solar inverters, CCTV cameras, agricultural sensors — to a shared network so they can be managed remotely. This convenience creates a serious attack surface. Any single compromised device can be used to send forged commands to the control plane: shut down the water supply, disable alarms, or exfiltrate operational data.

Existing off-the-shelf security products assume enterprise budgets, cloud connectivity, and skilled IT staff. Rural smart-village deployments have none of these. A water pump controller in a remote village needs security that:

- Works with **zero internet dependency** after initial setup
- Runs on **cheap, low-power hardware** (no GPU, no cloud VM)
- Is **explainable** — a non-technical operator must understand why a device was blocked
- Cannot be silently bypassed if the AI component goes offline

---

## The Solution

SecuriVillage is a **zero-trust IoT security stack** for smart villages. Every command from every IoT device passes through a single security gateway before it can touch the real control plane. The gateway makes a deterministic rule-based decision first, then asks a locally-running open-source language model to explain the decision in plain English. Every outcome — allowed, blocked, or quarantined — streams live to a Security Operations Center (SOC) dashboard in the operator's browser.

The system has **two independent layers of defence** that complement each other:

| Layer | Technology | Purpose |
|---|---|---|
| **Action-Based Access Control Matrix (ACM)** | Deterministic rule engine (Python) | Hard allow-list per device — a weather station can never shut down the water pump, no matter what |
| **Local AI Risk Engine** | Ollama + llama3.2:1b (offline LLM) | Per-packet risk score (0–100) and a plain-English reason that a human operator can read and act on |

If the AI goes offline, the ACM layer continues to enforce security silently. The dashboard shows a `STATIC` badge instead of `AI LIVE` so the operator knows the AI is unavailable — but protection never drops.

---

## Main Features

- **Zero-trust policy enforcement** — every device has an explicit allow-list of actions. Anything not on the list is blocked by default, regardless of AI state.
- **Deep Payload Inspection (DPI)** — static regex rules catch SQL/shell injection patterns, overflow values, error tokens, and oversized payloads before they reach the backend.
- **Automatic device quarantine** — cumulative risk score accumulates per device across packets. Once a device crosses the isolation threshold it is blacklisted for the session; even legitimate requests from that device are refused.
- **Local AI risk scoring** — a 1-billion-parameter LLM (llama3.2:1b via Ollama) runs entirely inside Docker. It reads the device context, action, payload, and ACM verdict, then returns a per-packet risk score and a one-sentence explanation. No API key. No internet after setup. No cost per query.
- **Graceful AI fallback** — if the AI times out or fails, the router falls back to static scoring transparently. Security is never interrupted.
- **Live SOC dashboard** — a PIN-gated, real-time web UI showing device cards with status, cumulative risk gauges, an AI insight preview, a global live event feed, and per-device modals with inbound/outbound transaction history. Every row is expandable to show raw headers, payload, and the AI's per-packet reasoning.
- **Two-score system** — the card gauge shows the *cumulative* ACM risk (how dangerous a device has been *over time*); the modal AI panel shows the *per-packet* AI score (how dangerous *this specific request* looks). Both are always visible and labelled.
- **Network isolation** — Core Utilities (the protected backend) and the AI engine have no published host ports. They are only reachable from inside the private Docker bridge, so an attacker on the host network cannot query them directly.

---

## Tech Stack

| Component | Technology |
|---|---|
| Security router / PEP | Python 3, Flask, `threading.Lock` |
| SIEM event engine | Node.js, Express, Socket.io |
| SOC dashboard UI | Vanilla HTML/JS, Tailwind CSS (Play CDN), Socket.io client |
| AI engine | [Ollama](https://ollama.com/) (`llama3.2:1b`, 1B params, 4-bit quantized) |
| Protected backend | Python 3, Flask |
| Container orchestration | Docker, Docker Compose (bridge network with static IPs) |
| Demo / attack harness | Python 3 (standard library only — no pip install needed) |

---

## How to Run

### Prerequisites

Install these before anything else:

| Tool | Version | Install |
|---|---|---|
| **Docker Desktop** (Mac/Windows) or **Docker Engine + Docker Compose plugin** (Linux) | Docker ≥ 24, Compose ≥ 2.20 | https://docs.docker.com/get-docker/ |
| **Python 3** | 3.9 or later | https://www.python.org/downloads/ — the demo script uses only the standard library, no pip needed |

Check your versions:

```bash
docker --version          # Docker version 24.x.x
docker compose version    # Docker Compose version v2.x.x
python3 --version         # Python 3.x.x
```

### First-time setup note

On first run, Ollama will download the `llama3.2:1b` model (~1.3 GB). This takes **2–5 minutes** on a normal connection. The router waits for the model to be fully loaded before it accepts any traffic — you will see the router container stay in a "waiting" state until then. Every subsequent run loads the cached model from disk in about 10 seconds.

### Step 1 — Start the stack

```bash
git clone <repo-url>
cd securivillage

docker compose up --build
```

Leave this terminal open. You will see log lines from all four services. Wait until you see:

```
sv_router  | [BOOT] SecuriVillage router listening on :5000
```

That means the model is loaded and the router is ready.

### Step 2 — Open the dashboard

Open your browser and go to:

```
http://localhost:3000
```

Enter the demo PIN when prompted (see Demo Login below). You will see five device cards appear immediately, all in `NOMINAL` state.

### Step 3 — Run the demo attack

In a **second terminal**, from the project root:

```bash
python3 mock_devices/attack_script.py
```

Watch the dashboard update live as the script runs through all 5 phases. Each send is colour-coded in the terminal and reflected in real time on the SOC dashboard.

**Targeting a different host** (e.g. if the stack is running on a remote machine):

```bash
PROXY_URL=http://192.168.1.50:8080/command python3 mock_devices/attack_script.py
```

### Stopping the stack

```bash
# Stop containers but keep the model cache (fastest next restart):
docker compose down

# Stop and wipe EVERYTHING including the downloaded model:
docker compose down -v
```

### Switching to a more capable model

Edit `docker-compose.yml` — change both `OLLAMA_MODEL` lines — then wipe the model volume and rebuild:

```bash
docker compose down
docker volume rm securivillage_ollama_models   # or securivillage_ollama_models
docker compose up --build
```

Suggested alternatives:

| Model | Size | RAM needed | Quality |
|---|---|---|---|
| `llama3.2:1b` (default) | 1.3 GB | ~2 GB | Fast, basic reasoning |
| `llama3.2:3b` | 2.0 GB | ~3 GB | Good balance |
| `phi3:mini` | 2.3 GB | ~3 GB | Strong instruction following |
| `llama3.1:8b` | 4.7 GB | ~6 GB | Near GPT-3.5 quality |

---

## Demo Login

| Field | Value |
|---|---|
| URL | `http://localhost:3000` |
| PIN | `1234` |

The PIN is a simple demo gate for the jury — it is not real authentication. A refresh re-prompts for the PIN; no session is stored between visits.

---

## Example Data — The Attack Script

`mock_devices/attack_script.py` simulates a realistic multi-device attack escalation across five phases. Run it with `python3 mock_devices/attack_script.py`.

### Phase 1 — Nominal traffic (all 5 devices)

All devices send their permitted routine commands. Everything is `ALLOWED`, forwarded to Core Utilities, and risk stays flat. The AI returns low scores (0–10).

```
agri_soil_01         read_telemetry       → ALLOWED    cumulative=  1   AI ≈  3
env_weather_01       read_telemetry       → ALLOWED    cumulative=  1   AI ≈  3
cctv_gate_01         capture_snapshot     → ALLOWED    cumulative=  1   AI ≈  3
well_pump_01         read_telemetry       → ALLOWED    cumulative=  1   AI ≈  3
solar_inverter_01    read_telemetry       → ALLOWED    cumulative=  1   AI ≈  3
```

### Phase 2 — well_pump_01 forbidden actions (ACM violations)

The compromised pump tries three actions not in its allow-list. Cumulative risk climbs with each violation as the device threat level escalates from CLEAN → ELEVATED → HIGH-RISK:

```
well_pump_01    device_shutdown    → BLOCKED    cumulative= 27   AI ≈ 52
well_pump_01    set_config         → BLOCKED    cumulative= 44   AI ≈ 58
well_pump_01    exec_command       → BLOCKED    cumulative= 61   AI ≈ 65
```

### Phase 3 — cctv_gate_01 unauthorized control attempts

A second independent device is compromised. Its risk counter is separate from the pump's — it starts fresh:

```
cctv_gate_01    unlock_gate        → BLOCKED    cumulative= 16   AI ≈ 47
cctv_gate_01    disable_alarm      → BLOCKED    cumulative= 33   AI ≈ 55
```

### Phase 4 — Payload injection (immediate blacklist)

The attacker sends `pressure=999%,flow=ERROR_OVERFLOW`. Deep Payload Inspection detects `overflow_percentage` and `error_token` before the AI even runs. The router immediately sets cumulative risk to 100 and blacklists the device:

```
well_pump_01    read_telemetry     → BLOCKED    cumulative=100   AI ≈ 95
                                      anomalies: overflow_percentage, error_token
```

### Phase 5 — Isolation proof

The quarantined pump tries clean telemetry three times. All refused — the security decision is final:

```
well_pump_01    read_telemetry     → ISOLATED   cumulative=100   AI ≈ 95
well_pump_01    read_telemetry     → ISOLATED   cumulative=100   AI ≈ 95
well_pump_01    read_telemetry     → ISOLATED   cumulative=100   AI ≈ 95
```

After the script completes, click `well_pump_01` in the dashboard to see its full transaction history, the AI's per-packet reasoning for each row, and the pulsing red ISOLATED ring on the card.

---

## Architecture

```
                                 ┌─────────────────────────────────────────────────┐
                                 │             village_net (Docker bridge)          │
                                 │               172.28.0.0/24                     │
                                 │                                                  │
  IoT devices /                  │  ┌──────────────────┐    ┌──────────────────┐   │
  mock_devices/                  │  │  Security Router  │    │  Core Utilities  │   │
  attack_script.py               │  │  (PEP) Flask      │───▶│  Flask           │   │
        │                        │  │  172.28.0.20:5000 │    │  172.28.0.30:6000│   │
        │  HTTP POST /command ───┼─▶│                   │    │  (no host port)  │   │
        │  host port :8080       │  │  1. ACM check     │    └──────────────────┘   │
        │                        │  │  2. Payload DPI   │                           │
        │                        │  │  3. Risk update   │    ┌──────────────────┐   │
        │                        │  │  4. AI query  ────┼───▶│  Ollama AI       │   │
        │                        │  │              ◀────┼────│  llama3.2:1b     │   │
        │                        │  │  5. Emit event    │    │  172.28.0.40     │   │
        │                        │  │     + AI fields   │    │  (no host port)  │   │
        │                        │  └────────┬──────────┘    └──────────────────┘   │
        │                        │           │ POST /api/ingest (webhook)            │
        │                        │           ▼                                       │
        │                        │  ┌──────────────────┐                            │
        │                        │  │  SIEM Dashboard   │                            │
        │                        │  │  Node.js + WS     │                            │
        │                        │  │  172.28.0.10:3000 │                            │
        │                        │  └────────┬──────────┘                            │
        │                        └───────────┼───────────────────────────────────────┘
        │                                    │ WebSocket (Socket.io)
        ▼                                    ▼
  operator browser  ◀────────  http://localhost:3000  (live SOC + AI insights)
```

### Service summary

| Service | IP | Host port | Role |
|---|---|---|---|
| **dashboard** | 172.28.0.10 | 3000 | SIEM event ingest + WebSocket broadcast + SOC UI |
| **router** | 172.28.0.20 | 8080 → 5000 | Policy Enforcement Point: ACM, DPI, quarantine, AI query |
| **core** | 172.28.0.30 | *(none)* | Protected backend — only reachable via router inside bridge |
| **ollama** | 172.28.0.40 | *(none)* | Local LLM server — only reachable by router inside bridge |

---

## Project Layout

```
securivillage/
├── docker-compose.yml              # Private bridge network + 4 services with static IPs
├── README.md
├── ollama/
│   └── entrypoint.sh               # Starts ollama serve, waits for ready, pulls model
├── router/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── router.py                   # ACM + DPI + quarantine + Ollama AI query
├── core/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── core.py                     # Protected backend (no security logic)
├── dashboard/
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js                   # Webhook ingest + Socket.io broadcast
│   └── public/
│       └── index.html              # PIN gate + device cards + AI panel (Tailwind)
└── mock_devices/
    └── attack_script.py            # 5-phase graduated attack demo (stdlib only)
```

---

## Limitations

- **In-memory state only** — all device risk scores, quarantine lists, and transaction history live in RAM. A container restart resets everything. There is no database; persistent storage would require Redis or a SQL backend.
- **Session quarantine, not persistent** — a blacklisted device is unblocked on restart. In a real deployment, quarantine decisions would need to survive reboots and be reviewed by a human before lifting.
- **Demo PIN is not real authentication** — `1234` is hard-coded for the jury. A production SOC dashboard needs proper authentication (OAuth, LDAP, MFA).
- **Single-process router** — the Flask router runs with `threaded=True` (one process, many threads). Scaling to multiple worker processes would give each its own copy of the in-memory quarantine list and silently break isolation. Horizontal scaling would require moving state to a shared store (Redis, etcd).
- **1B model quality** — `llama3.2:1b` follows instructions well for structured JSON output but at `temperature: 0.3` it can occasionally produce generic or repetitive insights for very similar inputs. Larger models (3B+) produce significantly better per-event reasoning.
- **No mTLS between services** — traffic between the router, core, and dashboard is plain HTTP inside the Docker bridge. A production deployment should add mutual TLS between internal services.
- **ACM is static** — the allow-list is hard-coded in `router.py`. A real system would need a dynamic policy store with RBAC so operators can update rules without redeploying.
- **No rate limiting** — the router does not limit how fast a device can send requests. A production system should add per-device rate limiting to prevent flooding.

---

## Future Development Plans

- **Persistent state** — migrate risk scores, quarantine list, and event history to Redis (fast) or PostgreSQL (queryable) so state survives restarts and can be audited.
- **Human-in-the-loop quarantine review** — add a "lift isolation" button in the dashboard that requires a second operator to confirm, with a full audit trail of who approved what and when.
- **Dynamic ACM policy editor** — let operators add, remove, or temporarily override allow-list entries from the dashboard without redeploying code.
- **Alert routing** — send critical events (isolation triggered, payload injection detected) to SMS, email, or a messaging system like Telegram so operators are notified even when the dashboard is not open.
- **Historical analytics** — store events in a time-series database and add a dashboard tab with attack frequency graphs, peak risk periods, and device-level drill-downs over days/weeks.
- **Multi-village federation** — aggregate security events from multiple village deployments into a single regional SOC dashboard, enabling cross-village attack pattern detection.
- **Better model** — replace `llama3.2:1b` with `phi3:mini` or `llama3.2:3b` for richer, more context-aware insight text. Evaluate prompt tuning on village-specific attack logs.
- **Anomaly baseline learning** — let the AI observe two weeks of normal traffic per device and flag statistical deviations, not just rule violations. This would catch novel attack patterns that have no ACM rule.
- **Hardware deployment** — package the stack for single-board computers (Raspberry Pi 5, Orange Pi) so it can run on-site in the village without a cloud server.

---

## Ethics and Regulatory Notes

- **This system monitors infrastructure, not people.** The traffic analysed is machine-to-machine IoT commands (sensor readings, pump controls, camera snapshots). No personal data, biometrics, or user-level behaviour is collected, stored, or processed.
- **The AI is advisory, not autonomous.** The local LLM provides a risk score and a plain-English explanation to assist a human operator. It has no authority to take action. All enforcement decisions (ALLOW, BLOCK, ISOLATE) are made by the deterministic ACM rule engine. A human SOC operator reviews the AI's output and decides whether to act.
- **No cloud dependency for sensitive data.** The LLM runs entirely inside Docker on the operator's own hardware. Device payloads, IP addresses, and AI reasoning text never leave the local network. There is no third-party API call for security decisions.
- **Transparency by design.** Every decision the system makes is logged with a timestamp, reason code, AI score, and source badge (`AI LIVE` or `STATIC`). Operators can always see what happened and why, including which scoring layer made the call.
- **Applicable frameworks.** A production version of this system handling real village infrastructure would need to comply with:
  - **GDPR / national data protection law** if any data could be linked to individuals (e.g. CCTV metadata, access logs)
  - **NIS2 Directive (EU)** for operators of essential services (water, energy)
  - **IEC 62443** for industrial and operational technology security
  - **AI Act (EU)** — an AI system making security decisions affecting critical infrastructure would likely fall under high-risk AI provisions, requiring conformity assessment, logging, and human oversight mechanisms
- **Responsible disclosure.** The attack script (`attack_script.py`) targets only the local stack running on the operator's own machine. It is a test harness, not an offensive tool. It must not be run against any system the user does not own or have explicit written permission to test.
