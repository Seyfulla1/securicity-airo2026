#!/usr/bin/env python3
"""
VillageShield - Security Router / Policy Enforcement Point (PEP)
================================================================

This Flask service is the ONLY door that smart-village IoT devices are allowed
to knock on. Every command a device sends passes through here first. Think of it
as a strict security guard standing in front of the real control room ("Core
Utilities"). For every request the guard:

  1. Checks an Action-Based Access Control Matrix (ACM): is THIS device even
     allowed to perform THIS action? (default-deny / zero-trust)
  2. Performs Deep Payload Inspection: does the data inside the request look
     malicious (impossible values, error tokens, injection patterns)?
  3. Maintains a thread-safe isolation blacklist: once a device misbehaves
     badly enough it is quarantined and can no longer talk to anything.
  4. Computes a cumulative risk score (0-100) per device and escalates it on
     violations. This is the deterministic, rule-based baseline score.
  5. [NEW] Queries the local Ollama AI engine for a DYNAMIC per-packet risk
     score and a human-readable insight sentence. If Ollama is unavailable,
     falls back to the static rule matrix automatically — no crash, no silence.
  6. Forwards ONLY clean, permitted traffic to Core Utilities.
  7. Emits a standardized JSON event to the SIEM dashboard for EVERY packet,
     now enriched with the AI's risk score and reasoning insight.

ARCHITECTURE NOTE — WHY TWO SCORING SYSTEMS?
  The deterministic ACM (Step 1-4) is the security CONTRACT: it enforces hard
  rules that cannot be overridden. A weather station NEVER gets to shut down the
  water pump, no matter what the AI says. This is your guarantee of correctness.

  The AI scoring (Step 5) is the CONTEXT LAYER: it reads the situation holistically
  and adds a "why does this feel suspicious?" explanation that a human operator can
  actually understand. It can catch subtle patterns (unusual payload size at 3AM,
  a permitted action from a device with a history of anomalies) that rigid rules
  would miss.

  Together they form a defense-in-depth: the ACM stops known-bad; the AI flags
  unknown-suspicious; a human operator (looking at the SIEM) makes the final call.
"""

import json
import os
import re
import threading
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify

# --------------------------------------------------------------------------- #
# Configuration (read from environment so docker-compose can wire everything). #
# --------------------------------------------------------------------------- #
LISTEN_PORT       = int(os.environ.get("LISTEN_PORT", "5000"))
DASHBOARD_WEBHOOK = os.environ.get("DASHBOARD_WEBHOOK", "http://172.28.0.10:3000/api/ingest")
CORE_BACKEND      = os.environ.get("CORE_BACKEND",      "http://172.28.0.30:6000/command")
HTTP_TIMEOUT      = float(os.environ.get("HTTP_TIMEOUT", "2.0"))

# NEW: Ollama AI configuration.
# These are read from environment variables set in docker-compose.yml.
# Defaults point to the static IP we assigned to the ollama container.
OLLAMA_URL     = os.environ.get("OLLAMA_URL",     "http://172.28.0.40:11434")
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL",   "llama3.2:1b")
OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "8.0"))
# 8 seconds: enough time for even a slow CPU to generate a short JSON response,
# but short enough that a hanging Ollama container doesn't stall the whole pipeline.

# --------------------------------------------------------------------------- #
# Action-Based Access Control Matrix (ACM)                                     #
# --------------------------------------------------------------------------- #
# This is the heart of zero-trust. For each KNOWN device we list the EXACT set
# of actions it is permitted to perform. Anything not on the list is denied by
# default. A weather station has no business shutting devices down, so
# "device_shutdown" simply never appears in any allow-list anywhere.
ACM = {
    "agri_soil_01":      {"read_telemetry", "report_status", "calibrate"},
    "env_weather_01":    {"read_telemetry", "report_status"},
    "cctv_gate_01":      {"read_telemetry", "report_status", "capture_snapshot", "stream_video"},
    "well_pump_01":      {"read_telemetry", "report_status", "pump_on", "pump_off"},
    "solar_inverter_01": {"read_telemetry", "report_status", "set_mode"},
}

# Human-friendly labels (purely for nicer logs / events).
DEVICE_LABELS = {
    "agri_soil_01":      "Soil Moisture Sensor",
    "env_weather_01":    "Weather Station",
    "cctv_gate_01":      "Gate CCTV Camera",
    "well_pump_01":      "Well Water Pump",
    "solar_inverter_01": "Solar Inverter",
}

# --------------------------------------------------------------------------- #
# Risk model constants                                                         #
# --------------------------------------------------------------------------- #
RISK_ISOLATED_RETRY       = 5   # extra penalty each time a quarantined device retries
ISOLATION_THRESHOLD       = 70  # cumulative AI-risk score at which a device is quarantined
AI_RISK_ACCUMULATION_DIV  = 3   # each packet contributes ai_risk_score // this to cumulative risk
STATUS_SUSPICIOUS_AT      = 40
STATUS_ELEVATED_AT        = 15

# --------------------------------------------------------------------------- #
# Shared, mutable state  (protected by a single lock!)                         #
# --------------------------------------------------------------------------- #
# RISK and BLACKLIST are touched by many request threads at once. Without a lock,
# two threads could read-modify-write the same score simultaneously and corrupt
# it (a "race condition"). threading.Lock() guarantees only one thread is inside
# the critical section at a time, so our decisions stay consistent.
state_lock = threading.Lock()
RISK      = {device_id: 0 for device_id in ACM}   # device_id -> int 0..100
BLACKLIST = set()                                  # device_ids that are quarantined


def status_for(score, isolated):
    """Translate a numeric risk score into a human status label."""
    if isolated:
        return "ISOLATED"
    if score >= ISOLATION_THRESHOLD:
        return "CRITICAL"
    if score >= STATUS_SUSPICIOUS_AT:
        return "SUSPICIOUS"
    if score >= STATUS_ELEVATED_AT:
        return "ELEVATED"
    return "NOMINAL"


# --------------------------------------------------------------------------- #
# Deep Payload Inspection                                                      #
# --------------------------------------------------------------------------- #
# Blocking by action is not enough. A device might send an ALLOWED action but
# stuff malicious data into the payload. So we read the raw string and look for
# tell-tale signs of trouble. Each check returns a short tag describing what was
# found; the list of tags becomes part of the security event.
INJECTION_RE = re.compile(
    r"(?:--|;|/\*|\*/|\bunion\b|\bselect\b|\bdrop\b|\bor\b\s+1=1|<script|\$\(|`|\.\./)",
    re.IGNORECASE,
)
ERROR_TOKEN_RE = re.compile(
    r"(?:ERROR_OVERFLOW|OVERFLOW|UNDERFLOW|0x[0-9a-f]{6,}|\bnan\b|[-+]?inf\b)",
    re.IGNORECASE,
)
PERCENT_RE    = re.compile(r"(\d+(?:\.\d+)?)\s*%")
MAX_PAYLOAD_LEN = 256


def inspect_payload(payload: str):
    """Return a sorted list of anomaly tags found in the payload string."""
    anomalies = set()

    # 1) Percentages that are physically impossible (a sensor reporting 999%).
    for match in PERCENT_RE.finditer(payload):
        try:
            if float(match.group(1)) > 100:
                anomalies.add("overflow_percentage")
        except ValueError:
            pass

    # 2) Explicit error / overflow markers that should never appear in real data.
    if ERROR_TOKEN_RE.search(payload):
        anomalies.add("error_token")

    # 3) Classic injection patterns (SQL / shell / path traversal / XSS).
    if INJECTION_RE.search(payload):
        anomalies.add("injection_pattern")

    # 4) Suspiciously large payloads (possible buffer-overflow attempt).
    if len(payload) > MAX_PAYLOAD_LEN:
        anomalies.add("oversized_payload")

    # 5) Non-printable / control characters that shouldn't be in telemetry.
    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in payload):
        anomalies.add("control_chars")

    return sorted(anomalies)


# --------------------------------------------------------------------------- #
# NEW: Local Ollama AI Risk Scoring Engine                                     #
# --------------------------------------------------------------------------- #

def _extract_json_from_text(text: str) -> dict:
    """
    Robustly extracts a JSON object from an LLM's text output.

    WHY THIS IS NEEDED:
    Even with Ollama's `format: "json"` mode, small models (1B parameters)
    occasionally wrap their JSON in markdown fences like ```json ... ```,
    or prepend sentences like "Sure, here is the analysis:". This function
    handles all those cases defensively so we never crash on malformed output.

    The three fallback strategies in order of reliability:
      1. Direct parse: the happy path (model output clean JSON directly)
      2. Markdown fence extraction: strip ```json ... ``` wrapper
      3. Regex hunt: find ANY {...} block containing our expected keys
    """
    # Strategy 1: The model output clean JSON directly (ideal case).
    try:
        return json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        pass

    # Strategy 2: The model wrapped JSON in a markdown code fence.
    # Matches both ```json { ... } ``` and ``` { ... } ```
    fence_pattern = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
    match = fence_pattern.search(text)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    # Strategy 3: Nuclear option — find the LAST { ... } block in the text
    # that contains both of our required keys. This handles models that
    # prepend explanatory text before the JSON.
    # We search for the last occurrence because models sometimes "think aloud"
    # with invalid JSON first and then output the real answer.
    brace_pattern = re.compile(r"\{[^{}]*\}", re.DOTALL)
    candidates = brace_pattern.findall(text)
    for candidate in reversed(candidates):  # iterate newest-first
        if "risk_score" in candidate and "ai_insight" in candidate:
            try:
                return json.loads(candidate)
            except (json.JSONDecodeError, ValueError):
                continue

    # Nothing worked. Raise so the caller's except block can trigger fallback.
    raise ValueError(f"No parseable JSON found in AI response: {text[:300]!r}")


def query_ollama_for_risk(
    device_id: str,
    action: str,
    payload: str,
    source_ip: str,
    acm_decision: str,
    acm_reason: str,
    anomalies: list,
    current_risk: int,
) -> dict | None:
    """
    Sends a structured prompt to the local Ollama LLM and returns its risk assessment.

    WHAT THIS FUNCTION DOES:
    It builds two messages — a "system" prompt (permanent instructions for the AI's
    persona and output format) and a "user" prompt (the specific packet context for
    THIS request). It then POSTs them to Ollama's /api/chat endpoint and parses the
    JSON response.

    RETURN VALUE:
    On success: {"ai_risk_score": int, "ai_insight": str, "scoring_source": "ollama_ai"}
    On any failure: None  (caller falls back to static scoring)

    WHY WE RETURN None ON FAILURE (not raise):
    The Ollama AI is an enhancement, not a critical dependency. If the container is
    still starting, the model is slow, or the network hiccups, the security pipeline
    must NOT crash. Returning None lets the caller switch to static scoring
    transparently. The operator sees "AI offline. Static ACM verdict: ALLOWED."
    instead of a 500 error. This is called graceful degradation.
    """

    # ------------------------------------------------------------------ #
    # SYSTEM PROMPT: The AI's permanent identity and output contract.
    #
    # WHY FORMAT: "json" IN THE API CALL IS NOT ENOUGH ON ITS OWN:
    # Ollama's `format: "json"` uses constrained decoding at the tokenizer
    # level — it biases the model toward valid JSON tokens. However, small
    # 1B parameter models still sometimes mis-structure the JSON (wrong key
    # names, wrong value types). So we ALSO write very explicit instructions
    # in the system prompt AND validate the output in _extract_json_from_text.
    # Belt AND suspenders.
    # ------------------------------------------------------------------ #
    system_prompt = (
        "You are an automated cybersecurity analyst for a Smart Village IoT network "
        "monitoring soil sensors, weather stations, CCTV cameras, water pumps, and solar inverters.\n\n"
        "Your ONLY job: analyze one IoT packet and return a JSON risk score.\n\n"
        "STRICT OUTPUT FORMAT — no other text, no markdown, no fences:\n"
        '{"risk_score": <INTEGER 0-100>, "ai_insight": "<ONE sentence, max 15 words>"}\n\n'
        "MANDATORY SCORING RULES:\n"
        "  Rule 1: ACM Decision = ALLOWED, no anomalies  →  score 0-15\n"
        "  Rule 2: ACM Decision = ALLOWED, payload has suspicious words "
        "(override, bypass, disable, tamper, unauthorized)  →  score 20-45\n"
        "  Rule 3: ACM Decision = BLOCKED, reason = ACM_VIOLATION  →  score 45-65\n"
        "           Add 10-20 if Device Threat Level is ELEVATED or HIGH-RISK.\n"
        "  Rule 4: ACM Decision = BLOCKED, reason = PAYLOAD_ANOMALY  →  score 80-100\n"
        "  Rule 5: ACM Decision = ISOLATED  →  score 90-100\n\n"
        "CRITICAL RULES FOR ai_insight:\n"
        "  • You MUST use the exact 'Action Attempted' value from the input in your sentence.\n"
        "  • You MUST reflect the device's current Threat Level (CLEAN / ELEVATED / HIGH-RISK / CRITICAL).\n"
        "  • NEVER reuse the same sentence for different events — each insight must describe THIS packet.\n"
        "  • Write in plain English. Name the specific action and why it is suspicious or safe.\n\n"
        "INSIGHT PATTERNS — fill in the bracketed values from the input, do not copy literally:\n"
        "  Rule 1: \"[device_label] [action] is routine; no anomalies detected.\"\n"
        "  Rule 2: \"[action] permitted but payload contains suspicious keyword [word].\"\n"
        "  Rule 3 (CLEAN):     \"[action] not in [device_label] allow-list; first policy violation.\"\n"
        "  Rule 3 (ELEVATED):  \"[action] blocked again; [device_label] accumulating violations.\"\n"
        "  Rule 3 (HIGH-RISK): \"[action] blocked; [device_label] near isolation threshold.\"\n"
        "  Rule 4: \"Payload anomaly in [action]: [anomaly type] detected, device blacklisted.\"\n"
        "  Rule 5: \"[device_label] quarantined; [action] refused by isolation policy.\""
    )

    # ------------------------------------------------------------------ #
    # USER PROMPT: The specific packet details for THIS request.
    #
    # We include the ACM decision so the AI knows what the rule-based layer
    # already determined. A BLOCKED decision should raise the AI score.
    # We include anomalies so the AI knows about detected injection attempts.
    # We include current_risk so the AI knows this device's history.
    # ------------------------------------------------------------------ #
    device_label    = DEVICE_LABELS.get(device_id, "Unknown/Unregistered Device")
    allowed_actions = sorted(ACM.get(device_id, set()))
    anomaly_str     = ", ".join(anomalies) if anomalies else "none detected"

    # Describe device history in plain English so the model understands escalation context.
    if current_risk == 0:
        threat_level = "CLEAN — no prior violations recorded"
    elif current_risk < STATUS_ELEVATED_AT:
        threat_level = f"LOW ({current_risk}/100) — minor anomaly history"
    elif current_risk < STATUS_SUSPICIOUS_AT:
        threat_level = f"ELEVATED ({current_risk}/100) — some violations on record"
    elif current_risk < ISOLATION_THRESHOLD:
        threat_level = f"HIGH-RISK ({current_risk}/100) — repeated violations, near isolation threshold"
    else:
        threat_level = f"CRITICAL ({current_risk}/100) — at or above isolation threshold"

    user_prompt = (
        f"Analyze this IoT network packet:\n\n"
        f"Device ID: {device_id}\n"
        f"Device Label: {device_label}\n"
        f"Device Threat Level: {threat_level}\n"
        f"Action Attempted: {action}\n"
        f"Allowed Actions for This Device: {allowed_actions or 'NONE (unregistered device)'}\n"
        f"Payload Content: {payload[:200] if payload else '(empty)'}\n"
        f"Source IP Address: {source_ip}\n"
        f"ACM Rule Decision: {acm_decision} (reason: {acm_reason})\n"
        f"Payload Anomalies Detected: {anomaly_str}\n\n"
        f"Your ai_insight MUST mention the action '{action}' and the threat level '{threat_level.split(' ')[0]}'. "
        "Apply the scoring rules and respond with ONLY the JSON object. No other text."
    )

    try:
        # POST to Ollama's chat completion endpoint.
        # `/api/chat` supports system messages, which allows us to give the
        # model a persistent identity and output contract (the system prompt).
        # `/api/generate` is the simpler endpoint but lacks system message support.
        response = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                "stream": False,
                # Ollama's built-in JSON mode. Uses constrained decoding
                # to bias token selection toward valid JSON structure.
                # This is our first line of defense against malformed output.
                "format": "json",
                # Keep the model context small: we don't need conversation
                # history, just a fresh analysis for each packet.
                "options": {
                    "num_ctx": 1024,      # Larger context to fit enriched prompt + patterns
                    "temperature": 0.3,   # Enough variation to generate unique per-event insights
                },
            },
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()  # Raises if HTTP status is 4xx or 5xx.

        # The outer Ollama response envelope looks like:
        # { "model": "llama3.2:1b", "message": {"role": "assistant", "content": "..."}, "done": true }
        ollama_envelope = response.json()
        ai_text = ollama_envelope.get("message", {}).get("content", "")

        if not ai_text.strip():
            raise ValueError("Ollama returned an empty response content.")

        # Parse the AI's JSON output robustly (handles markdown fences etc.).
        parsed = _extract_json_from_text(ai_text)

        # Extract and validate both required fields.
        raw_score = parsed.get("risk_score")
        raw_insight = parsed.get("ai_insight", "")

        if raw_score is None:
            raise ValueError(f"AI response missing 'risk_score' key: {parsed}")

        # Type-coerce: the model might return "75" (string) instead of 75 (int).
        ai_risk_score = int(float(str(raw_score)))

        # Clamp to [0, 100]: the model might return 105 or -3.
        ai_risk_score = max(0, min(100, ai_risk_score))

        # Sanitize insight: truncate if very long, provide default if empty.
        ai_insight = str(raw_insight).strip()
        if not ai_insight:
            ai_insight = f"AI assessed {device_id} action {action!r}."
        ai_insight = ai_insight[:200]  # Hard cap to prevent UI overflow.

        print(
            f"[AI-OK] {device_id} | score={ai_risk_score} | "
            f'insight="{ai_insight[:60]}..."',
            flush=True,
        )

        return {
            "ai_risk_score": ai_risk_score,
            "ai_insight": ai_insight,
            "scoring_source": "ollama_ai",
        }

    except requests.exceptions.Timeout:
        # Ollama took too long. This is common when the model is loading into
        # RAM for the first time. Fail gracefully.
        print(f"[AI-TIMEOUT] Ollama timed out after {OLLAMA_TIMEOUT}s — using static fallback", flush=True)
        return None

    except requests.exceptions.ConnectionError:
        # Ollama container isn't reachable. This can happen during startup
        # before the health check passes, or if the container crashed.
        print("[AI-OFFLINE] Ollama not reachable — using static fallback", flush=True)
        return None

    except (json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
        # The AI returned something we couldn't parse. Log it and fall back.
        # We log the full error so the operator can debug model output quality.
        print(f"[AI-PARSE-ERR] Could not parse Ollama response: {exc} — using static fallback", flush=True)
        return None

    except Exception as exc:
        # Catch-all for any other unexpected errors (e.g., Ollama API changes).
        # Never let an AI failure crash the security pipeline.
        print(f"[AI-ERR] Unexpected Ollama error: {exc} — using static fallback", flush=True)
        return None


def get_static_ai_result(
    acm_decision: str,
    acm_reason: str,
    action: str = "",
    anomalies: list | None = None,
) -> dict:
    """
    Fallback when Ollama is unavailable.

    Produces event-specific text so each row in the dashboard shows a unique
    reason even when the AI is offline. The `scoring_source` field tells the
    dashboard to show a "STATIC" badge so operators know the AI is offline.
    """
    anomalies = anomalies or []
    act = action or "unknown action"

    if acm_decision == "ALLOWED":
        score = 5
        insight = f"Static rule: '{act}' is permitted by ACM policy. No violations detected."
    elif acm_decision == "BLOCKED":
        if acm_reason == "PAYLOAD_ANOMALY":
            score = 85
            anom_str = ", ".join(anomalies) if anomalies else "unspecified anomaly"
            insight = f"Static rule: malicious payload detected in '{act}' ({anom_str}). Device isolated."
        elif acm_reason == "ACM_VIOLATION":
            score = 65
            insight = f"Static rule: '{act}' is not in this device's allow-list. ACM policy violation."
        elif acm_reason == "UNKNOWN_DEVICE":
            score = 90
            insight = f"Static rule: unregistered device blocked attempting '{act}'."
        else:
            score = 65
            insight = f"Static rule: '{act}' blocked — {acm_reason}."
    elif acm_decision == "ISOLATED":
        score = 90
        insight = f"Static rule: device is quarantined; '{act}' denied by isolation policy."
    else:
        score = 50
        insight = f"Static rule: '{act}' — {acm_reason}."

    return {
        "ai_risk_score": score,
        "ai_insight": insight,
        "scoring_source": "static_acm",
    }


# --------------------------------------------------------------------------- #
# Outbound side-effects: SIEM webhook + forwarding to Core Utilities           #
# --------------------------------------------------------------------------- #
def build_event(direction, device_id, source_ip, action, payload,
                decision, reason, anomalies, risk_score, status,
                ai_risk_score=None, ai_insight="", scoring_source="static_acm",
                headers=None):
    """
    Assemble the standardized JSON event the dashboard understands.

    `headers` carries the raw HTTP request headers from the originating device
    so the SIEM can display them in the per-request detail pane.
    """
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "device_label": DEVICE_LABELS.get(device_id, "Unknown Device"),
        "source_ip": source_ip,
        "direction": direction,
        "action": action,
        "payload": payload,
        "headers": headers or {},
        "decision": decision,
        "reason": reason,
        "anomalies": anomalies,
        "risk_score": risk_score,
        "status": status,
        "ai_risk_score": ai_risk_score,
        "ai_insight": ai_insight,
        "scoring_source": scoring_source,
    }


def send_to_siem(event):
    """POST a single event to the dashboard. Never let a SIEM hiccup crash us."""
    try:
        requests.post(DASHBOARD_WEBHOOK, json=event, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        print(f"[WARN] could not reach SIEM dashboard: {exc}", flush=True)


def forward_to_core(device_id, action, payload):
    """Forward a permitted command to the protected Core Utilities backend."""
    try:
        resp = requests.post(
            CORE_BACKEND,
            json={"device_id": device_id, "action": action, "payload": payload},
            timeout=HTTP_TIMEOUT,
        )
        return resp.status_code == 200
    except requests.RequestException as exc:
        print(f"[WARN] could not reach Core Utilities: {exc}", flush=True)
        return False


# --------------------------------------------------------------------------- #
# Flask app                                                                    #
# --------------------------------------------------------------------------- #
app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"service": "villageshield-router", "status": "up"}), 200


@app.get("/status")
def status_dump():
    """Debug helper: current risk scores and quarantine list."""
    with state_lock:
        return jsonify({"risk": dict(RISK), "blacklist": sorted(BLACKLIST)}), 200


@app.post("/command")
def handle_command():
    """
    The single entry point for ALL device traffic.
    Body: {"device_id": "...", "action": "...", "payload": "..."}

    EXECUTION FLOW:
      Phase 1 [FAST, inside lock]:
        - ACM check (microseconds)
        - Payload inspection (microseconds)
        - Risk score update (microseconds)
        - Quarantine decision (microseconds)

      Phase 2 [SLOW, outside lock]:
        - Ollama AI query (~500ms-2s on CPU)
        - SIEM webhook POST (~2ms on local network)
        - Core Utilities forwarding (~2ms on local network)

    WHY SEPARATE PHASES?
    Holding a threading.Lock() across slow network I/O is a critical mistake.
    It would mean one slow AI response serializes ALL incoming device traffic.
    By releasing the lock before any network calls, other threads can process
    packets concurrently while this thread waits for the AI to respond.
    """
    data      = request.get_json(silent=True) or {}
    device_id = str(data.get("device_id", "")).strip()
    action    = str(data.get("action",    "")).strip()
    payload   = str(data.get("payload",   ""))
    source_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    # Capture all request headers for SIEM event enrichment (shown in detail pane).
    req_headers = dict(request.headers)

    # =====================================================================
    # PHASE 1: Deterministic security decision (inside lock, always fast)
    # Risk scoring is intentionally NOT done here — the AI score (Phase 2)
    # is the sole driver of cumulative risk accumulation. Only unambiguous
    # deterministic cases (unknown device, confirmed payload injection) still
    # trigger an immediate blacklist without waiting for AI.
    # =====================================================================
    with state_lock:
        anomalies = []

        if device_id not in ACM:
            # Unknown device: maximally distrusted, isolate immediately.
            RISK[device_id] = 100
            BLACKLIST.add(device_id)
            decision, reason = "BLOCKED", "UNKNOWN_DEVICE"

        elif device_id in BLACKLIST:
            # Already quarantined: refuse, nudge score toward 100.
            RISK[device_id] = min(100, RISK[device_id] + RISK_ISOLATED_RETRY)
            decision, reason = "ISOLATED", "DEVICE_ISOLATED"

        else:
            anomalies = inspect_payload(payload)
            if anomalies:
                # Confirmed malicious payload injection — isolate immediately.
                RISK[device_id] = 100
                BLACKLIST.add(device_id)
                decision, reason = "BLOCKED", "PAYLOAD_ANOMALY"
            elif action not in ACM[device_id]:
                # Forbidden action: decision is BLOCKED but risk accumulation
                # is deferred to Phase 2 so the AI score drives isolation.
                decision, reason = "BLOCKED", "ACM_VIOLATION"
            else:
                decision, reason = "ALLOWED", "OK"

        # Snapshot for logging. Will be re-snapshotted after AI updates risk.
        risk_now     = RISK.get(device_id, 100)
        isolated_now = device_id in BLACKLIST
        status       = status_for(risk_now, isolated_now)
    # =====================================================================
    # END PHASE 1: Lock released. Other threads can now process packets.
    # =====================================================================

    # One readable line for the live `docker compose logs` view.
    print(
        f"[{decision:8}] {device_id:18} action={action:16} "
        f"risk={risk_now:3} reason={reason} anomalies={anomalies}",
        flush=True,
    )

    # =====================================================================
    # PHASE 2: AI Risk Scoring (outside lock, can be slow)
    # =====================================================================
    # Query Ollama for a dynamic, contextual risk assessment.
    # If Ollama is unavailable for ANY reason, get_static_ai_result() returns
    # a reasonable static fallback so the event still has valid ai_* fields.
    ai_result = query_ollama_for_risk(
        device_id=device_id,
        action=action,
        payload=payload,
        source_ip=source_ip,
        acm_decision=decision,
        acm_reason=reason,
        anomalies=anomalies,
        current_risk=risk_now,
    )
    if ai_result is None:
        ai_result = get_static_ai_result(decision, reason, action=action, anomalies=anomalies)

    # Unpack the AI result into named variables for clarity.
    ai_risk_score   = ai_result["ai_risk_score"]
    ai_insight      = ai_result["ai_insight"]
    scoring_source  = ai_result["scoring_source"]

    # =====================================================================
    # PHASE 2.5: AI-driven cumulative risk accumulation (re-acquires lock)
    # Each packet contributes a fraction of the AI's per-packet score to
    # the device's running total. Once the total crosses ISOLATION_THRESHOLD
    # the device is quarantined — no ACM rule bump needed.
    # We skip devices already in BLACKLIST (already isolated via Phase 1).
    # =====================================================================
    with state_lock:
        if device_id not in BLACKLIST:
            delta = ai_risk_score // AI_RISK_ACCUMULATION_DIV
            # Safety floor for ACM violations: even if the model is conservative
            # (cold start, low-confidence output), a blocked forbidden action must
            # always register a visible risk increase. The AI score is still the
            # primary driver; the floor only activates when it scores below 30.
            if reason == "ACM_VIOLATION":
                delta = max(delta, 10)
            if delta > 0:
                RISK[device_id] = min(100, RISK.get(device_id, 0) + delta)
                if RISK[device_id] >= ISOLATION_THRESHOLD:
                    BLACKLIST.add(device_id)
        # Re-snapshot with updated values so SIEM and response reflect current state.
        risk_now     = RISK.get(device_id, 100)
        isolated_now = device_id in BLACKLIST
        status       = status_for(risk_now, isolated_now)

    # =====================================================================
    # PHASE 3: Side-effects — notify SIEM, forward to core
    # =====================================================================

    # 1) ALWAYS tell the SIEM what the device ATTEMPTED (outbound traffic).
    send_to_siem(build_event(
        "outbound", device_id, source_ip, action, payload,
        decision, reason, anomalies, risk_now, status,
        ai_risk_score=ai_risk_score,
        ai_insight=ai_insight,
        scoring_source=scoring_source,
        headers=req_headers,
    ))

    # 2) Only permitted traffic is forwarded to Core Utilities. If Core accepts
    #    it, we also tell the SIEM what Core RECEIVED (inbound traffic).
    #    The inbound event carries the same AI data — this lets the dashboard
    #    show "the AI confirmed this delivered command was safe" in the modal.
    delivered = False
    if decision == "ALLOWED":
        delivered = forward_to_core(device_id, action, payload)
        if delivered:
            send_to_siem(build_event(
                "inbound", device_id, source_ip, action, payload,
                "DELIVERED", "FORWARDED_TO_CORE", [], risk_now, status,
                ai_risk_score=ai_risk_score,
                ai_insight=ai_insight,
                scoring_source=scoring_source,
                headers=req_headers,
            ))

    http_status = 200 if decision == "ALLOWED" else 403
    return jsonify({
        "accepted":        decision == "ALLOWED",
        "delivered":       delivered,
        "decision":        decision,
        "reason":          reason,
        "anomalies":       anomalies,
        "risk_score":      risk_now,
        "status":          status,
        # AI fields also returned in the API response (useful for testing).
        "ai_risk_score":   ai_risk_score,
        "ai_insight":      ai_insight,
        "scoring_source":  scoring_source,
    }), http_status


if __name__ == "__main__":
    print(f"[BOOT] VillageShield router listening on :{LISTEN_PORT}", flush=True)
    print(f"[BOOT] SIEM webhook  -> {DASHBOARD_WEBHOOK}", flush=True)
    print(f"[BOOT] Core backend  -> {CORE_BACKEND}", flush=True)
    print(f"[BOOT] Ollama AI     -> {OLLAMA_URL} (model: {OLLAMA_MODEL}, timeout: {OLLAMA_TIMEOUT}s)", flush=True)
    # threaded=True => ONE process, MANY threads. The in-memory BLACKLIST/RISK is
    # shared across those threads (and protected by state_lock). We deliberately
    # run a SINGLE process so the quarantine list is global. Multiple worker
    # *processes* would each get their own copy and isolation would silently break.
    app.run(host="0.0.0.0", port=LISTEN_PORT, threaded=True)
