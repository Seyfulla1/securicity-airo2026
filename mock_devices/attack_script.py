#!/usr/bin/env python3
"""
SecuriVillage - Graduated Attack Demo
======================================

Runs a realistic multi-device attack escalation against the security router
and shows how the local Ollama AI's per-packet score accumulates into a
cumulative device risk, eventually triggering automatic isolation.

HOW THE AI SCORE IS CALCULATED
───────────────────────────────
Every packet goes through two layers before the dashboard sees it:

  Layer 1 — ACM + Payload Inspection (deterministic, inside the lock)
    The router checks a fixed allow-list (Action-Based Access Control Matrix).
    Unknown devices and confirmed payload injections are blacklisted instantly.
    All other decisions (ALLOWED / BLOCKED) proceed to Layer 2.

  Layer 2 — Ollama AI per-packet score (probabilistic, outside the lock)
    The router sends this context to llama3.2:1b:
      • Device label and ID
      • Device Threat Level (CLEAN / ELEVATED / HIGH-RISK / CRITICAL)
      • Action attempted
      • The device's complete allow-list
      • Payload content
      • ACM verdict (ALLOWED / BLOCKED) + reason
      • Payload anomalies detected by static rules

    The model applies the scoring rules from its system prompt:
      ACM ALLOWED + clean payload          →  score  0-15
      ACM ALLOWED + suspicious payload     →  score 20-45
      ACM BLOCKED (forbidden action)       →  score 45-65
        + elevated device history          →  +10-20 on top
      ACM BLOCKED (payload injection)      →  score 80-100
      Already ISOLATED                     →  score 90-100

  Accumulation formula (router Phase 2.5):
      cumulative_risk  +=  max(ai_score // 3,  floor)
      floor = 10 for ACM_VIOLATION (ensures blocked packets always register)

  Isolation threshold: cumulative_risk >= 70

EXPECTED PROGRESSION IN THIS DEMO
───────────────────────────────────
  Phase 1  Nominal (5 packets)              AI ≈  0-10   cumulative ≈ 0
  Phase 2  well_pump_01 ACM violations (3)  AI ≈ 45-68   cumulative ≈ 15→35→55
  Phase 3  cctv_gate_01 ACM violations (2)  AI ≈ 45-62   cumulative ≈ 15→30
  Phase 4  well_pump_01 payload injection   immediate blacklist (cumulative → 100)
  Phase 5  Isolation proof (3 packets)      all refused

Run:  python3 attack_script.py
      PROXY_URL=http://host:8080/command python3 attack_script.py
"""

import json, os, time, urllib.request, urllib.error

PROXY_URL    = os.environ.get("PROXY_URL", "http://localhost:8080/command")
PUMP         = "well_pump_01"
CCTV         = "cctv_gate_01"

RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m"
GREEN  = "\033[32m"; RED    = "\033[31m"; CYAN   = "\033[36m"
YELLOW = "\033[33m"; PURPLE = "\033[35m"; ORANGE = "\033[38;5;208m"


# ─────────────────────────────────────────────────────────────────────────────
# Transport + display
# ─────────────────────────────────────────────────────────────────────────────

def send(device_id, action, payload, note=""):
    """POST to the router; print ACM verdict, cumulative risk, and AI reasoning."""
    body = json.dumps({"device_id": device_id,
                       "action": action,
                       "payload": payload}).encode()
    req = urllib.request.Request(
        PROXY_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            code   = resp.status
    except urllib.error.HTTPError as err:
        result = json.loads(err.read().decode())
        code   = err.code
    except urllib.error.URLError as err:
        print(f"{RED}  !! cannot reach router at {PROXY_URL}: {err}{RESET}")
        return None

    decision   = result.get("decision",      "?")
    cumulative = result.get("risk_score",     "?")
    ai_score   = result.get("ai_risk_score",  "?")
    ai_insight = result.get("ai_insight",     "(no insight)")
    source     = result.get("scoring_source", "?")
    reason     = result.get("reason",         "")
    anomalies  = result.get("anomalies")      or []

    col        = GREEN if decision == "ALLOWED" else RED
    src_lbl    = (f"{PURPLE}AI-LIVE{RESET}" if source == "ollama_ai"
                  else f"{YELLOW}STATIC {RESET}")
    anom_str   = f"  {ORANGE}⚠ {' | '.join(anomalies)}{RESET}" if anomalies else ""
    note_str   = f"  {DIM}# {note}{RESET}" if note else ""

    # Show the cumulative risk bar (one █ per 10 points)
    cum_val    = cumulative if isinstance(cumulative, int) else 0
    bar        = ("█" * (cum_val // 10)).ljust(10)
    bar_col    = GREEN if cum_val < 40 else (YELLOW if cum_val < 70 else RED)

    print(
        f"  {device_id:20} {action:20}"
        f" → {col}{BOLD}{decision:9}{RESET}"
        f"  cumulative={bar_col}{BOLD}{cumulative:>3}{RESET} [{bar_col}{bar}{RESET}]"
        f"  [{src_lbl}] per-packet={BOLD}{ai_score:>3}{RESET}"
        f"{note_str}"
    )
    print(f"    {DIM}↳ {ai_insight[:90]}{anom_str}{RESET}")
    return result


def banner(phase, title, expected):
    print(f"\n{CYAN}{BOLD}{'─'*72}{RESET}")
    print(f"{CYAN}{BOLD}  {phase}  {title}{RESET}")
    print(f"{DIM}  Expected AI per-packet score: {expected}{RESET}")
    print(f"{CYAN}{BOLD}{'─'*72}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Phases
# ─────────────────────────────────────────────────────────────────────────────

def phase1_nominal():
    banner("PHASE 1", "Nominal transmission — all devices, routine commands", "0 – 10")
    print(f"""{DIM}  All 5 devices send their expected routine commands.
  ACM: ALLOWED   AI sees: known device + permitted action + clean payload
  Expected output: risk scores near 0, cumulative stays flat.{RESET}\n""")
    for did, action, payload in [
        ("agri_soil_01",      "read_telemetry",   "moisture=38,temp=21"),
        ("env_weather_01",    "read_telemetry",   "temp=22,humidity=55,wind=12"),
        ("cctv_gate_01",      "capture_snapshot", "frame=jpeg,size=82kb"),
        (PUMP,                "read_telemetry",   "pressure=48,flow=12"),
        ("solar_inverter_01", "read_telemetry",   "output=3200,voltage=230"),
    ]:
        send(did, action, payload)
        time.sleep(0.5)


def phase2_pump_acm_violations():
    banner("PHASE 2", f"{PUMP} — forbidden actions escalate risk gradually", "45 – 68")
    print(f"""{DIM}  The compromised pump tries three actions outside its allow-list.
  ACM: BLOCKED (ACM_VIOLATION)   AI sees: BLOCKED + device history worsening
  After each violation the per-packet AI score should rise because the device's
  Threat Level escalates from CLEAN → ELEVATED → HIGH-RISK.
  With accumulation formula  delta = max(ai_score // 3, 10)  the cumulative
  risk grows by ~10-22 per packet, reaching ~30-65 after three violations.{RESET}\n""")

    # 1st violation — device is CLEAN; AI scores the forbidden action ~45-55
    send(PUMP, "device_shutdown", "force=true",
         "1st violation: pump has no shutdown permission (device: CLEAN)")
    time.sleep(0.6)

    # 2nd violation — device now ELEVATED; AI should score higher ~52-62
    send(PUMP, "set_config", "remote_access=enabled,auth_check=bypass",
         "2nd violation: config change + auth bypass (device: ELEVATED)")
    time.sleep(0.6)

    # 3rd violation — device now HIGH-RISK; AI should score highest ~60-72
    send(PUMP, "exec_command", "cmd=export_data,destination=external",
         "3rd violation: unknown action, data exfiltration attempt (device: HIGH-RISK)")
    time.sleep(0.6)


def phase3_cctv_acm_violations():
    banner("PHASE 3", f"{CCTV} — a second compromised device attempts unauthorized control", "45 – 62")
    print(f"""{DIM}  A different device — the gate CCTV camera — is now compromised.
  Its allow-list: read_telemetry, report_status, capture_snapshot, stream_video.
  It tries to unlock the gate and disable the alarm — actions outside its domain.
  ACM: BLOCKED (ACM_VIOLATION)
  Note that this device starts from a CLEAN history (its own risk counter),
  independent of the pump. You will see its cumulative risk build separately.{RESET}\n""")

    # cctv_gate_01 has allow-list: read_telemetry, report_status, capture_snapshot, stream_video
    send(CCTV, "unlock_gate",    "pin=0000,force=true",
         "camera should not control the lock (device: CLEAN)")
    time.sleep(0.6)

    send(CCTV, "disable_alarm",  "reason=maintenance,auth=none",
         "alarm control not in camera's allow-list (device: ELEVATED)")
    time.sleep(0.6)


def phase4_payload_injection():
    banner("PHASE 4", f"{PUMP} — confirmed payload injection (immediate blacklist)", "80 – 100")
    print(f"""{DIM}  The attacker now sends a payload that the router's static Deep Payload
  Inspection (DPI) catches BEFORE the AI runs:

    payload: pressure=999%,flow=ERROR_OVERFLOW

  DPI flags:
    • overflow_percentage  (999 > 100 is physically impossible)
    • error_token          (ERROR_OVERFLOW is a known attack marker)

  Because PAYLOAD_ANOMALY is deterministic, the router immediately sets
  cumulative_risk = 100 and blacklists the device — no AI needed for the
  isolation decision. The AI still runs and confirms the score.{RESET}\n""")

    send(PUMP, "read_telemetry", "pressure=999%,flow=ERROR_OVERFLOW",
         "DPI catch: overflow_percentage + error_token → immediate blacklist")
    time.sleep(0.6)


def phase5_isolation_proof():
    banner("PHASE 5", f"{PUMP} — isolation enforced for all future requests", "90 – 100")
    print(f"""{DIM}  {PUMP} is quarantined. Any future packet — even clean telemetry — is
  refused with decision=ISOLATED. The AI still runs (it explains the
  quarantine in ai_insight) but the security decision is already final.{RESET}\n""")

    for i in range(3):
        send(PUMP, "read_telemetry", "pressure=47,flow=11",
             f"attempt {i+1}: legitimate payload, still refused")
        time.sleep(0.4)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(f"""
{BOLD}SecuriVillage — Graduated Attack Demo{RESET}
{DIM}Target: {PROXY_URL}{RESET}

{BOLD}AI scoring formula:{RESET}
  per_packet_score  = llama3.2:1b output (0-100, follows scoring rules in system prompt)
  delta             = max(per_packet_score // 3,  10 if BLOCKED else 0)
  cumulative_risk  += delta   →   isolate when cumulative_risk >= 70

{BOLD}Column guide:{RESET}
  cumulative  = device's total accumulated risk (grows across packets)
  per-packet  = AI's score for this specific request only
  ████        = cumulative risk bar (10 blocks = 100%)
""")
    phase1_nominal()
    phase2_pump_acm_violations()
    phase3_cctv_acm_violations()
    phase4_payload_injection()
    phase5_isolation_proof()
    print(f"""
{GREEN}{BOLD}Demo complete.{RESET}
Open the dashboard:
  • Click {BOLD}{PUMP}{RESET}  — watch per-packet scores rise across Phases 2 and 4.
  • Click {BOLD}{CCTV}{RESET} — see its own independent cumulative risk from Phase 3.
  • Click any row (▶) to expand raw headers and payload.
""")


if __name__ == "__main__":
    main()
