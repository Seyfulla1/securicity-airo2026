# SecuriVillage — Business Model & Feasibility Study

**Project:** SecuriVillage — Smart Village IoT Security Monitoring Platform
**Team:** Securicity
**Task:** 2 — Smart Village IoT Security

---

## 3.4. Project Usability, Cost, Benefit, and Schedule Data

Here we will explain each part according to our project.

### Usability

Smart village infrastructure is operated by people who are not necessarily IT professionals — they are farmers, utility workers, and local administrators who know how to manage a water pump or a solar inverter but are not trained in cybersecurity. So usability is actually one of the most critical parts of our project, maybe even more than in a typical software product.

We tried to design the dashboard so that it does not require any technical background to understand. The device cards show a simple colour-coded status (green for NOMINAL, amber for ELEVATED, red for ISOLATED) and a plain-English explanation from the AI, something like "set_config blocked; well_pump_01 accumulating violations, risk elevated." instead of an error code. The idea is that even if the operator does not understand what a payload anomaly is, they can still read that sentence and understand something is wrong with the pump.

The PIN login is also intentionally kept simple for the demo. In a real deployment we would obviously need stronger authentication, but for the purpose of showing the system to non-technical village managers, a simple PIN lowers the barrier to entry significantly.

Overall, we believe usability will not be a major obstacle as long as we keep the interface clean and the AI explanations readable. The harder part is convincing village administrations to adopt a new security tool at all, which is more of a cultural and awareness problem than a technical one.

### Cost

To build a fully deployable version of SecuriVillage we would need professionals like embedded systems engineers who understand IoT protocols, backend developers, a security engineer who can audit the ACM rules and threat model, a DevOps engineer to handle containerisation and deployment on low-power hardware, and QA engineers for testing. As I am not very familiar with the exact current salaries of all these professionals and the price of the infrastructure we would need, I cannot give a precise total cost. But I will try to give a rough estimate in the Economic Feasibility section below.

### Benefit

There have been multiple real-world attacks on smart city and village infrastructure that caused serious damage — water treatment plants being accessed remotely, power grids being disrupted, and industrial control systems being compromised. These incidents show that the risk is very real and the consequences go beyond financial loss — they can endanger lives. Our system directly addresses this by making it much harder for a compromised device to send unauthorized commands to the control plane, and by giving operators a real-time view of what is happening in their network with plain-English AI explanations they can actually understand and act on.

Beyond security, there is also a trust benefit. Villages and municipalities that adopt smart infrastructure need to be able to assure their residents that the systems are protected. Having a visible, explainable security layer helps build that confidence.

### Schedule

For this project we had a quite tight schedule similar to any hackathon setting, roughly a few days to build the prototype. We prioritised building a working end-to-end pipeline first — router, dashboard, AI engine, and demo script — and then added features like per-request AI reasoning in the row expansion, the static fallback, and the attack demo phases on top of that. In a real development cycle the schedule would obviously be much longer, which we discuss in the Schedule Feasibility section.

---

## 3.5. Evaluation of Feasibility

We identified feasibilities through our research into real-world IoT attack incidents and by thinking about how the system would be used in an actual smart village deployment.

### 3.5.1. Operational Feasibility

Our system is designed to work for operators who have little to no cybersecurity background. The two-layer approach — deterministic ACM rules for hard enforcement and a local AI for plain-English explanations — means that even if the operator does not understand what an ACM_VIOLATION or a payload anomaly means technically, they can still read the AI's insight sentence and understand that something unusual happened. The pulsing red ring on an isolated device card is also immediately recognisable without needing to know anything about risk scores.

One potential operational challenge is that village administrators may be reluctant to act on an AI-generated warning without fully understanding it, especially if it means cutting off a device that seems to be working fine from their perspective. The quarantine feature isolates a device automatically when the cumulative risk crosses 70, which is intentional for the prototype, but in a real deployment this should probably require a human confirmation step so operators feel they are in control of the decision.

Another challenge is that the system needs someone to monitor the dashboard regularly. In a small village without dedicated IT staff, that might not always happen. Alert routing to SMS or a messaging app would help here.

**S** — Non-technical operators can understand what is happening from the AI insight text and colour-coded status without needing to know security terminology

**W** — Operators may not act quickly enough on warnings, especially if they do not trust automated decisions about their infrastructure

**O** — Can help village administrations meet basic cybersecurity compliance requirements for smart infrastructure funding programs

**T** — Resistance to adopting new monitoring tools is common in environments where things have "always worked fine" without security monitoring

### 3.5.2. Technical Feasibility

Technically, the core of the system is built on proven open-source tools — Flask, Node.js, Socket.io, Docker, and Ollama. The most difficult technical challenge we faced during development was getting the local AI model to produce unique, contextually accurate insights per packet rather than copying example responses from the system prompt. Small 1B models at low temperature tend to be very repetitive, and we had to carefully redesign the prompt to force the model to use the actual action name and device threat level in its output rather than returning a cached phrase.

For a real deployment, the harder technical challenges would be integrating with real IoT protocols like MQTT and CoAP (the prototype uses a simple HTTP API), deploying on low-power hardware like a Raspberry Pi 5 where CPU-based inference is slower, and tuning the ACM rules and risk thresholds for specific real-world village setups where what counts as a "normal" action may vary significantly between deployments.

The AI fallback mechanism — which switches to static rule-based scoring when Ollama is unavailable — is one of the more important technical features because it means the system stays secure even if the AI component fails, which is essential for critical infrastructure.

**S** — Built entirely on proven, free, open-source technologies with no external API dependency

**W** — The 1B model quality is limited; for complex attack patterns it may produce generic or inaccurate insights

**O** — Can be upgraded to a larger model (3B, 8B) by changing a single configuration line as better hardware becomes available

**T** — Real IoT environments use many different protocols and device types that would require significant additional integration work beyond the prototype

### 3.5.3. Economic Feasibility (if we think that we will build a full functional product)

If this project was considered as a real product that would be deployed across multiple smart villages, the total cost would cover a development team, infrastructure, security testing, and ongoing maintenance. As I do not know the exact salaries of these professionals in every country, I will give a rough estimate based on reasonable assumptions.

**Development Team:**

- 3–4 Senior Developers (backend, embedded, frontend) × 3000$ × 8 months = 72,000$ → 96,000$
- 1–2 IoT/Security Engineers × 3000$ × 8 months = 24,000$ → 48,000$
- 1 DevOps Engineer × 2500$ × 8 months = 20,000$
- 1 QA Engineer × 2000$ × 8 months = 16,000$

**Subtotal: Roughly 130,000$ → 180,000$**

**Infrastructure:**

Low-power on-site hardware (Raspberry Pi 5 units or similar) for each village deployment, plus development tools and internal testing infrastructure would probably come to around 15,000$ → 25,000$ depending on the number of villages.

**Security Testing:**

External audit of the ACM rule design, threat modelling, and penetration testing: approximately 15,000$ → 20,000$.

**So our total cost would be roughly 160,000$ → 225,000$** for the first production-ready version covering a small number of village deployments.

It is worth noting that the cost per additional village after the initial system is built would be much lower — mostly hardware and setup time — because the software stack is entirely open-source and there are no per-query AI costs.

**S** — No recurring AI API costs since the model runs locally; scales cheaply to additional villages after initial development

**W** — High upfront development cost that small village administrations cannot typically fund on their own

**O** — EU and national smart infrastructure funding programs (Smart Villages initiative, etc.) could partially or fully cover development costs

**T** — Ongoing maintenance cost is hard to predict as IoT security threats evolve and new attack patterns require updates to the ACM rules and AI prompts

### 3.5.4. Schedule Feasibility (for a real case)

For a real-life deployment of this system across actual village infrastructure we would need at least 8–10 months. So what we built in the hackathon is obviously not deployable as-is, and we are thinking of a hypothetical realistic schedule.

In the **first month** we would do feasibility studies, threat modelling specific to the village's infrastructure, and requirement gathering — including actually visiting the site and understanding what devices are used, what protocols they speak, and who will be operating the dashboard.

In the **second month** we would design the system and security architecture, define the ACM allow-lists for each device type, and plan the deployment topology.

In the **third and fourth months** the core development would happen — the router, dashboard, AI integration, and hardware setup on the target devices. We would also start writing integration tests during this period.

In the **fifth and sixth months** we would do internal testing with simulated attack scenarios similar to our demo script, tune the risk thresholds and AI prompts for the specific device types in that village, and fix issues.

In the **seventh and eighth months** we would do external security testing, train the operators, and do a staged rollout where the system runs in monitoring-only mode first before enforcement is turned on.

**S** — The core software stack is already prototyped, which gives a real project a significant head start over building from scratch

**W** — Actual IoT integration and on-site deployment would take considerably longer than expected because real village infrastructure is heterogeneous and often poorly documented

**O** — A phased rollout where monitoring runs first without enforcement lets operators build trust in the system before it starts blocking devices

**T** — Coordinating with multiple stakeholders (village administration, device manufacturers, local government IT) will likely extend the schedule beyond the initial estimate

---

## 3.6. Request Form

### 3.6.1. Description of the Project

With the rapid expansion of smart village and smart city infrastructure, thousands of IoT devices — water pumps, solar inverters, environmental sensors, and surveillance cameras — are being connected to shared networks so they can be managed remotely. While this improves operational efficiency, it also creates a serious and often underappreciated attack surface.

In one well-documented real-world incident, attackers gained remote access to the water treatment plant in Oldsmar, Florida (2021) and attempted to increase the level of sodium hydroxide in the water supply to a dangerous concentration. The operator noticed the cursor moving on the screen and was able to intervene manually, but the incident showed how easy it is to compromise industrial control systems that have inadequate access control. In another major case, the Mirai botnet (2016) infected hundreds of thousands of IoT devices — cameras, routers, DVRs — by simply trying default factory passwords, and then used them to launch some of the largest distributed denial-of-service attacks ever recorded. These incidents show that IoT security is not a hypothetical concern; it is a real and present danger, including for small-scale infrastructure like smart villages.

Our project, SecuriVillage, aims to address this problem by building a zero-trust security gateway for smart village IoT networks. Every command sent by a device must pass through the security router, which checks it against a strict action-based allow-list before forwarding it to the protected backend. A locally-hosted open-source AI model (llama3.2:1b via Ollama) then provides a per-packet risk score and a plain-English explanation of why the traffic looks safe or suspicious. The entire system runs inside Docker with no internet dependency after the initial model download, no cloud API costs, and no requirement for the operator to have a cybersecurity background. Everything is visible in real time on a SOC dashboard that a non-technical village administrator can understand.

### 3.6.2. Requested Features

**Zero-Trust Action Control (ACM)** — Every IoT device has an explicit allow-list of exactly which actions it is permitted to perform. A weather station can read telemetry and report status. A water pump can turn on and off. Nothing else. Any action not on the list is blocked immediately, no exceptions, regardless of what the AI says.

**Deep Payload Inspection (DPI)** — Even if a device sends an allowed action, the payload content is scanned for injection patterns (SQL, shell, path traversal), physically impossible values (sensor reporting 999% humidity), error tokens, oversized payloads, and control characters. If anything suspicious is found the device is blacklisted immediately without waiting for the AI.

**Local AI Risk Scoring** — Each packet is sent to a locally-running llama3.2:1b model via Ollama. The model reads the device context, action, payload content, and the ACM decision, then returns a risk score from 0 to 100 and a one-sentence plain-English explanation. This explanation is shown in the dashboard and in the per-request detail panel so operators know exactly why a packet was flagged without needing to interpret error codes.

**Cumulative Risk and Automatic Quarantine** — Each device accumulates a risk score over time based on its behaviour history. A single minor violation raises the score slightly. Repeated violations or a payload injection spike it to 100. Once a device crosses the isolation threshold (70 by default) it is quarantined and all future requests — even clean ones — are refused until the session is reset. This means an attacker cannot just try one forbidden action and back off; each attempt permanently raises the risk.

**Graceful AI Fallback** — If the Ollama AI model is unavailable for any reason — still loading, timed out, or crashed — the system automatically switches to static rule-based scoring with a descriptive fallback message that includes the specific action that was blocked. Security enforcement never stops. The dashboard shows a STATIC badge instead of AI LIVE so operators can see the AI is offline.

**Live SOC Dashboard** — A real-time web dashboard shows all devices with colour-coded status cards, risk gauges, AI insight previews, global event counters, and a live scrolling event feed. Clicking on any device opens a modal with its full inbound and outbound transaction history. Expanding any row shows the raw request headers, payload, and the AI's per-packet reasoning for that specific request. Everything updates over WebSocket without any page refresh.
