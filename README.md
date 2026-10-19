# CyberDefense-AI

CyberDefense-AI is a local-first, full-stack security monitoring and analysis platform. It combines a React dashboard with a Python API, SQLite storage, trained file and network classifiers, host-visible network capture, honeypot decoys, incident records, and optional threat-intelligence and blockchain integrations.

It has two distinct workspaces:

- **SOC workspace** — network activity, threats, incidents, analytics, investigations, and administration.
- **Ransomware workspace** — the earlier ransomware/file-scanning dashboard and its scan history.

The application is a defensive learning and monitoring project, not an endpoint protection product or a substitute for a production SOC. Detection is limited to data the host can actually observe and the installed models can process. A model prediction is evidence for analyst review, not proof that an attack occurred.

## Contents

1. [What the application does](#what-the-application-does)
2. [Workspaces and pages](#workspaces-and-pages)
3. [How data moves through the system](#how-data-moves-through-the-system)
4. [Live network capture and model verification](#live-network-capture-and-model-verification)
5. [File and ransomware scanning](#file-and-ransomware-scanning)
6. [Events, incidents, and risk scores](#events-incidents-and-risk-scores)
7. [Cyber Lab simulations](#cyber-lab-simulations)
8. [Honeypot, evidence, and integrations](#honeypot-evidence-and-integrations)
9. [Requirements and setup](#requirements-and-setup)
10. [Configuration](#configuration)
11. [Running and using the application](#running-and-using-the-application)
12. [API and real-time events](#api-and-real-time-events)
13. [Data, privacy, and security](#data-privacy-and-security)
14. [Troubleshooting](#troubleshooting)
15. [Tests and development](#tests-and-development)
16. [Repository map](#repository-map)
17. [Known limitations](#known-limitations)

## What the application does

| Capability | Input | Output |
| --- | --- | --- |
| File threat scan | Uploaded PE file or extracted PE features | Benign, suspicious, or ransomware classification, score, feature summary, and persisted scan record |
| Live network analysis | Packets visible to the selected host adapter | Parsed packet/flow rows and, when the trained classifier can verify a flow, a model-verified network alert |
| OS connection monitoring | Connections visible to the local operating system | Host connection and network-activity context; this is not packet capture |
| Security events and incidents | File, honeypot, network, and simulation telemetry | Stored records and analyst-facing incident views |
| Cyber Lab | An explicitly enabled scenario | Clearly labeled synthetic events for exercising the Lab/SOC display |
| Enrichment and response support | An IP, file hash, or incident | Optional external lookups, investigation context, evidence bundle, and integrity checks |

The app keeps several concepts separate:

- **Packets** are observations emitted by packet capture.
- **Flows** summarize packets by network endpoints and protocol for model input.
- **Verified network alerts** require a valid trained network-model result. A rule candidate alone is not a confirmed attack.
- **File predictions** come from the ransomware/file classifier and are separate from the network classifier.
- **Simulation events** are manufactured test telemetry. They do not become captured packets or verified live network attacks.

## Workspaces and pages

The workspace switcher lets an analyst move between the SOC dashboard and the ransomware center.

### SOC workspace

- **SOC Dashboard (`/`)** — high-level security activity, alerts, health, and links to investigations.
- **SOC War Room (`/soc`)** — operational event and incident view.
- **Network (`/network`)** — packet capture status, network flows, and verified network alerts.
- **Threats (`/threats`)** — file scan history and threat results.
- **Analytics (`/analytics`)** — summaries and charts based on stored data.
- **Incidents (`/incidents`)** — incident list and scenario context.
- **Incident detail (`/incidents/:id`)** — incident overview, attacker context, investigation, timeline, attack graph, evidence, and replay views.
- **Cyber Lab (`/lab`)** — controlled synthetic scenarios, mode control, logs, honeypot activity, and stop/reset controls.
- **Blockchain (`/blockchain`)** — blockchain status, recorded entries, and verification tools when the integration is configured.
- **Audit Log (`/audit`)** — recorded user and system actions.
- **Chat (`/chat`)** — AI-assisted analyst chat when a supported provider key is configured.
- **Admin (`/admin`)** — user and system administration; restricted to the admin role.

### Ransomware workspace

- **Ransomware Center (`/ransomware`)** — the dedicated ransomware/file-analysis dashboard.
- **Ransomware History (`/ransomware-history`)** — stored ransomware-related scan records.

The SOC and ransomware pages share the application's backend and scan database. The workspace switcher separates the interfaces; it does not create separate application installations or databases.

## How data moves through the system

```text
Wireshark TShark + Npcap
        │ observed packets
        ▼
Flow extractor ──► Trained network IDS ──► verified live flow / alert
        │                                      │
        └────────► packet and flow views        ├──► in-memory live metrics
                                               └──► real-time dashboard events

Uploaded PE or watched-file activity
        │
        ▼
PE feature extraction ──► file threat scorer ──► scan record / threat event

Real security telemetry ──────────────┐
Synthetic Cyber Lab events ───────────┼──► security-event / incident handling
Honeypot activity ────────────────────┘       │
                                               ├──► SQLite history
                                               ├──► WebSocket UI updates
                                               └──► optional enrichment/evidence integrations
```

The live packet path and simulation path are intentionally independent. A simulation can create an incident or event visible in the application while no corresponding network packet exists. For classifying traffic generated by a test tool as a **real network flow**, run the test over the captured adapter and let the live capture/model pipeline observe it; the scenario endpoint itself does not inject traffic.

The Flask application serves the JSON API on port `5000` and uses Flask-SocketIO for real-time updates. The React/Vite frontend calls the API and subscribes to socket events. Most dashboard data is loaded through authenticated API requests; live events are pushed to connected clients as they occur.

## Live network capture and model verification

### Capture path

1. The backend discovers TShark interfaces and attempts to start capture automatically on the interface matching a local IP.
2. TShark (Wireshark's command-line capture tool) uses Npcap on Windows to read traffic visible to that adapter.
3. Parsed IPv4/IPv6 packet fields are passed to the flow extractor.
4. The extractor groups packets into bidirectional flows and produces the features named by the saved network-model metadata.
5. The trained network IDS classifies each completed flow.
6. The app records flows and only creates a **confirmed live network attack** when the trained model is available, inference succeeds, required features are valid, the predicted class is non-benign, and confidence is at least 70%.
7. Repeated alerts for the same flow/class are throttled; the dashboard receives updates through the API and WebSocket.

When the model is missing, required features are absent or invalid, or inference fails, the result is unverified. It must not be treated as a confirmed attack. A normal prediction is not an attack. A rule-based scan/connection heuristic may be useful context, but does not replace the trained-model gate.

### What Wi-Fi capture can and cannot see

- Capture is from the host's selected network interface. On ordinary Wi-Fi client mode this generally means traffic visible to this computer, not every device communicating through the access point.
- Promiscuous mode does not by itself provide 802.11 monitor-mode visibility or decrypt other clients' Wi-Fi traffic.
- Encrypted application payloads usually remain encrypted; the app can still display packet metadata such as endpoints, ports, protocol, length, and timing.
- IPv6 endpoints are supported when the capture tool supplies the required fields. Ports are displayed alongside IP addresses where available.
- Seeing an endpoint IP does not automatically provide a reliable owner, city, ISP, or organization. Private, reserved, local, and unsupported addresses may have no useful public geolocation.

### Packet capture prerequisites

- Install Wireshark with TShark and Npcap. Confirm `tshark -D` lists the adapter you intend to use.
- On Windows, run the backend with the privileges required by Npcap/capture configuration. The repository includes `backend/start_admin.bat` to request an elevated prompt.
- Select the correct adapter in the Network page if automatic selection does not start capture.
- Check `/api/capture/status` or the Network page for capture state, packet count, and selected interface.
- OS connection monitoring can provide a fallback view when packet capture is unavailable. It does **not** produce packet rows or trained-model flow confirmations.

## File and ransomware scanning

The file scanner uses features extracted from Windows PE files. The feature schema currently includes fields such as machine type, image/linker versions, sections, imports/exports, resources, stack reserve, DLL characteristics, and a Bitcoin-address indicator. Files that are not valid or parseable PE inputs may fail feature extraction.

The backend combines the available file-classification models and returns:

- `prediction`: `Benign`, `Suspicious`, or `Ransomware`;
- `threat_score` and `risk_level`;
- model confidence fields when available;
- a short feature-based explanation and hash;
- MITRE ATT&CK mappings where applicable.

The file classifier is not the same model as the live network IDS. Upload scans are persisted in SQLite and may produce SOC feed events. Optional notifications and AI summaries depend on configuration and service availability. Scores are model outputs and should be reviewed with the source file and context; they are not a guarantee of malware or safety.

## Events, incidents, and risk scores

The backend stores file scan history, unified security events, honeypot triggers, simulation logs, audit events, network audit entries, and incident records in SQLite. Some live packet/flow counters are held in memory and can reset when the backend restarts.

An incident is an analyst-oriented record that can aggregate source/destination context, severity, risk factors, timeline entries, files, honeypot activity, model fields, and optional enrichment/evidence. The existence of an incident does not mean every field was observed directly: simulation events are labeled by `scenario_id`, and unavailable enrichment fields can remain unknown.

The risk scorer combines configured signal categories including model/file analysis, file activity, honeypot interaction, network signal, process context, and correlation. Its output is a 0–100 prioritization score with contributing factors. It is not a calibrated probability that an attack occurred.

## Cyber Lab simulations

Cyber Lab scenarios exercise UI, event storage, and incident handling using **synthetic telemetry**. They do not scan or attack a real host, generate packets, or pass synthetic network flows to the trained packet-flow model.

Simulation mode is off by default for each backend process. An authenticated user must enable **SIMULATION MODE** in the Cyber Lab before starting a scenario. The API validates the scenario against an allowlist and allows only one running scenario at a time. Stop requests cancel the running scenario cooperatively.

Available scenario IDs:

| Scenario | Behavior |
| --- | --- |
| `ransomware` | Writes synthetic demo files and a simulation ransom note under `backend/watched/`; it does not encrypt personal files. |
| `portscan` | Emits synthetic port-scan events; does not probe real ports. |
| `brute-force` | Emits synthetic authentication-attempt events; does not attempt real logins. |
| `phishing` | Emits synthetic phishing-chain events and may write a demo file under `backend/watched/`; it does not send email or contact a command server. |
| `suspicious-process` | Emits synthetic process telemetry; it does not launch a real malicious process. |
| `data-exfiltration` | Emits synthetic data-transfer telemetry; it does not upload local data. |
| `honeypot` | Records simulated access to decoy resources. |
| `full-attack` | Runs a multi-stage synthetic event sequence. |

Scenario events can appear in Lab/SOC event or incident views because the UI is intended to demonstrate event handling. A scenario is **not** evidence that the same attack happened on the network. Keep the simulation labels and `scenario_id` when interpreting or exporting data.

To inspect or remove files created by the ransomware/phishing demonstrations, review only the explicitly named synthetic files under `backend/watched/`. Do not treat that directory as a general cleanup target; it may contain files monitored by the application.

## Honeypot, evidence, and integrations

### Honeypot

The backend creates decoy documents under `backend/lab/honeypot/`. Their contents are fake and intended only for monitoring. A Watchdog observer looks for file activity and records observed triggers. Cyber Lab can also record scenario-tagged, simulated honeypot interactions; these are different from a real filesystem access.

### Incident evidence

Evidence utilities can serialize incident context, associated events, hashes, and response information into local JSON bundles under `backend/evidence/`. The bundle is SHA-256 hashed and can be checked for integrity. Blockchain anchoring is optional and depends on a correctly configured provider and contract. A hash proves equality with the recorded content, not that the original observation was accurate.

### Optional integrations

- **IP geolocation and reputation** — external lookups can enrich public IPs when the relevant service and key are available.
- **Shodan / VirusTotal / AbuseIPDB** — optional lookups for IP or file-hash context; quotas and coverage are controlled by those services.
- **AI chat and summaries** — use a configured provider such as Gemini, Groq, or OpenAI; without a valid key these features may be unavailable.
- **Email and webhooks** — optional notifications; configure only if needed.
- **Blockchain** — Web3 logging/verification can use Core Testnet2 or another supported RPC/contract configuration. Testnet records are not production evidence storage.

External lookups may be unavailable, rate-limited, or incomplete. Never interpret missing enrichment as evidence that an IP or file is safe.

## Requirements and setup

### Prerequisites

- Windows, macOS, or Linux with Python **3.10+** and Node.js **18+**.
- Git and npm.
- Wireshark/TShark and Npcap are required only for packet-level capture. Install the Npcap driver during Wireshark setup on Windows.
- A working trained-model asset set under `backend/models/` is required for the corresponding ML features. Optional DNN support depends on a compatible PyTorch installation and runtime libraries.

### Install the backend

From the repository root in PowerShell:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item example.env .env
```

Edit `backend/.env` with a unique `SECRET_KEY` and any optional integration settings. Do not commit `.env` or put actual private keys into documentation, issue reports, or source files.

### Install the frontend

Open a second terminal at the repository root:

```powershell
cd frontend
npm install
```

The frontend API client currently targets `http://localhost:5000/api`. Keep the backend on that address/port for the default local development setup.

## Configuration

`backend/example.env` documents the supported settings. Only configure services you intend to use.

| Setting | Purpose |
| --- | --- |
| `SECRET_KEY` | Signs session JWTs. Set a long, random value before use. |
| `ETH_RPC_URL`, `CONTRACT_ADDRESS`, `WALLET_PRIVATE_KEY`, `CHAIN_ID` | Optional blockchain RPC and contract access. Never expose or commit the private key. |
| `GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENAI_API_KEY` | Optional AI chat/summary provider credentials. |
| `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY` | Optional threat-intelligence API credentials. |
| `EMAIL_ENABLED`, `EMAIL_SENDER`, `EMAIL_PASSWORD`, `EMAIL_RECEIVER` | Optional email alerts. For Gmail, use an app password rather than an account password. |
| `WEBHOOK_URL` | Optional Slack/Discord-compatible alert webhook. Treat the URL as a secret. |
| `IPINFO_TOKEN` | Optional geolocation provider token where supported. |

Environment variable names and optional integrations can vary as modules evolve. Use `backend/example.env` as the authoritative template and check backend startup output and the health/status pages to confirm a component actually initialized.

## Running and using the application

### Start the backend

In the backend virtual environment:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python app.py
```

Backend API: `http://localhost:5000`

For Windows packet capture, open an elevated terminal and run:

```powershell
cd backend
.\start_admin.bat
```

The batch file activates `backend/venv` and starts the backend. If that environment is not installed, create it and install `requirements.txt` first.

### Start the frontend

In a second terminal:

```powershell
cd frontend
npm run dev
```

Open the Vite URL printed by the command (normally `http://localhost:5173`). Sign in, then use the workspace switcher to navigate between the SOC and Ransomware Center.

### Verify the installation

1. Confirm the backend reports that SQLite initialized and inspect its startup output for missing model/capture/integration warnings.
2. Open `http://localhost:5000/api/health` to check basic backend availability.
3. Sign in through the frontend and inspect the component health and Network capture status.
4. For real packet capture, confirm that the correct adapter is listed and capture is active before expecting packet rows.
5. To test the Cyber Lab, enable Simulation Mode, start one scenario, and verify that events carry a simulation scenario ID.
6. Use the Ransomware Center for file scans; the Lab ransomware scenario is only a synthetic demonstration and is not the uploaded-file scan workflow.

### Development build

```powershell
cd frontend
npm run build
```

## API and real-time events

The API base is `http://localhost:5000/api`. Login returns a bearer JWT; protected endpoints expect:

```http
Authorization: Bearer <token>
```

The token expires after eight hours in the current implementation. The frontend stores the session locally for development use.

| Area | Endpoint examples |
| --- | --- |
| Authentication | `POST /login`, `GET /verify-token` |
| File analysis | `POST /upload-scan`, `POST /predict`, `GET /threats`, `GET /stats` |
| System health | `GET /health`, `GET /system/health`, `GET /system/status` |
| Capture and network | `GET /interfaces`, `POST /capture/start`, `POST /capture/stop`, `GET /capture/status`, `GET /flows`, `GET /alerts`, `GET /attackers`, `GET /network/stats`, `GET /network/packets` |
| Events and incidents | `GET /events`, `GET /incidents`, `GET /incidents/<id>` and incident investigation/evidence/replay/attack-graph routes |
| Honeypot | `GET /honeypot/status`, `GET /honeypot/files`, `GET /honeypot/triggers` |
| Cyber Lab | `GET/POST /lab/mode`, `POST /lab/simulate`, `GET /lab/status`, `POST /lab/stop`, `POST /lab/reset`, `GET /lab/logs/<scenario_id>` |
| Enrichment and evidence | `/geo/<ip>`, `/intel/...`, `/evidence`, `/evidence/verify`, `/risk-score` |
| Admin | `/admin/...` routes for user and system administration |

Most operational endpoints require authentication; `/health` is a basic unauthenticated liveness check. Consult `backend/app.py` for exact methods, parameters, authorization, and response shapes.

Flask-SocketIO emits event types including `security_event`, `soc_update`, `live_incident`, `alert_created`, `network_alert`, `attacker_update`, `capture_status`, `sim_log`, and `honeypot_triggered`. Payload details depend on the event source. A `scenario_id` means the event came from a lab scenario and must not be confused with a live packet capture.

## Data, privacy, and security

- The app stores its SQLite database at `backend/cyberdefense.db`; evidence, watched files, honeypot data, and logs are stored in backend-local directories.
- Network capture, uploaded files, event metadata, and external IP/hash lookup requests may contain sensitive data. Run only on systems and networks you are authorized to monitor.
- Live flows and some metrics are held in process memory; restarting the backend can clear those in-memory views. SQLite-backed threat/event records persist locally.
- The backend binds to `0.0.0.0` in its current run configuration. Keep it on a trusted network, apply firewall rules, and do not expose the development server directly to the public internet.
- The default development accounts are seeded only when the users table is empty: `admin` / `admin123` and `analyst` / `analyst123`. Change/remove defaults before using the app beyond a disposable local demo.
- Set a strong `SECRET_KEY`; the backend has a development fallback if it is missing. Do not rely on that fallback for any shared or deployed environment.
- Do not enable optional integrations unless required. API keys, blockchain signing keys, webhook URLs, and email credentials must remain private.
- Simulation mode controls synthetic scenario starts; it does not toggle or disable the live capture pipeline.

## Troubleshooting

### Frontend stays on a loading screen

- Confirm the backend is running on `localhost:5000` and `/api/health` responds.
- Check the browser developer console and network panel for API errors.
- Confirm a token exists and is valid; sign out and back in if it has expired.
- Dashboard data requests have a finite timeout, but the browser cannot display live data if the backend is stopped or the API URL is incorrect.

### No packets or live traffic

- Check the Network page and `/api/capture/status`; `is_capturing` should be true and packet count should increase.
- Run `tshark -D` to check that TShark can list interfaces. Ensure the selected interface is the active Wi-Fi/Ethernet adapter, not a disconnected VPN or loopback interface.
- On Windows verify Npcap is installed, capture permissions are sufficient, and the backend was started elevated if required.
- Generate ordinary traffic from the same host to check host-visible capture. Other Wi-Fi clients' traffic is not generally visible in normal client mode.
- If capture is unavailable, the OS-connection fallback is not equivalent to packet capture; it will not supply packet rows or flow-model confirmations.
- Review backend logs for TShark executable, adapter, access, or model-feature errors.

### No model-verified network alerts

- Confirm the trained network RF/scaler/label-encoder files and `network_model_info.json` are present and compatible in `backend/models/`.
- Check model status and startup logs. An unavailable optional DNN does not necessarily mean RF is unavailable, but a missing or incompatible required classifier does.
- The flow must contain the complete feature schema, be classed as non-benign, and meet the 70% confidence gate. Benign traffic and incomplete/low-confidence flows correctly do not create confirmed alerts.

### Cyber Lab cannot start a scenario

- Sign in and switch **SIMULATION MODE** on in the Lab page.
- Confirm the backend is running the current code; the mode flag is process-local and resets when the backend restarts.
- Only one scenario may run at a time. Stop it and wait for status to clear before starting another.
- Use one of the scenario IDs in the [Cyber Lab table](#cyber-lab-simulations). The endpoint rejects unknown scenario types.
- Lab simulations create synthetic events and do not create Wi-Fi packets or model-verified network detections.

### Geolocation or threat intelligence displays unknown/unavailable

- Private or local IP addresses are not publicly geolocatable.
- Public-IP enrichment needs network connectivity and may require the provider API key. Providers can rate-limit requests or have incomplete records.
- Unknown fields should remain unknown rather than be interpreted as a confirmed identity.

### Blockchain, email, or AI unavailable

- These are optional components. Check `.env` values, backend startup messages, provider/network availability, and service quotas.
- Testnet writes require a funded test wallet and a compatible contract configuration. Never use a production wallet key in a local demo.

## Tests and development

Run the backend regression tests from the repository root:

```powershell
python -m unittest backend.tests.test_network_verification backend.tests.test_attack_director
```

Compile the changed/backend Python modules:

```powershell
python -m py_compile backend\app.py backend\utils\attack_director.py
```

Build the frontend:

```powershell
cd frontend
npm run build
```

Tests cover network feature extraction and verification guards as well as simulation scenario state/stop behavior. A passing test suite does not validate capture visibility on a particular adapter, external service access, model quality on new traffic, or blockchain connectivity.

## Repository map

```text
backend/
  app.py                    Flask API, auth, initialization, capture wiring, event callbacks
  cyberdefense_cli.py       Command-line client for the Cyber Lab API
  models/
    threat_scorer.py        PE/ransomware classifier
    network_scorer.py       Trained network-flow classifier and verification gate
    network_monitor.py      OS connection monitoring and candidate detection
    file_monitor.py         PE feature extraction and watched-directory monitoring
    *.pkl, *.pth, *.json    Trained models, encoders, metadata, feature lists
  tests/                    Focused backend regression tests
  utils/
    attack_director.py      Synthetic lab scenarios
    db.py                   SQLite persistence and user/audit helpers
    event_schema.py         Unified security-event representation
    flow_extractor.py       Packet-to-flow feature generation
    forensic_evidence.py    Local evidence bundle/hash utilities
    honeypot.py             Decoy setup, watcher, and trigger storage
    incident_manager.py     Incident lifecycle and persistence
    risk_scorer.py          Explainable signal-based risk score
    threat_intel.py         Optional IP/hash enrichment
    tshark_capture.py       TShark capture process and packet parsing
frontend/
  src/App.jsx               Routes, login/session gate, admin gate
  src/api.js                HTTP client and API wrappers
  src/components/           Shared workspace and incident components
  src/pages/                SOC, Network, Lab, incidents, ransomware, and other pages
  package.json              Vite scripts and frontend dependencies
read.md                     This detailed operator and architecture guide
```

## Known limitations

- Packet visibility depends on the operating system, interface, Npcap/TShark permissions, network topology, and Wi-Fi adapter mode.
- The live network model uses the feature schema recorded in its metadata. Training/evaluation metrics describe a dataset run, not guaranteed field accuracy.
- The file classifier is specific to its PE feature representation; it does not inspect every file type or prove whether arbitrary content is safe.
- Geolocation and external intelligence are best-effort, optional, and subject to provider coverage and rate limits.
- Some dashboards mix persistent historical records with process-local live state; restarting the backend can change what appears in live counters.
- Cyber Lab output is generated telemetry. It is useful for checking the event/incident presentation path but does not validate packet capture or the network classifier.
- This repository is a development application. Review authentication, password handling, CORS, secrets, logging, and deployment configuration before any production or multi-user exposure.
