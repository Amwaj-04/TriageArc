# TriageArc

**From signal to decision.**

TriageArc is an educational Security Operations Center (SOC) detection and alert-triage lab. It turns a small synthetic event dataset into explainable alerts, then lets an analyst inspect related evidence, record a verdict, and document the next action.

> **Scope:** portfolio / learning project. This is not a production SIEM, EDR, SOAR, or autonomous response system. The dataset is synthetic and the application does not execute endpoint commands or connect to real telemetry sources.

## What is included

- A browser-based SOC analyst console with overview metrics, alert queue, event explorer, and detection-rule reference.
- Light/dark theme toggle.
- Theme-aware TriageArc brand marks in the sidebar: the approved light variant in Light Mode and the dark variant in Dark Mode. Browser icons use dedicated files under `static/`; the approved brand-board reference is retained under `assets/brand/`.
- Search and filtering by alert status and severity.
- Alert investigation drawer with event timeline, host/user/source context, rationale, confidence, and MITRE ATT&CK reference.
- Analyst triage states: `NEW`, `IN_REVIEW`, `ESCALATED`, `CLOSED`.
- Verdicts: `BENIGN`, `SUSPICIOUS`, `MALICIOUS`.
- Confidence score and response/next-action note.
- Flask JSON API and SQLite data store.
- Deterministic synthetic demo scenario and automated tests.
- Windows launch and check scripts that avoid PowerShell execution-policy changes.
- Render deployment configuration.

## Detection rules

| Rule | Detection | Severity | MITRE ATT&CK |
|---|---|---|---|
| `AUTH-001` | Five or more failed logins for the same user and source within 10 minutes | High | T1110.001 — Password Guessing |
| `AUTH-002` | Successful login after at least three failures from the same source within 15 minutes | High | T1078 — Valid Accounts |
| `PROC-001` | Explicit suspicious PowerShell command-line indicators | High | T1059.001 — PowerShell |
| `IAM-001` | New account receives administrative privilege within 30 minutes | Critical | T1098 — Account Manipulation |
| `DATA-001` | Sensitive file accessed from an unexpected synthetic workstation | Medium | T1005 — Data from Local System |

The rules are deterministic heuristics, not proof that an action is malicious. Alert severity and confidence are educational values and should not be treated as calibrated production risk scores.

## Run on Windows (recommended)

**Requirements:** Python 3.11 or newer and an internet connection for the first dependency installation.

1. Extract the full `TriageArc` folder to a normal writable location, for example `Downloads` or `Documents`.
2. Double-click **`START_TRIAGEARC.bat`**.
3. Wait for the setup to finish. The browser should open at `http://127.0.0.1:5000`.
4. Keep the black terminal window open while using the app. Press `Ctrl+C` in that window to stop it.

The launcher creates a project-local `.venv`, installs the packages from `requirements.txt`, and starts the web app. On first run, the app automatically loads the synthetic demo dataset only if the database is empty; restarting the app does not intentionally erase analyst decisions. It does not require running PowerShell as Administrator or changing the execution policy. The first launch needs network access so pip can download the packages.

To run checks later, double-click **`CHECK_TRIAGEARC.bat`**. It compiles the Python files and runs the automated tests. It requires the virtual environment to have been created first.

### If the launcher cannot find Python

Install Python 3.11+ from [python.org](https://www.python.org/downloads/windows/). During installation, enable the option to add Python to PATH, then reopen the folder and run the launcher again.

### Manual Windows commands (alternative)

Open PowerShell in the project folder and run these one at a time:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

No activation command is needed, so PowerShell execution policy does not need to be changed.

## Publish to GitHub

1. Create a **public** GitHub repository named `TriageArc` (unless you prefer to keep it private until review).
2. Upload the **contents of this folder**, not the ZIP file itself. Include `app.py`, `database.py`, `engine.py`, `rules.py`, `seed.py`, `schema.sql`, `templates/`, `static/`, `tests/`, `requirements.txt`, `render.yaml`, both `.bat` files, and this README.
3. Do **not** upload `.venv/`, `__pycache__/`, or `data/triagearc.db`. These are local generated files and are excluded by `.gitignore`.
4. After upload, confirm the repository root directly contains `app.py`, `requirements.txt`, `render.yaml`, `templates/`, and `static/`.

## Deploy on Render

The included `render.yaml` defines a Python web service.

1. Sign in to Render and choose **New → Web Service**.
2. Connect the `TriageArc` GitHub repository.
3. If Render asks for commands, use:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app:app --bind 0.0.0.0:$PORT`
4. Deploy and wait for the health check at `/api/health` to pass.

**Deployment note:** the default SQLite database lives inside the app folder. On hosts with an ephemeral filesystem, demo data and analyst changes may reset after a redeploy or restart. That is acceptable for this learning demo; do not use this default storage setup for real incident records. A persistent database would be required for production use.

## API reference

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/` | SOC analyst console |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/events` | Synthetic event records |
| `GET` | `/api/alerts` | Alert queue |
| `GET` | `/api/alerts?status=NEW` | Filter alerts by status |
| `GET` | `/api/alerts/<alert_uid>` | Alert plus linked evidence events |
| `POST` | `/api/alerts/<alert_uid>/triage` | Save analyst state, verdict, confidence, and note |
| `GET` | `/api/stats` | Summary counts |
| `POST` | `/api/demo/run` | Reset and reload deterministic synthetic scenario (clears analyst decisions) |
| `POST` | `/api/demo/reset` | Reset local demo data and analyst decisions |

Example triage JSON:

```json
{
  "status": "IN_REVIEW",
  "verdict": "SUSPICIOUS",
  "confidence": 90,
  "response_note": "Review adjacent authentication events and confirm whether the login was expected."
}
```

## Project layout

```text
TriageArc/
├── app.py                 # Flask app and API routes
├── database.py            # SQLite connection lifecycle and helpers
├── engine.py              # Alert persistence, retrieval, and triage
├── rules.py               # Detection logic and MITRE mappings
├── seed.py                # Synthetic training events
├── schema.sql             # Database schema and indexes
├── templates/index.html   # Analyst console
├── static/styles.css      # Responsive visual system and themes
├── static/triagearc-mark.png       # Dark-mode brand mark
├── static/triagearc-mark-light.png # Light-mode brand mark
├── static/favicon.ico              # Browser favicon
├── static/triagearc-favicon-32.png # 32px browser icon
├── static/triagearc-icon-192.png   # App icon
├── static/apple-touch-icon.png     # Apple touch icon
├── assets/brand/                   # Approved brand reference board
├── static/app.js          # Console interactions
├── tests/                 # Unit and API tests
├── START_TRIAGEARC.bat    # Windows setup and launcher
├── CHECK_TRIAGEARC.bat    # Windows validation script
├── requirements.txt
├── requirements-dev.txt
├── render.yaml
└── README.md
```

## Testing and known boundaries

Run tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests cover detection thresholds and correlation, API responses, event evidence, and invalid triage input. The `check_foundation.py` script provides an additional deterministic check for the expected 13 events and five detections.

Current boundaries: the lab does not ingest real Windows Event Logs or Sysmon, does not query external threat intelligence, and does not execute containment actions. The sensitive-file rule uses a deliberately small synthetic host mapping. Those constraints are stated explicitly to keep the project credible and explainable in a portfolio review.

## Portfolio positioning

**TriageArc** demonstrates detection logic, evidence correlation, triage state management, analyst notes, and MITRE ATT&CK awareness. **SentinelTrail** focuses on evidence integrity and incident investigation. Together they illustrate complementary defensive-security workflows without presenting either project as a commercial SIEM.
