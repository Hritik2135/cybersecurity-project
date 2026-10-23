# 🛡️ Mini-SIEM Lab

> A single-file Python Security Information & Event Management (SIEM) simulator  
> inspired by Wazuh SIEM cluster log aggregation and alert dashboards.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.66%2B-red?style=flat-square&logo=streamlit)
![Plotly](https://img.shields.io/badge/Plotly-7.1%2B-blue?style=flat-square&logo=plotly)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-10%2F10%20Passed-brightgreen?style=flat-square)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Dashboard Pages](#dashboard-pages)
- [Log Sources](#log-sources)
- [Alert Rules](#alert-rules)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Testing](#testing)
- [Screenshots Guide](#screenshots-guide)
- [Known Limitations](#known-limitations)

---

## Overview

**Mini-SIEM Lab** demonstrates every layer of a production SIEM system in a single Python file:

| Layer | Component |
|---|---|
| **Log Collection** | 6 synthetic log generators (sshd, apache, iptables, sudo, useradd, auditd) |
| **Aggregation & Storage** | SQLite database with WAL concurrency + 7 indexes |
| **Correlation Engine** | 12 regex-based alert rules, 1 stateful brute-force rule |
| **Dashboard** | 7-page Streamlit UI with 15+ Plotly charts |
| **Live Mode** | Background daemon thread + auto-refresh UI loop |

Prepared by **Hritik Kumar Prajapati**. The entire application lives in **one file** — `Hritik_Kumar_Prajapati_mini_siem.py` (~1,631 lines, fully commented).

---

## Features

### 🔄 Live Mode
A background daemon thread ingests **15 logs every 10 seconds** and the dashboard auto-refreshes — simulating a real SOC display with no manual interaction.

### 🔔 Alert Rules Engine
- **12 detection rules** mapped to MITRE ATT&CK technique IDs
- **Stateful rule** — SSH Brute Force fires only after **≥ 3 failures from the same IP within 60 seconds** (rolling time window, thread-safe)
- **Stateless rules** — fire on first regex match against the raw log line

### 📊 Interactive Dashboard
- 7-column KPI bar with **+N /min** live rate indicators
- Log volume timeline with attack overlay
- Severity-categorised alerts table (5 tabs: Critical / High / Medium / Low / All)
- Top 10 attacker IPs, alerts-by-rule breakdown, MITRE ATT&CK sunburst

### 🔍 Full-Text Log Search
Regex search across all stored logs via a custom SQLite `REGEXP` user function — no pandas required.

### 🎯 Analyst Triage
Update any alert status (`OPEN → ACKNOWLEDGED → RESOLVED → FALSE_POSITIVE`) and add free-text analyst notes directly from the dashboard.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.9 or higher (3.11+ recommended) |
| streamlit | 1.66+ |
| plotly | 7.1+ |
| faker | any |

> **Note:** `pandas` and `pyarrow` are **not required**. All Plotly charts use
> `plotly.graph_objects` directly, which accepts raw Python lists with no native
> DLL dependencies.

---

## Installation

**1. Clone or download the project**

```bash
git clone https://github.com/your-username/mini-siem-lab.git
cd mini-siem-lab
```

**2. (Optional) Create a virtual environment**

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Install dependencies**

```bash
pip install streamlit plotly faker
```

---

## How to Run

```bash
streamlit run Hritik_Kumar_Prajapati_mini_siem.py
```

The app opens automatically at **http://localhost:8501**

### Quick Start

Once the app is open:

1. Click **▶️ Simulate & Ingest Logs** in the sidebar to populate data
2. Explore **📊 Dashboard** — KPI metrics, charts, and the live alerts table appear
3. Enable **🔄 Live Mode → ▶ Start** for continuous auto-ingestion and real-time refresh
4. Visit **🔔 Alerts** to triage alerts — acknowledge, resolve, or mark as false positive
5. Use **🔍 Log Search** — try regex patterns like `Failed password` or `UNION SELECT`
6. Explore **🎯 MITRE ATT&CK** for the interactive sunburst coverage map
7. Click **🗑️ Clear All Data** to reset the database and start fresh

---

## Dashboard Pages

| Page | Description |
|---|---|
| 📊 **Dashboard** | KPI bar, log timeline, severity donut, top attacker IPs, rule breakdown, severity-tabbed live alerts table |
| 🔔 **Alerts** | Filterable alert list with per-alert expanders for analyst triage (status + notes) |
| 🔍 **Log Search** | Full-text regex search with source / severity / agent filters |
| 🖥️ **Agents** | Per-agent metrics, alert breakdown charts, log-source heatmap |
| 📋 **Detection Rules** | All 12 rules sorted by severity — description, pattern, MITRE ID, hit count |
| 🎯 **MITRE ATT&CK** | Sunburst chart (technique → rule → count) + tabular breakdown |
| 📈 **Analytics** | Hourly event/alert trend, threat intel top-IPs, log distribution pie charts |

---

## Log Sources

| Source | Format | Agent(s) |
|---|---|---|
| `sshd` | OpenSSH auth log | auth-server-01, endpoint-win-01 |
| `apache` | Apache Combined Log Format (CLF) | web-server-01, endpoint-win-01 |
| `iptables` | Linux netfilter kernel log | web-server-01, db-server-01, firewall-01 |
| `sudo` | sudo syslog line | all except firewall-01 |
| `useradd` | useradd syslog entry | auth-server-01, db-server-01 |
| `auditd` | Linux Audit daemon syscall record | web-server-01, db-server-01, auth-server-01, endpoint-win-01 |

### Simulated Agents

| Agent ID | Hostname | OS | Role |
|---|---|---|---|
| agent-001 | web-server-01 | Ubuntu 22.04 | Web Server |
| agent-002 | db-server-01 | CentOS 8 | Database |
| agent-003 | firewall-01 | pfSense 2.7 | Firewall |
| agent-004 | auth-server-01 | Debian 11 | Auth/LDAP |
| agent-005 | endpoint-win-01 | Windows 11 | Workstation |

---

## Alert Rules

| ID | Rule Name | Source | Severity | MITRE | Type |
|---|---|---|---|---|---|
| R001 | SSH Brute Force | sshd | 🟠 HIGH | T1110.001 | Stateful (≥3/60s) |
| R002 | Root Login Attempt | sshd | 🔴 CRITICAL | T1078.003 | Stateless |
| R003 | SQL Injection Attempt | apache | 🔴 CRITICAL | T1190 | Stateless |
| R004 | Port Scan Detected | iptables | 🟠 HIGH | T1046 | Stateless |
| R005 | Privilege Escalation via sudo | sudo | 🟡 MEDIUM | T1548.003 | Stateless |
| R006 | Reverse Shell / C2 Pattern | iptables | 🔴 CRITICAL | T1059 | Stateless |
| R007 | Web Directory Enumeration | apache | 🟡 MEDIUM | T1595.003 | Stateless |
| R008 | New User Account Created | useradd | 🟡 MEDIUM | T1136.001 | Stateless |
| R009 | Large Data Exfiltration | iptables | 🟠 HIGH | T1030 | Stateless |
| R010 | Firewall REJECT Triggered | iptables | 🟠 HIGH | T1562.004 | Stateless |
| R011 | Sensitive File Access | auditd | 🟠 HIGH | T1003.008 | Stateless |
| R012 | Executable Written to /tmp | auditd | 🔴 CRITICAL | T1059 | Stateless |

### Stateful SSH Brute Force (R001)

Rule R001 uses a **rolling time-window counter** per source IP:

```
IP A → fail #1  (no alert)
IP A → fail #2  (no alert)
IP A → fail #3  → 🔔 HIGH alert fires
IP A → fail #4  → 🔔 HIGH alert fires (still above threshold)

After 60 seconds of no failures from IP A → counter resets
```

Thread-safe via `threading.Lock`. Resets on app restart.

---

## Project Structure

```
mini-siem-lab/
│
├── Hritik_Kumar_Prajapati_mini_siem.py   # Complete application — single file (~1,631 lines)
├── test_siem.py               # Headless validation test suite (10 tests)
├── README.md                  # This file
│
└── mini_siem.db               # SQLite database (auto-created on first run)
```

### Inside `Hritik_Kumar_Prajapati_mini_siem.py`

```
Hritik_Kumar_Prajapati_mini_siem.py
│
├── CONSTANTS & CONFIGURATION       # DB path, severity colours, agent profiles
├── STATEFUL SSH BRUTE-FORCE TRACKER # Rolling window + threading.Lock
├── ALERT RULES                     # 12 rules list (R001–R012)
├── DATABASE LAYER                  # get_conn(), init_db(), query(), scalar()
├── PLOTLY HELPER                   # rows_to_lists() — no pandas needed
├── LOG SIMULATION ENGINE           # _gen_ssh(), _gen_apache(), … _gen_fileaccess()
├── INGESTION PIPELINE              # simulate_logs(), _run_rules(), ingest_logs()
├── DATA HELPERS                    # get_stats(), update_alert()
├── BACKGROUND THREAD               # start_bg_simulation(), stop_bg_simulation()
├── UI HELPERS                      # _sev_badge(), _alerts_table_html()
├── DASHBOARD PAGES                 # page_dashboard() … page_analytics()
├── SIDEBAR                         # render_sidebar() — nav + controls + live mode
└── ENTRY POINT                     # main()
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│           PRESENTATION LAYER  (Streamlit UI)            │
│   7 pages · 15+ charts · analyst triage forms          │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│           CORRELATION ENGINE  (Alert Rules)             │
│   12 rules · regex match · stateful threshold          │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│           INGESTION LAYER  (simulate → ingest → rules)  │
│   6 log sources · 5 agents · background daemon thread  │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│           STORAGE LAYER  (SQLite WAL)                   │
│   logs table · alerts table · agents table             │
└─────────────────────────────────────────────────────────┘
```

---

## Testing

Run the headless test suite (no Streamlit required):

```bash
python test_siem.py
```

### Test Results

```
1.  Import: OK
2.  init_db: OK
3.  simulate_logs: OK  sources={'auditd','apache','sshd','useradd','iptables','sudo'}
    All 5 expected log sources present: OK
4.  ingest_logs: OK  (80 logs in DB)
5.  SSH brute-force threshold (3 in 60s): OK
6.  File access rules R011=7 R012=2: OK
7.  get_stats: OK  -> critical=6 high=9 medium=19
8.  Background simulation thread: OK  (82 -> 97 logs after 1 cycle)
    Thread stop: OK
9.  update_alert: OK
10. ALERT_RULES count: OK  (12 rules)

ALL 10 TESTS PASSED
```

### Syntax validation

```bash
python -m py_compile Hritik_Kumar_Prajapati_mini_siem.py
```

---

## Screenshots Guide

After running the app and simulating ~200 logs at 40% attack ratio, you will see:

- **Dashboard** — KPI bar showing total logs, open alerts broken down by severity; a blue bar chart of log volume per minute with a red attack-overlay line; a donut chart of alert severity distribution
- **Alerts** — Expandable alert cards with MITRE technique, source IP, and triage dropdowns
- **Log Search** — Try `Failed password` to find SSH failures or `UNION SELECT` for SQLi hits
- **MITRE ATT&CK** — An interactive sunburst with T1110.001, T1190, T1059, etc. sized by alert count
- **Analytics** — Stacked bar chart of alerts by severity over time

---

## Known Limitations

| Limitation | Notes |
|---|---|
| Logs are synthetic | No real syslog listener; for education / demo only |
| Brute-force tracker resets on restart | In-process memory — not persisted between runs |
| SQLite only | Not suitable for millions of events; replace with PostgreSQL for production |
| No authentication | Dashboard is open to anyone on localhost |
| Rules are hardcoded | No YAML/JSON rule loader yet |
| No alerting integrations | No email / Slack / webhook on CRITICAL alerts |

---

## Built With

- [Streamlit](https://streamlit.io/) — Web UI framework
- [Plotly](https://plotly.com/python/) — Interactive charts (graph_objects only — no pandas)
- [Faker](https://faker.readthedocs.io/) — Realistic fake data generation
- [SQLite3](https://docs.python.org/3/library/sqlite3.html) — Built-in database (stdlib)

---

*Mini-SIEM Lab — single-file Wazuh-inspired SIEM for cybersecurity learning.*
