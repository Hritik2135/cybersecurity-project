# ==============================================================================
#  Mini-SIEM Lab
#  Prepared by: Hritik Kumar Prajapati
#  Single-file Python Security Information & Event Management simulator
#  Inspired by Wazuh SIEM cluster log aggregation and alert dashboards
# ==============================================================================
#
#  PREREQUISITES
#  -------------
#  Python 3.9 or higher (3.11+ recommended)
#  Third-party packages (all pure-Python, no native DLLs):
#
#      pip install streamlit plotly faker
#
#  Built-in stdlib used:  sqlite3, random, re, threading, time, datetime,
#                         pathlib, typing  (no extra install needed)
#
# ==============================================================================
#  HOW TO RUN
#  ----------
#      streamlit run Hritik_Kumar_Prajapati_mini_siem.py
#
#  The app opens automatically at  http://localhost:8501
#  Use the sidebar to simulate logs, enable Live Mode, or clear all data.
#
# ==============================================================================
#  FEATURE OVERVIEW
#  ----------------
#  Log Sources simulated
#    sshd      - SSH login attempts (brute-force, root, successful auth)
#    apache    - HTTP access logs (SQLi payloads, 4xx/5xx errors)
#    iptables  - Firewall events (port scans, reverse shells, exfiltration)
#    sudo      - Privilege escalation commands
#    useradd   - New account creation events
#    auditd    - File access events (sensitive paths, /tmp executables)
#
#  Alert Rules Engine  (12 rules, MITRE ATT&CK mapped)
#    Stateful:  SSH Brute Force fires only after >=3 failures/IP within 60s
#    Stateless: All other rules fire on first regex match
#
#  Dashboard pages
#    [CHART]   Dashboard       - KPI metrics, log timeline, severity donut,
#                                attacker IPs, rule breakdown, live alerts table
#    [BELL]    Alerts          - Filterable alert triage with analyst notes
#    [SEARCH]  Log Search      - Full-text regex search across raw logs
#    [SCREEN]  Agents          - Per-agent metrics and log-source heatmap
#    [LIST]    Detection Rules - View all active rules with hit counts
#    [TARGET]  MITRE ATT&CK   - Sunburst coverage map
#    [TREND]   Analytics       - Hourly trends, threat intel, source distribution
#
#  Live Mode
#    A background daemon thread ingests AUTO_SIM_BATCH logs every
#    AUTO_SIM_SECS seconds. The sidebar auto-refreshes the UI on the
#    same schedule so the dashboard updates without manual interaction.
#
# ==============================================================================

import sqlite3           # built-in: local database storage
import random            # built-in: synthetic data randomisation
import re                # built-in: regex pattern matching for alert rules
import threading         # built-in: background simulation daemon thread
import time              # built-in: monotonic clock for brute-force window
from datetime import datetime, timedelta   # built-in: timestamp generation
from pathlib import Path                   # built-in: cross-platform file paths
from typing import Optional                # built-in: type hints (Python 3.9 compat)

import streamlit as st                     # UI framework - pip install streamlit
import plotly.graph_objects as go          # chart objects - no pandas required
from faker import Faker                    # realistic fake usernames / data


# ==============================================================================
#  CONSTANTS & CONFIGURATION
# ==============================================================================

# Path to the local SQLite database file (created on first run)
DB_PATH = Path("mini_siem.db")

# Maximum rows returned by any single query to keep the UI responsive
PAGE_SIZE = 50

# Background simulation: how often (seconds) the daemon ingests a new batch
AUTO_SIM_SECS = 10

# Background simulation: how many logs to generate per daemon tick
AUTO_SIM_BATCH = 15

# Canonical severity ordering (highest to lowest) used for sorting / display
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Hex colour codes for each severity level (used in charts and HTML badges)
SEVERITY_COLORS = {
    "CRITICAL": "#e63946",
    "HIGH":     "#f4a261",
    "MEDIUM":   "#e9c46a",
    "LOW":      "#2a9d8f",
    "INFO":     "#457b9d",
}

# Simulated monitoring agents - each represents a different host type
AGENT_PROFILES = [
    {"id": "agent-001", "hostname": "web-server-01",   "os": "Ubuntu 22.04", "role": "Web Server",  "ip": "10.0.1.10"},
    {"id": "agent-002", "hostname": "db-server-01",    "os": "CentOS 8",     "role": "Database",    "ip": "10.0.1.20"},
    {"id": "agent-003", "hostname": "firewall-01",     "os": "pfSense 2.7",  "role": "Firewall",    "ip": "10.0.0.1"},
    {"id": "agent-004", "hostname": "auth-server-01",  "os": "Debian 11",    "role": "Auth/LDAP",   "ip": "10.0.1.30"},
    {"id": "agent-005", "hostname": "endpoint-win-01", "os": "Windows 11",   "role": "Workstation", "ip": "10.0.2.10"},
]


# ==============================================================================
#  STATEFUL SSH BRUTE-FORCE TRACKER
#  (kept in process memory - resets when the app restarts)
# ==============================================================================

# Maps source_ip -> list of monotonic timestamps for recent failures.
# Only accessed under _ssh_fail_lock to stay thread-safe.
_ssh_fail_tracker = {}
_ssh_fail_lock = threading.Lock()

# Number of failures from the same IP within the window needed to fire R001
SSH_BRUTE_THRESHOLD = 3

# Rolling time window in seconds for counting SSH failures
SSH_BRUTE_WINDOW_SEC = 60


def _record_ssh_fail(src_ip):
    """Record one failed SSH attempt for src_ip.

    Prunes timestamps older than SSH_BRUTE_WINDOW_SEC, then appends now.

    Returns:
        True  - the failure count now meets or exceeds SSH_BRUTE_THRESHOLD
        False - threshold not yet reached; no alert should be raised.
    """
    now = time.monotonic()
    with _ssh_fail_lock:
        bucket = _ssh_fail_tracker.setdefault(src_ip, [])
        # Drop events that have fallen outside the rolling window
        bucket[:] = [t for t in bucket if now - t < SSH_BRUTE_WINDOW_SEC]
        bucket.append(now)
        return len(bucket) >= SSH_BRUTE_THRESHOLD


# ==============================================================================
#  ALERT RULES
#  Each rule is a dict with:
#    rule_id    - unique identifier (e.g. "R001")
#    name       - human-readable rule name
#    description- what the rule detects
#    pattern    - regex applied to raw_log
#    log_source - only logs from this source are evaluated
#    severity   - alert severity if the rule fires
#    mitre      - MITRE ATT&CK technique ID for context
#    stateful   - (optional) if True, uses _record_ssh_fail() threshold logic
# ==============================================================================

ALERT_RULES = [
    # -- SSH / Authentication --------------------------------------------------
    {
        "rule_id":     "R001",
        "name":        "SSH Brute Force",
        "description": ">=3 failed SSH logins from same IP within 60s",
        "pattern":     r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        "log_source":  "sshd",
        "severity":    "HIGH",
        "mitre":       "T1110.001",
        "stateful":    True,
    },
    {
        "rule_id":     "R002",
        "name":        "Root Login Attempt",
        "description": "Attempt to login as root via SSH",
        "pattern":     r"Failed password for root from (\d+\.\d+\.\d+\.\d+)",
        "log_source":  "sshd",
        "severity":    "CRITICAL",
        "mitre":       "T1078.003",
    },
    # -- Web Application -------------------------------------------------------
    {
        "rule_id":     "R003",
        "name":        "SQL Injection Attempt",
        "description": "Possible SQL injection string detected in web request",
        "pattern":     r"(UNION SELECT|OR 1=1|DROP TABLE|INSERT INTO|--\s|/\*.*\*/)",
        "log_source":  "apache",
        "severity":    "CRITICAL",
        "mitre":       "T1190",
    },
    {
        "rule_id":     "R007",
        "name":        "Web Directory Enumeration",
        "description": "High rate of 404 errors - possible dirbuster / scanner",
        "pattern":     r'"GET .+ HTTP/\d\.\d" 404',
        "log_source":  "apache",
        "severity":    "MEDIUM",
        "mitre":       "T1595.003",
    },
    # -- Firewall / Network ----------------------------------------------------
    {
        "rule_id":     "R004",
        "name":        "Port Scan Detected",
        "description": "Multiple SYN packets across different destination ports",
        "pattern":     r"SYN .+ DPT=(\d+)",
        "log_source":  "iptables",
        "severity":    "HIGH",
        "mitre":       "T1046",
    },
    {
        "rule_id":     "R006",
        "name":        "Reverse Shell / C2 Pattern",
        "description": "Suspicious outbound connection on known reverse-shell / C2 port",
        "pattern":     r"ESTABLISHED .+ DPT=(4444|1337|31337|5555|9999)",
        "log_source":  "iptables",
        "severity":    "CRITICAL",
        "mitre":       "T1059",
    },
    {
        "rule_id":     "R009",
        "name":        "Large Data Exfiltration",
        "description": "Unusually large outbound packet (LEN >= 10000) in firewall log",
        "pattern":     r"OUT=.+ LEN=(\d{5,})",
        "log_source":  "iptables",
        "severity":    "HIGH",
        "mitre":       "T1030",
    },
    {
        "rule_id":     "R010",
        "name":        "Firewall REJECT Rule Triggered",
        "description": "Traffic matched a REJECT rule - blocked intrusion attempt",
        "pattern":     r"REJECT .+ PROTO=TCP",
        "log_source":  "iptables",
        "severity":    "HIGH",
        "mitre":       "T1562.004",
    },
    # -- Privilege / Account ---------------------------------------------------
    {
        "rule_id":     "R005",
        "name":        "Privilege Escalation via sudo",
        "description": "User executed a command as root via sudo",
        "pattern":     r"sudo:.+COMMAND=(.+)",
        "log_source":  "sudo",
        "severity":    "MEDIUM",
        "mitre":       "T1548.003",
    },
    {
        "rule_id":     "R008",
        "name":        "New User Account Created",
        "description": "A new local user account was added to the system",
        "pattern":     r"new user: name=(\w+)",
        "log_source":  "useradd",
        "severity":    "MEDIUM",
        "mitre":       "T1136.001",
    },
    # -- File Integrity / Auditd -----------------------------------------------
    {
        "rule_id":     "R011",
        "name":        "Sensitive File Access",
        "description": "Read/write access detected on a sensitive system file",
        "pattern":     r"(READ|WRITE|OPEN).+(/etc/shadow|/etc/passwd|/etc/sudoers|\.ssh/authorized_keys|/root/)",
        "log_source":  "auditd",
        "severity":    "HIGH",
        "mitre":       "T1003.008",
    },
    {
        "rule_id":     "R012",
        "name":        "Executable Written to /tmp",
        "description": "A script or binary was written to /tmp - possible malware drop",
        "pattern":     r"WRITE.+/tmp/.+\.(sh|py|elf|bin|exe)",
        "log_source":  "auditd",
        "severity":    "CRITICAL",
        "mitre":       "T1059",
    },
]


# ==============================================================================
#  DATABASE LAYER
#  All storage is handled via a local SQLite file (mini_siem.db).
#  WAL journal mode allows safe concurrent reads from the UI while the
#  background simulation thread is writing.
# ==============================================================================

def get_conn():
    """Open and return a new SQLite connection with Row factory and WAL mode."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # allow concurrent reader + writer
    return conn


def init_db():
    """Create all tables and indexes if they do not already exist.

    Also seeds the agents table with AGENT_PROFILES on first run.
    Safe to call on every app startup - uses CREATE IF NOT EXISTS.
    """
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                agent_id    TEXT    NOT NULL,
                hostname    TEXT    NOT NULL,
                source_ip   TEXT,
                dest_ip     TEXT,
                log_source  TEXT    NOT NULL,
                raw_log     TEXT    NOT NULL,
                severity    TEXT    DEFAULT 'INFO'
            );
            CREATE INDEX IF NOT EXISTS idx_logs_ts    ON logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_agent ON logs(agent_id);
            CREATE INDEX IF NOT EXISTS idx_logs_src   ON logs(log_source);
            CREATE INDEX IF NOT EXISTS idx_logs_sev   ON logs(severity);

            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                rule_id      TEXT    NOT NULL,
                rule_name    TEXT    NOT NULL,
                severity     TEXT    NOT NULL,
                agent_id     TEXT    NOT NULL,
                hostname     TEXT    NOT NULL,
                source_ip    TEXT,
                description  TEXT,
                raw_log      TEXT,
                mitre_tactic TEXT,
                status       TEXT    DEFAULT 'OPEN',
                analyst_note TEXT    DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_sev    ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule   ON alerts(rule_id);

            CREATE TABLE IF NOT EXISTS agents (
                agent_id  TEXT PRIMARY KEY,
                hostname  TEXT    NOT NULL,
                os        TEXT,
                role      TEXT,
                ip        TEXT,
                status    TEXT    DEFAULT 'active',
                last_seen TEXT    DEFAULT (datetime('now')),
                log_count INTEGER DEFAULT 0
            );
        """)
        # Seed agent rows only if the table is empty (first run)
        if conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0] == 0:
            for agent in AGENT_PROFILES:
                conn.execute(
                    "INSERT OR IGNORE INTO agents VALUES (?,?,?,?,?,'active',datetime('now'),0)",
                    (agent["id"], agent["hostname"], agent["os"],
                     agent["role"], agent["ip"]),
                )


def query(sql, params=()):
    """Execute a SELECT statement and return results as a list of plain dicts."""
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def execute(sql, params=()):
    """Execute a non-SELECT statement (INSERT / UPDATE / DELETE)."""
    with get_conn() as conn:
        conn.execute(sql, params)


def scalar(sql, params=()):
    """Execute a SELECT that returns a single value. Returns None if no rows."""
    with get_conn() as conn:
        row = conn.execute(sql, params).fetchone()
    return row[0] if row is not None else None


# ==============================================================================
#  PLOTLY HELPER
# ==============================================================================

def rows_to_lists(rows, *keys):
    """Unzip a list of row dicts into parallel lists suitable for Plotly.

    Example:
        mins, counts = rows_to_lists(rows, "minute", "events")
        go.Bar(x=mins, y=counts)
    """
    return tuple([r[k] for r in rows] for k in keys)


# ==============================================================================
#  LOG SIMULATION ENGINE
#  Generates realistic-looking synthetic log lines for each log source.
#  Every generator returns (raw_log, log_source, severity, source_ip).
# ==============================================================================

fake = Faker()


def _rnd_ip(internal=False):
    """Return a random IP address (private or public)."""
    if internal:
        return "10.0.{}.{}".format(random.randint(1, 3), random.randint(1, 254))
    return "{}.{}.{}.{}".format(
        random.randint(1, 223), random.randint(0, 255),
        random.randint(0, 255), random.randint(1, 254),
    )


def _rnd_ts(minutes_back=120):
    """Return a UTC timestamp string for a random point up to minutes_back ago."""
    delta_secs = random.randint(0, minutes_back * 60)
    dt = datetime.utcnow() - timedelta(seconds=delta_secs)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# Common usernames targeted in SSH brute-force attacks
SSH_USERS = ["admin", "root", "ubuntu", "deploy", "git", "test", "oracle", "postgres"]

# Typical web paths hit by scanners and attackers
HTTP_PATHS = [
    "/login", "/admin", "/wp-login.php", "/api/v1/users", "/.env",
    "/phpmyadmin", "/index.html", "/static/main.js", "/api/data", "/robots.txt",
]

# HTTP status code distribution that mimics real traffic
HTTP_CODES = [200, 200, 200, 301, 302, 400, 403, 404, 404, 500]

# Classic SQL injection payloads
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL,NULL--",
    "admin'/*",
    "1' AND SLEEP(5)--",
]

# Sensitive files that attackers try to read/write
FILE_ACCESS_TARGETS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.bash_history",
    "/home/admin/.ssh/authorized_keys", "/var/log/auth.log",
    "/tmp/backdoor.sh", "/tmp/exploit.elf", "/tmp/rev.py",
    "/etc/cron.d/jobs", "/var/www/html/config.php",
]


def _gen_ssh(agent, attack):
    """Generate a synthetic sshd log line."""
    src  = _rnd_ip(internal=False)
    user = random.choice(SSH_USERS) if attack else fake.user_name()
    if attack:
        raw = "Failed password for {} from {} port {} ssh2".format(
            user, src, random.randint(40000, 65000))
        sev = "CRITICAL" if user == "root" else "HIGH"
    else:
        success = random.random() > 0.3
        if success:
            raw = "Accepted publickey for {} from {} port {} ssh2".format(
                user, _rnd_ip(True), random.randint(40000, 65000))
            sev = "LOW"
        else:
            raw = "Failed password for {} from {} port {} ssh2".format(
                user, src, random.randint(40000, 65000))
            sev = "MEDIUM"
    return raw, "sshd", sev, src


def _gen_apache(agent, attack):
    """Generate a synthetic Apache access log line (CLF format)."""
    src  = _rnd_ip(internal=False)
    ts_s = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
    if attack:
        path    = random.choice(HTTP_PATHS[:4])
        payload = random.choice(SQLI_PAYLOADS)
        raw = '{} - - [{}] "GET {}?id={} HTTP/1.1" 500 512'.format(
            src, ts_s, path, payload)
        sev = "CRITICAL"
    else:
        path = random.choice(HTTP_PATHS)
        code = random.choice(HTTP_CODES)
        size = random.randint(200, 50000)
        raw  = '{} - - [{}] "GET {} HTTP/1.1" {} {}'.format(
            src, ts_s, path, code, size)
        sev = "HIGH" if code == 500 else ("MEDIUM" if code in (403, 404) else "INFO")
    return raw, "apache", sev, src


def _gen_iptables(agent, attack):
    """Generate a synthetic iptables/netfilter kernel log line."""
    src = _rnd_ip(internal=False)
    dst = agent["ip"]
    if attack:
        kind = random.choice(["portscan", "revshell", "exfil", "reject"])
        if kind == "portscan":
            raw = ("kernel: [iptables] IN=eth0 OUT= SRC={} DST={} "
                   "PROTO=TCP SPT=54321 DPT={} SYN URGP=0").format(
                src, dst, random.randint(1, 65535))
            sev = "HIGH"
        elif kind == "revshell":
            dpt = random.choice([4444, 1337, 31337, 5555, 9999])
            raw = ("kernel: [iptables] IN= OUT=eth0 SRC={} DST={} "
                   "PROTO=TCP SPT=54321 DPT={} ESTABLISHED").format(dst, src, dpt)
            sev = "CRITICAL"
        elif kind == "exfil":
            pkt = random.randint(10000, 99999)
            raw = ("kernel: [iptables] OUT=eth0 SRC={} DST={} "
                   "PROTO=TCP LEN={} REJECT").format(dst, src, pkt)
            sev = "HIGH"
        else:
            raw = ("kernel: [iptables] IN=eth0 OUT= SRC={} DST={} "
                   "PROTO=TCP SPT={} DPT=443 REJECT").format(
                src, dst, random.randint(1024, 65000))
            sev = "HIGH"
    else:
        dpt    = random.choice([80, 443, 22, 3306, 5432, 53])
        action = random.choice(["ACCEPT", "REJECT"])
        raw    = ("kernel: [iptables] IN=eth0 OUT= SRC={} DST={} "
                  "PROTO=TCP SPT={} DPT={} {}").format(
            src, dst, random.randint(1024, 65000), dpt, action)
        sev = "LOW" if action == "ACCEPT" else "MEDIUM"
    return raw, "iptables", sev, src


def _gen_sudo(agent, attack):
    """Generate a synthetic sudo log line."""
    src  = agent["ip"]
    user = fake.user_name()
    if attack:
        cmd = random.choice([
            "/bin/bash",
            "/usr/bin/passwd root",
            "/bin/chmod 777 /etc/shadow",
        ])
        sev = "CRITICAL"
    else:
        cmd = random.choice([
            "/usr/bin/apt update",
            "/bin/systemctl restart nginx",
            "/usr/bin/journalctl -xe",
        ])
        sev = "LOW"
    raw = "sudo: {} : TTY=pts/0 ; PWD=/home/{} ; USER=root ; COMMAND={}".format(
        user, user, cmd)
    return raw, "sudo", sev, src


def _gen_useradd(agent, attack=False):
    """Generate a synthetic useradd syslog line."""
    user = fake.user_name()
    uid  = random.randint(1001, 9999)
    pid  = random.randint(1000, 9999)
    raw  = ("useradd[{}]: new user: name={}, UID={}, GID={}, "
            "home=/home/{}, shell=/bin/bash").format(pid, user, uid, uid, user)
    return raw, "useradd", "MEDIUM", agent["ip"]


def _gen_fileaccess(agent, attack):
    """Generate a synthetic Linux Audit daemon (auditd) syscall log line."""
    src  = agent["ip"]
    user = (random.choice(["root", "www-data", "nobody"])
            if attack else fake.user_name())
    pid  = random.randint(1000, 65000)
    if attack:
        target = random.choice(FILE_ACCESS_TARGETS)
        op     = random.choice(["READ", "WRITE", "OPEN"])
        sev    = "CRITICAL" if "/tmp/" in target else "HIGH"
        raw    = (
            "type=SYSCALL msg=audit({:.3f}:{}): "
            "arch=x86_64 syscall={} success=yes "
            "pid={} uid=0 gid=0 comm=\"{}\" exe=\"/bin/cat\" "
            "key=\"file_access\" {} path={} perm=rw"
        ).format(time.time(), pid, op.lower(), pid, user, op, target)
    else:
        target = random.choice([
            "/var/log/syslog", "/etc/hosts", "/etc/hostname",
            "/proc/cpuinfo", "/home/{}/.bashrc".format(fake.user_name()),
        ])
        raw = (
            "type=SYSCALL msg=audit({:.3f}:{}): "
            "arch=x86_64 syscall=read success=yes "
            "pid={} uid={} comm=\"{}\" exe=\"/usr/bin/cat\" "
            "key=\"file_access\" READ path={}"
        ).format(time.time(), pid, pid, random.randint(1000, 9999), user, target)
        sev = "INFO"
    return raw, "auditd", sev, src


# Maps each agent hostname to the log generators appropriate for its role
_AGENT_GENERATORS = {
    "web-server-01":   [_gen_apache, _gen_iptables, _gen_sudo, _gen_fileaccess],
    "db-server-01":    [_gen_iptables, _gen_sudo, _gen_useradd, _gen_fileaccess],
    "firewall-01":     [_gen_iptables],
    "auth-server-01":  [_gen_ssh, _gen_sudo, _gen_useradd, _gen_fileaccess],
    "endpoint-win-01": [_gen_ssh, _gen_apache, _gen_fileaccess],
}


def simulate_logs(n=100, attack_ratio=0.30):
    """Generate n synthetic log entries across all simulated agents.

    Args:
        n:            Number of log entries to generate.
        attack_ratio: Fraction of logs that represent attack activity (0 to 1).

    Returns:
        List of log dicts ready to be passed to ingest_logs().
    """
    logs = []
    for _ in range(n):
        agent  = random.choice(AGENT_PROFILES)
        gens   = _AGENT_GENERATORS.get(agent["hostname"], [_gen_ssh])
        gen_fn = random.choice(gens)
        attack = random.random() < attack_ratio
        try:
            raw, src, sev, sip = gen_fn(agent, attack)
        except TypeError:
            raw, src, sev, sip = gen_fn(agent)
        logs.append({
            "timestamp":  _rnd_ts(),
            "agent_id":   agent["id"],
            "hostname":   agent["hostname"],
            "source_ip":  sip,
            "dest_ip":    agent["ip"],
            "log_source": src,
            "raw_log":    raw,
            "severity":   sev,
        })
    return logs


def _run_rules(conn, log):
    """Evaluate log against every alert rule and INSERT matching alerts.

    Stateful rules delegate threshold checking to _record_ssh_fail().
    All other rules fire on first regex match.
    """
    for rule in ALERT_RULES:
        if rule["log_source"] != log["log_source"]:
            continue
        match = re.search(rule["pattern"], log["raw_log"], re.IGNORECASE)
        if not match:
            continue
        if rule.get("stateful"):
            src_ip = log.get("source_ip") or ""
            if not _record_ssh_fail(src_ip):
                continue
        conn.execute(
            """INSERT INTO alerts
               (timestamp, rule_id, rule_name, severity, agent_id, hostname,
                source_ip, description, raw_log, mitre_tactic, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')""",
            (log["timestamp"], rule["rule_id"], rule["name"], rule["severity"],
             log["agent_id"], log["hostname"], log["source_ip"],
             rule["description"], log["raw_log"][:500], rule["mitre"]),
        )


def ingest_logs(logs):
    """Persist logs to the database and run all alert rules against each entry."""
    with get_conn() as conn:
        for log in logs:
            conn.execute(
                """INSERT INTO logs
                   (timestamp, agent_id, hostname, source_ip, dest_ip,
                    log_source, raw_log, severity)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (log["timestamp"], log["agent_id"], log["hostname"],
                 log["source_ip"], log["dest_ip"], log["log_source"],
                 log["raw_log"], log["severity"]),
            )
            conn.execute(
                "UPDATE agents SET last_seen = datetime('now'), "
                "log_count = log_count + 1 WHERE agent_id = ?",
                (log["agent_id"],),
            )
            _run_rules(conn, log)


# ==============================================================================
#  DATA HELPER FUNCTIONS
# ==============================================================================

def get_stats():
    """Return a snapshot of key SIEM metrics for the dashboard KPI bar."""
    return {
        "total_logs":    scalar("SELECT COUNT(*) FROM logs") or 0,
        "total_alerts":  scalar("SELECT COUNT(*) FROM alerts") or 0,
        "open_alerts":   scalar("SELECT COUNT(*) FROM alerts WHERE status='OPEN'") or 0,
        "critical":      scalar("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND status='OPEN'") or 0,
        "high":          scalar("SELECT COUNT(*) FROM alerts WHERE severity='HIGH' AND status='OPEN'") or 0,
        "medium":        scalar("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM' AND status='OPEN'") or 0,
        "active_agents": scalar("SELECT COUNT(*) FROM agents WHERE status='active'") or 0,
        "last_event":    scalar("SELECT MAX(timestamp) FROM logs") or "N/A",
        "logs_1m":       scalar("SELECT COUNT(*) FROM logs   WHERE timestamp >= datetime('now','-1 minute')") or 0,
        "alerts_1m":     scalar("SELECT COUNT(*) FROM alerts WHERE timestamp >= datetime('now','-1 minute')") or 0,
    }


def update_alert(alert_id, status, note=""):
    """Update the triage status and analyst note for a single alert."""
    execute(
        "UPDATE alerts SET status = ?, analyst_note = ? WHERE id = ?",
        (status, note, alert_id),
    )


# ==============================================================================
#  BACKGROUND SIMULATION THREAD
# ==============================================================================

_bg_thread = None
_bg_stop   = threading.Event()


def _bg_worker(attack_ratio):
    """Daemon loop: generates AUTO_SIM_BATCH logs every AUTO_SIM_SECS seconds."""
    while not _bg_stop.wait(AUTO_SIM_SECS):
        try:
            logs = simulate_logs(n=AUTO_SIM_BATCH, attack_ratio=attack_ratio)
            ingest_logs(logs)
        except Exception:
            pass  # never crash the daemon


def start_bg_simulation(attack_ratio=0.30):
    """Start the background simulation thread if not already running."""
    global _bg_thread, _bg_stop
    if _bg_thread and _bg_thread.is_alive():
        return
    _bg_stop.clear()
    _bg_thread = threading.Thread(
        target=_bg_worker, args=(attack_ratio,),
        daemon=True, name="siem-bg-sim",
    )
    _bg_thread.start()


def stop_bg_simulation():
    """Signal the background thread to stop and wait up to 2 seconds."""
    global _bg_thread
    _bg_stop.set()
    if _bg_thread:
        _bg_thread.join(timeout=2)
        _bg_thread = None


def bg_is_running():
    """Return True if the background simulation thread is currently alive."""
    return _bg_thread is not None and _bg_thread.is_alive()


# ==============================================================================
#  UI HELPER FUNCTIONS
# ==============================================================================

def _sev_badge(sev):
    """Return an inline HTML span styled as a coloured severity badge."""
    colour = SEVERITY_COLORS.get(sev, "#888888")
    return (
        "<span style='background:{};color:#ffffff;padding:2px 8px;"
        "border-radius:4px;font-size:11px;font-weight:700'>{}</span>"
    ).format(colour, sev)


def _alerts_table_html(rows, columns, col_labels):
    """Render a list of alert row dicts as a styled HTML table string."""
    th = "".join(
        "<th style='text-align:left;padding:7px 10px;background:#1e2a3a;"
        "color:#ffffff;font-size:12px;white-space:nowrap'>{}</th>".format(lbl)
        for lbl in col_labels
    )
    td_rows = ""
    for r in rows:
        sev    = r.get("severity", "INFO")
        row_bg = SEVERITY_COLORS.get(sev, "#888888") + "18"
        cells  = ""
        for col in columns:
            val = r.get(col) or ""
            if col == "severity":
                cells += "<td style='padding:6px 10px'>{}</td>".format(_sev_badge(sev))
            elif col in ("source_ip", "mitre_tactic", "rule_id"):
                cells += ("<td style='padding:6px 10px;font-family:monospace;"
                          "font-size:12px'><code>{}</code></td>").format(val)
            else:
                cells += "<td style='padding:6px 10px;font-size:12px'>{}</td>".format(val)
        td_rows += (
            "<tr style='background:{};border-bottom:1px solid #e5e7eb'>{}</tr>"
        ).format(row_bg, cells)
    return (
        "<div style='overflow-x:auto;border:1px solid #e5e7eb;border-radius:6px'>"
        "<table style='width:100%;border-collapse:collapse'>"
        "<thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>"
    ).format(th, td_rows)


# ==============================================================================
#  DASHBOARD PAGE
# ==============================================================================

def page_dashboard():
    """Render the main Security Dashboard page."""
    st.title("Mini-SIEM - Security Dashboard")

    s = get_stats()

    # Live-mode banner
    is_live = st.session_state.get("auto_sim_on", False)
    if is_live:
        st.caption(
            "[LIVE] Live mode - new data every {}s | Last update: {} UTC".format(
                AUTO_SIM_SECS, datetime.utcnow().strftime("%H:%M:%S"))
        )
    else:
        st.caption(
            "Last refresh: {} UTC  (use Simulate or enable Live Mode in the sidebar)".format(
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        )

    # KPI metrics row
    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
    c1.metric("Total Logs",
              "{:,}".format(s["total_logs"]),
              delta="+{} /min".format(s["logs_1m"]) if s["logs_1m"] else None)
    c2.metric("Total Alerts",
              "{:,}".format(s["total_alerts"]),
              delta="+{} /min".format(s["alerts_1m"]) if s["alerts_1m"] else None)
    c3.metric("Open Alerts",   "{:,}".format(s["open_alerts"]))
    c4.metric("CRITICAL",      "{:,}".format(s["critical"]),
              delta="+{}".format(s["critical"]) if s["critical"] else None,
              delta_color="inverse")
    c5.metric("HIGH",          "{:,}".format(s["high"]),
              delta="+{}".format(s["high"]) if s["high"] else None,
              delta_color="inverse")
    c6.metric("MEDIUM",        "{:,}".format(s["medium"]))
    c7.metric("Agents",        "{}".format(s["active_agents"]))

    st.divider()

    # Row 1: Log volume timeline | Severity donut
    col_a, col_b = st.columns([3, 2])

    with col_a:
        st.subheader("Log Volume - Last 2 Hours")
        ev_rows = query("""
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) AS minute,
                   COUNT(*) AS events,
                   SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) AS attacks
            FROM logs
            WHERE timestamp >= datetime('now', '-2 hours')
            GROUP BY minute ORDER BY minute
        """)
        if ev_rows:
            mins   = [r["minute"]  for r in ev_rows]
            events = [r["events"]  for r in ev_rows]
            atks   = [r["attacks"] for r in ev_rows]
            fig = go.Figure()
            fig.add_trace(go.Bar(x=mins, y=events, name="All Events",
                                 marker_color="#457b9d", opacity=0.65))
            fig.add_trace(go.Scatter(x=mins, y=atks, name="Attack/High",
                                     mode="lines+markers",
                                     line=dict(color="#e63946", width=2),
                                     marker=dict(size=5)))
            fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0),
                               legend=dict(orientation="h", y=1.12),
                               xaxis_title="", yaxis_title="Count",
                               barmode="overlay")
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No recent events - use Simulate or enable Live Mode in the sidebar.")

    with col_b:
        st.subheader("Open Alerts by Severity")
        sev_rows = query("""
            SELECT severity, COUNT(*) AS cnt FROM alerts
            WHERE status = 'OPEN'
            GROUP BY severity ORDER BY cnt DESC
        """)
        if sev_rows:
            sevs, cnts = rows_to_lists(sev_rows, "severity", "cnt")
            fig2 = go.Figure(go.Pie(
                labels=sevs, values=cnts, hole=0.5,
                marker=dict(colors=[SEVERITY_COLORS.get(s, "#888") for s in sevs]),
                textinfo="percent+label",
                hovertemplate="%{label}: %{value} alerts<extra></extra>",
            ))
            fig2.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0),
                               showlegend=False)
            st.plotly_chart(fig2, width="stretch")
        else:
            st.info("No open alerts yet.")

    st.divider()

    # Row 2: Top attacker IPs | Alerts by rule
    col_c, col_d = st.columns(2)

    with col_c:
        st.subheader("Top 10 Attacker IPs")
        ip_rows = query("""
            SELECT source_ip, COUNT(*) AS hits FROM alerts
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip ORDER BY hits DESC LIMIT 10
        """)
        if ip_rows:
            ips, hits = rows_to_lists(ip_rows, "source_ip", "hits")
            fig3 = go.Figure(go.Bar(
                x=hits, y=ips, orientation="h",
                marker=dict(color=hits, colorscale="OrRd", showscale=False),
                hovertemplate="%{y}: %{x} alerts<extra></extra>",
            ))
            fig3.update_layout(height=310, margin=dict(l=0, r=0, t=10, b=0),
                               yaxis=dict(categoryorder="total ascending"))
            st.plotly_chart(fig3, width="stretch")
        else:
            st.info("No alert data yet.")

    with col_d:
        st.subheader("Alerts by Detection Rule")
        rule_rows = query("""
            SELECT rule_name, severity, COUNT(*) AS cnt FROM alerts
            GROUP BY rule_name, severity ORDER BY cnt DESC LIMIT 12
        """)
        if rule_rows:
            fig4 = go.Figure()
            for sev in SEVERITY_ORDER:
                sev_rules = [r for r in rule_rows if r["severity"] == sev]
                if not sev_rules:
                    continue
                fig4.add_trace(go.Bar(
                    x=[r["cnt"]       for r in sev_rules],
                    y=[r["rule_name"] for r in sev_rules],
                    name=sev, orientation="h",
                    marker_color=SEVERITY_COLORS.get(sev, "#888"),
                ))
            fig4.update_layout(height=310, margin=dict(l=0, r=0, t=10, b=0),
                               barmode="stack",
                               yaxis=dict(categoryorder="total ascending"),
                               legend=dict(orientation="h", y=1.1),
                               xaxis_title="Count")
            st.plotly_chart(fig4, width="stretch")
        else:
            st.info("No alert data yet.")

    st.divider()

    # Severity-categorized live alerts table
    st.subheader("Active Security Alerts - Categorized by Severity")

    sev_tabs    = st.tabs(["CRITICAL", "HIGH", "MEDIUM", "LOW / INFO", "All Open"])
    tab_filters = [
        ("CRITICAL",),
        ("HIGH",),
        ("MEDIUM",),
        ("LOW", "INFO"),
        ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
    ]

    for tab, sevs_tuple in zip(sev_tabs, tab_filters):
        with tab:
            sev_in = ",".join("'{}'".format(s) for s in sevs_tuple)
            alert_rows = query("""
                SELECT timestamp, rule_id, rule_name, severity, hostname,
                       source_ip, mitre_tactic, description, status
                FROM alerts
                WHERE severity IN ({}) AND status = 'OPEN'
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1 WHEN 'HIGH'   THEN 2
                        WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'    THEN 4
                        ELSE 5 END,
                    timestamp DESC
                LIMIT 30
            """.format(sev_in))
            if alert_rows:
                count_label = "{} alert{}".format(
                    len(alert_rows), "s" if len(alert_rows) != 1 else "")
                if len(alert_rows) == 30:
                    count_label += " (capped at 30)"
                st.caption(count_label)
                st.markdown(
                    _alerts_table_html(
                        alert_rows,
                        ["timestamp", "severity", "rule_name", "hostname",
                         "source_ip", "mitre_tactic", "description"],
                        ["Timestamp", "Severity", "Rule", "Agent",
                         "Source IP", "MITRE", "Description"],
                    ),
                    unsafe_allow_html=True,
                )
            else:
                st.success("No open alerts at this severity level.")


# ==============================================================================
#  ALERT MANAGEMENT PAGE
# ==============================================================================

def page_alerts():
    """Render the Alert Management page."""
    st.title("Alert Management")
    st.caption("Filter, review, and triage open security alerts.")

    col1, col2, col3 = st.columns(3)
    sev_filter  = col1.multiselect(
        "Severity", SEVERITY_ORDER, default=["CRITICAL", "HIGH", "MEDIUM"])
    stat_filter = col2.multiselect(
        "Status", ["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"],
        default=["OPEN"])
    rule_opts   = [r["rule_name"] for r in
                   query("SELECT DISTINCT rule_name FROM alerts ORDER BY rule_name")]
    rule_filter = col3.multiselect("Rule (optional)", rule_opts, default=[])

    sev_ph   = ",".join("'{}'".format(s) for s in sev_filter)  or "'__NONE__'"
    stat_ph  = ",".join("'{}'".format(s) for s in stat_filter) or "'__NONE__'"
    rule_sql = ("AND rule_name IN ({})".format(
                    ",".join(repr(r) for r in rule_filter))
                if rule_filter else "")

    rows = query("""
        SELECT id, timestamp, rule_id, rule_name, severity, hostname,
               source_ip, mitre_tactic, description, status, analyst_note
        FROM alerts
        WHERE severity IN ({}) AND status IN ({}) {}
        ORDER BY timestamp DESC LIMIT {}
    """.format(sev_ph, stat_ph, rule_sql, PAGE_SIZE))

    st.caption("Showing up to {} results - {} matched".format(PAGE_SIZE, len(rows)))

    if not rows:
        st.info("No alerts match the current filters.")
        return

    for row in rows:
        label = "[{}] {} - {} @ {}".format(
            row["severity"], row["rule_name"], row["hostname"], row["timestamp"])
        with st.expander(label, expanded=False):
            c1, c2 = st.columns(2)
            c1.markdown(
                "**Rule ID:** `{}`  \n"
                "**MITRE ATT&CK:** `{}`  \n"
                "**Source IP:** `{}`  \n"
                "**Agent:** `{}`".format(
                    row["rule_id"], row["mitre_tactic"],
                    row["source_ip"], row["hostname"])
            )
            c2.markdown(
                "**Status:** `{}`  \n"
                "**Description:** {}".format(row["status"], row["description"])
            )
            new_status = st.selectbox(
                "Update Status",
                ["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"],
                index=["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"]
                      .index(row["status"]),
                key="status_{}".format(row["id"]),
            )
            note = st.text_input(
                "Analyst Note", value=row["analyst_note"] or "",
                key="note_{}".format(row["id"]),
            )
            if st.button("Save", key="save_{}".format(row["id"])):
                update_alert(row["id"], new_status, note)
                st.success("Alert updated.")
                st.rerun()


# ==============================================================================
#  LOG SEARCH PAGE
# ==============================================================================

def page_log_search():
    """Render the Log Search & Explorer page."""
    st.title("Log Search and Explorer")
    st.caption("Search raw log lines using regex patterns or plain text.")

    with st.form("search_form"):
        col1, col2 = st.columns([3, 1])
        query_str  = col1.text_input(
            "Search (regex)", placeholder="Failed password|192.168")
        log_source = col2.selectbox(
            "Log Source",
            ["All", "sshd", "apache", "iptables", "sudo", "useradd", "auditd"])

        col3, col4 = st.columns(2)
        sev_sel   = col3.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
        agent_sel = col4.multiselect(
            "Agent",
            ["All"] + [a["hostname"] for a in AGENT_PROFILES],
            default=["All"])
        submitted = st.form_submit_button("Search")

    if not submitted:
        st.info("Enter search criteria and click Search.")
        return

    sev_ph = ",".join("'{}'".format(s) for s in sev_sel) or "'__NONE__'"

    agent_sql = ""
    agent_params = []
    if agent_sel and "All" not in agent_sel:
        placeholders = ",".join("?" * len(agent_sel))
        agent_sql    = "AND hostname IN ({})".format(placeholders)
        agent_params = list(agent_sel)

    src_sql    = "AND log_source = ?" if log_source != "All" else ""
    text_sql   = "AND raw_log REGEXP ?" if query_str else ""

    params = agent_params[:]
    if log_source != "All":
        params.append(log_source)
    if query_str:
        params.append(query_str)

    conn = get_conn()
    conn.create_function(
        "REGEXP", 2,
        lambda pattern, text: bool(
            re.search(pattern, text or "", re.IGNORECASE)
        ) if pattern else True,
    )

    try:
        cur = conn.execute(
            """SELECT id, timestamp, hostname, log_source, severity,
                      source_ip, raw_log
               FROM logs
               WHERE severity IN ({}) {} {} {}
               ORDER BY timestamp DESC LIMIT {}""".format(
                sev_ph, agent_sql, src_sql, text_sql, PAGE_SIZE),
            params,
        )
        rows = [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError as exc:
        st.error("Search error: {}".format(exc))
        rows = []
    finally:
        conn.close()

    st.caption("{} results (max {})".format(len(rows), PAGE_SIZE))
    if not rows:
        st.info("No logs found for the given criteria.")
        return

    headers   = ["ID", "Timestamp", "Agent", "Source", "Severity", "Source IP", "Raw Log"]
    rows_html = ""
    for r in rows:
        row_bg       = SEVERITY_COLORS.get(r["severity"], "#888888") + "33"
        sev_colour   = SEVERITY_COLORS.get(r["severity"], "#888888")
        raw_truncated = (r["raw_log"][:120] + "...") if len(r["raw_log"]) > 120 else r["raw_log"]
        rows_html += (
            "<tr style='background:{}'>"
            "<td style='padding:5px 8px'>{}</td>"
            "<td style='padding:5px 8px'>{}</td>"
            "<td style='padding:5px 8px'>{}</td>"
            "<td style='padding:5px 8px'>{}</td>"
            "<td style='padding:5px 8px;color:{};font-weight:bold'>{}</td>"
            "<td style='padding:5px 8px;font-family:monospace;font-size:12px'>"
            "<code>{}</code></td>"
            "<td style='padding:5px 8px;font-family:monospace;font-size:12px'>"
            "{}</td></tr>"
        ).format(row_bg, r["id"], r["timestamp"], r["hostname"],
                 r["log_source"], sev_colour, r["severity"],
                 r["source_ip"], raw_truncated)
    th_cells = "".join(
        "<th style='text-align:left;padding:5px 8px;background:#1e2a3a;"
        "color:#ffffff'>{}</th>".format(h) for h in headers)
    st.markdown(
        "<div style='overflow-x:auto'>"
        "<table style='width:100%;border-collapse:collapse;font-size:12px'>"
        "<thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>".format(
            th_cells, rows_html),
        unsafe_allow_html=True,
    )


# ==============================================================================
#  AGENT MANAGEMENT PAGE
# ==============================================================================

def page_agents():
    """Render the Agent Management page."""
    st.title("Agent Management")
    st.caption("Status and telemetry for each monitored host agent.")

    agents = query(
        "SELECT agent_id, hostname, os, role, ip, status, last_seen, log_count "
        "FROM agents ORDER BY hostname"
    )
    if not agents:
        st.warning("No agents registered. Check init_db().")
        return

    for a in agents:
        status_icon = "[ACTIVE]" if a["status"] == "active" else "[OFFLINE]"
        with st.expander(
            "{} {} - {} ({})".format(status_icon, a["hostname"], a["role"], a["ip"]),
            expanded=False,
        ):
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Agent ID",  a["agent_id"])
            c2.metric("OS",        a["os"])
            c3.metric("Logs Sent", "{:,}".format(a["log_count"]))
            c4.metric("Last Seen", a["last_seen"])

            alert_rows = query(
                "SELECT severity, COUNT(*) AS cnt FROM alerts "
                "WHERE hostname = ? GROUP BY severity",
                (a["hostname"],),
            )
            if alert_rows:
                sevs, cnts = rows_to_lists(alert_rows, "severity", "cnt")
                fig = go.Figure(go.Bar(
                    x=sevs, y=cnts,
                    marker=dict(color=[SEVERITY_COLORS.get(s, "#888") for s in sevs]),
                ))
                fig.update_layout(height=180, margin=dict(l=0, r=0, t=20, b=0),
                                   showlegend=False,
                                   title="Alert Breakdown - {}".format(a["hostname"]))
                st.plotly_chart(fig, width="stretch")

    st.divider()
    st.subheader("Log Heatmap - Agent x Source")
    st.caption("Cell colour intensity reflects log volume.")

    hm_rows = query("""
        SELECT hostname, log_source, COUNT(*) AS cnt
        FROM logs GROUP BY hostname, log_source
        ORDER BY hostname, cnt DESC
    """)
    if hm_rows:
        agents_u  = sorted({r["hostname"]   for r in hm_rows})
        sources_u = sorted({r["log_source"] for r in hm_rows})
        lookup    = {(r["hostname"], r["log_source"]): r["cnt"] for r in hm_rows}
        z = [[lookup.get((ag, src), 0) for src in sources_u] for ag in agents_u]
        fig_h = go.Figure(go.Heatmap(z=z, x=sources_u, y=agents_u,
                                      colorscale="Blues", showscale=True))
        fig_h.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0))
        st.plotly_chart(fig_h, width="stretch")
    else:
        st.info("No log data yet.")


# ==============================================================================
#  DETECTION RULES PAGE
# ==============================================================================

def page_rules():
    """Render the Detection Rules reference page."""
    st.title("Detection Rules")
    st.caption("All active correlation rules powering the alert engine.")

    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for rule in sorted(ALERT_RULES, key=lambda r: sev_rank.get(r["severity"], 9)):
        sev_colour = SEVERITY_COLORS.get(rule["severity"], "#888888")
        with st.expander(
            "[{}] {} - {}".format(rule["severity"], rule["rule_id"], rule["name"]),
            expanded=False,
        ):
            c1, c2 = st.columns(2)
            c1.markdown(
                "**Description:** {}  \n"
                "**Log Source:** `{}`  \n"
                "**MITRE ATT&CK:** `{}`  \n"
                "**Stateful:** {}".format(
                    rule["description"], rule["log_source"], rule["mitre"],
                    "Yes (threshold-based)" if rule.get("stateful") else "No (fires on every match)")
            )
            c2.markdown(
                "**Severity:** <span style='color:{};font-weight:bold'>{}</span>".format(
                    sev_colour, rule["severity"]),
                unsafe_allow_html=True,
            )
            st.code(rule["pattern"], language=None)
            hits = scalar("SELECT COUNT(*) FROM alerts WHERE rule_id = ?",
                          (rule["rule_id"],)) or 0
            st.metric("Total Alerts Fired", hits)


# ==============================================================================
#  MITRE ATT&CK PAGE
# ==============================================================================

def page_mitre():
    """Render the MITRE ATT&CK Coverage page."""
    st.title("MITRE ATT&CK Coverage")
    st.caption("Alert distribution mapped to MITRE ATT&CK technique IDs.")

    rows = query("""
        SELECT mitre_tactic, rule_name, severity, COUNT(*) AS cnt
        FROM alerts GROUP BY mitre_tactic, rule_name, severity ORDER BY cnt DESC
    """)
    if not rows:
        st.info("No alert data yet - simulate some logs first.")
        return

    # Build sunburst data: root -> tactic -> rule_name
    labels  = []
    parents = []
    values  = []

    seen_tactics = set()
    for r in rows:
        tactic = r["mitre_tactic"]
        if tactic not in seen_tactics:
            labels.append(tactic)
            parents.append("")
            values.append(0)
            seen_tactics.add(tactic)

    for r in rows:
        labels.append(r["rule_name"])
        parents.append(r["mitre_tactic"])
        values.append(r["cnt"])

    fig = go.Figure(go.Sunburst(
        labels=labels, parents=parents, values=values,
        branchvalues="total",
        hovertemplate="%{label}: %{value} alerts<extra></extra>",
    ))
    fig.update_layout(height=500, margin=dict(l=0, r=0, t=40, b=0),
                      title="MITRE Coverage - Technique to Rule")
    st.plotly_chart(fig, width="stretch")

    st.divider()
    st.subheader("Technique Alert Table")
    headers   = ["MITRE Technique", "Rule Name", "Severity", "Count"]
    rows_html = ""
    for r in rows:
        c = SEVERITY_COLORS.get(r["severity"], "#888888")
        rows_html += (
            "<tr>"
            "<td style='padding:6px 10px;font-family:monospace'><code>{}</code></td>"
            "<td style='padding:6px 10px'>{}</td>"
            "<td style='padding:6px 10px;color:{};font-weight:bold'>{}</td>"
            "<td style='padding:6px 10px'>{}</td>"
            "</tr>"
        ).format(r["mitre_tactic"], r["rule_name"], c, r["severity"], r["cnt"])
    th_cells = "".join(
        "<th style='text-align:left;padding:6px 10px;background:#1e2a3a;"
        "color:#ffffff'>{}</th>".format(h) for h in headers)
    st.markdown(
        "<div style='overflow-x:auto'>"
        "<table style='width:100%;border-collapse:collapse;font-size:13px'>"
        "<thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>".format(
            th_cells, rows_html),
        unsafe_allow_html=True,
    )


# ==============================================================================
#  ANALYTICS PAGE
# ==============================================================================

def page_analytics():
    """Render the Security Analytics page."""
    st.title("Security Analytics")

    tab1, tab2, tab3 = st.tabs([
        "Event Trends", "Threat Intelligence", "Log Source Distribution"])

    with tab1:
        st.subheader("Hourly Event and Alert Trend")
        ev_rows = query("""
            SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hr, COUNT(*) AS events
            FROM logs GROUP BY hr ORDER BY hr DESC LIMIT 48
        """)
        al_rows = query("""
            SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hr, COUNT(*) AS alerts
            FROM alerts GROUP BY hr ORDER BY hr DESC LIMIT 48
        """)
        if ev_rows and al_rows:
            ev_map  = {r["hr"]: r["events"] for r in ev_rows}
            al_map  = {r["hr"]: r["alerts"] for r in al_rows}
            all_hrs = sorted(set(ev_map) | set(al_map))
            fig = go.Figure()
            fig.add_trace(go.Bar(x=all_hrs,
                                  y=[ev_map.get(h, 0) for h in all_hrs],
                                  name="Events", marker_color="#457b9d", opacity=0.75))
            fig.add_trace(go.Scatter(x=all_hrs,
                                      y=[al_map.get(h, 0) for h in all_hrs],
                                      name="Alerts", mode="lines+markers",
                                      line=dict(color="#e63946", width=2)))
            fig.update_layout(height=350, legend=dict(orientation="h"),
                               xaxis_title="", yaxis_title="Count")
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("Insufficient data - simulate some logs first.")

    with tab2:
        st.subheader("Top Attacking IPs")
        rows = query("""
            SELECT source_ip,
                   COUNT(*) AS total_alerts,
                   SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END) AS high,
                   MAX(timestamp) AS last_seen
            FROM alerts WHERE source_ip IS NOT NULL
            GROUP BY source_ip ORDER BY total_alerts DESC LIMIT 20
        """)
        if rows:
            headers   = ["Source IP", "Total Alerts", "Critical", "High", "Last Seen"]
            rows_html = "".join(
                "<tr>"
                "<td style='padding:6px 10px;font-family:monospace'><code>{}</code></td>"
                "<td style='padding:6px 10px'>{}</td>"
                "<td style='padding:6px 10px;color:{}'>{}</td>"
                "<td style='padding:6px 10px;color:{}'>{}</td>"
                "<td style='padding:6px 10px'>{}</td>"
                "</tr>".format(
                    r["source_ip"], r["total_alerts"],
                    SEVERITY_COLORS["CRITICAL"], r["critical"],
                    SEVERITY_COLORS["HIGH"], r["high"],
                    r["last_seen"])
                for r in rows
            )
            th_cells = "".join(
                "<th style='text-align:left;padding:6px 10px;background:#1e2a3a;"
                "color:#ffffff'>{}</th>".format(h) for h in headers)
            st.markdown(
                "<div style='overflow-x:auto'>"
                "<table style='width:100%;border-collapse:collapse;font-size:13px'>"
                "<thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>".format(
                    th_cells, rows_html),
                unsafe_allow_html=True,
            )
        else:
            st.info("No alert data yet.")

        st.divider()
        st.subheader("Attack Timeline by Severity")
        tl_rows = query("""
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) AS ts,
                   severity, COUNT(*) AS cnt
            FROM alerts GROUP BY ts, severity ORDER BY ts
        """)
        if tl_rows:
            fig2 = go.Figure()
            for sev in SEVERITY_ORDER:
                sev_tl = [r for r in tl_rows if r["severity"] == sev]
                if not sev_tl:
                    continue
                fig2.add_trace(go.Bar(
                    x=[r["ts"]  for r in sev_tl],
                    y=[r["cnt"] for r in sev_tl],
                    name=sev, marker_color=SEVERITY_COLORS.get(sev, "#888"),
                ))
            fig2.update_layout(height=300, barmode="stack",
                                legend=dict(orientation="h"),
                                xaxis_title="", yaxis_title="Alerts")
            st.plotly_chart(fig2, width="stretch")

    with tab3:
        st.subheader("Log Volume by Source and Agent")
        src_rows = query("SELECT log_source, COUNT(*) AS cnt FROM logs "
                         "GROUP BY log_source ORDER BY cnt DESC")
        ag_rows  = query("SELECT hostname, COUNT(*) AS cnt FROM logs "
                         "GROUP BY hostname ORDER BY cnt DESC")
        c1, c2 = st.columns(2)
        if src_rows:
            srcs, cnts = rows_to_lists(src_rows, "log_source", "cnt")
            fig3 = go.Figure(go.Pie(labels=srcs, values=cnts, hole=0.4,
                                     title="By Log Source"))
            fig3.update_layout(height=300, margin=dict(l=0, r=0, t=40, b=0))
            c1.plotly_chart(fig3, width="stretch")
        if ag_rows:
            ags, cnts2 = rows_to_lists(ag_rows, "hostname", "cnt")
            fig4 = go.Figure(go.Pie(labels=ags, values=cnts2, hole=0.4,
                                     title="By Agent"))
            fig4.update_layout(height=300, margin=dict(l=0, r=0, t=40, b=0))
            c2.plotly_chart(fig4, width="stretch")


# ==============================================================================
#  SIDEBAR
# ==============================================================================

def render_sidebar():
    """Render the left-side navigation and control sidebar.

    Returns:
        The label string of the currently selected navigation page.
    """
    with st.sidebar:
        st.markdown("## Mini-SIEM Lab")
        st.caption("Wazuh-inspired | Single-file Python SIEM")
        st.divider()

        page = st.radio(
            "Navigation",
            [
                "Dashboard",
                "Alerts",
                "Log Search",
                "Agents",
                "Detection Rules",
                "MITRE ATT&CK",
                "Analytics",
            ],
            label_visibility="collapsed",
        )

        # Manual simulation controls
        st.divider()
        st.subheader("Simulation Controls")
        n_logs     = st.slider("Logs to generate",  10, 500, 100, step=10)
        attack_pct = st.slider("Attack ratio %",      0, 100,  30, step=5)

        if st.button("Simulate and Ingest Logs",
                     width="stretch", type="primary"):
            with st.spinner("Generating logs and running alert rules..."):
                logs = simulate_logs(n=n_logs, attack_ratio=attack_pct / 100)
                ingest_logs(logs)
            st.success("Ingested {} logs".format(len(logs)))
            st.rerun()

        # Live Mode controls
        st.divider()
        st.subheader("Live Mode")
        st.caption(
            "Auto-ingest {} logs every {}s in a background thread, "
            "then auto-refresh the dashboard.".format(AUTO_SIM_BATCH, AUTO_SIM_SECS)
        )

        live_on = st.session_state.get("auto_sim_on", False)
        st.markdown("Live Mode: ON" if live_on else "Live Mode: OFF")

        col_l, col_r = st.columns(2)
        if col_l.button("Start", width="stretch", disabled=live_on, type="primary"):
            st.session_state["auto_sim_on"]     = True
            st.session_state["auto_sim_attack"] = attack_pct / 100
            start_bg_simulation(attack_pct / 100)
            st.rerun()

        if col_r.button("Stop", width="stretch", disabled=not live_on):
            st.session_state["auto_sim_on"] = False
            stop_bg_simulation()
            st.rerun()

        # Restart thread if live but died after a hot-reload
        if live_on and not bg_is_running():
            start_bg_simulation(st.session_state.get("auto_sim_attack", 0.30))

        # Clear data
        st.divider()
        if st.button("Clear All Data", width="stretch"):
            stop_bg_simulation()
            st.session_state["auto_sim_on"] = False
            with get_conn() as conn:
                conn.executescript(
                    "DELETE FROM logs; "
                    "DELETE FROM alerts; "
                    "UPDATE agents SET log_count = 0;"
                )
            with _ssh_fail_lock:
                _ssh_fail_tracker.clear()
            st.success("Database cleared.")
            st.rerun()

        # Live stats mini-table
        st.divider()
        s = get_stats()
        st.markdown(
            "| Metric | Value |\n"
            "|---|---|\n"
            "| Logs | {:,} |\n"
            "| Alerts | {:,} |\n"
            "| Open | {:,} |\n"
            "| Critical | {:,} |\n"
            "| +Logs /min | {} |\n"
            "| +Alerts /min | {} |\n"
            "| Last Event | {} |".format(
                s["total_logs"], s["total_alerts"], s["open_alerts"],
                s["critical"], s["logs_1m"], s["alerts_1m"], s["last_event"])
        )

        # Auto-refresh loop when Live Mode is active
        if live_on:
            time.sleep(AUTO_SIM_SECS)
            st.rerun()

    return page


# ==============================================================================
#  MAIN ENTRY POINT
# ==============================================================================

def main():
    """Configure Streamlit, initialise the database, and dispatch to a page."""

    st.set_page_config(
        page_title="Mini-SIEM Lab",
        page_icon=":shield:",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "About": (
                "Mini-SIEM Lab - a single-file Wazuh-inspired SIEM simulator.\n"
                "Run with:  streamlit run Hritik_Kumar_Prajapati_mini_siem.py"
            ),
        },
    )

    # Global CSS overrides
    st.markdown("""
    <style>
    [data-testid="stMetricValue"]            { font-size: 1.45rem; font-weight: 700; }
    [data-testid="stSidebar"]                { background-color: #0d1117; }
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] .stCaption     { color: #c9d1d9 !important; }
    [data-testid="stSidebar"] .stMarkdown    { color: #c9d1d9 !important; }
    .block-container                         { padding-top: 1.5rem; }
    </style>
    """, unsafe_allow_html=True)

    init_db()
    page = render_sidebar()

    dispatch = {
        "Dashboard":       page_dashboard,
        "Alerts":          page_alerts,
        "Log Search":      page_log_search,
        "Agents":          page_agents,
        "Detection Rules": page_rules,
        "MITRE ATT&CK":    page_mitre,
        "Analytics":       page_analytics,
    }
    dispatch.get(page, page_dashboard)()


if __name__ == "__main__":
    main()
