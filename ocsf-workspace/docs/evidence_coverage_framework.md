# Digital Evidence Coverage Framework

## Purpose
We unify heterogeneous digital evidence into OCSF to enable downstream analysis and correlation.

## Evidence Taxonomy

### 1) Identity & Authentication Evidence
**Why it matters:** Authentication events show who accessed what, when, and how—core to attribution and access audits.

**Coverage complete checklist:**
- Event timestamp
- Subject user identity (name, SID, or unique identifier)
- Authentication outcome (success/failure)
- Authentication method or logon type
- Source host/device
- Target host/resource

**Example sources:** Windows Security (4624/4625), IdP logs (Okta/Azure AD), RADIUS/LDAP.

**Current status:** **Covered** (Windows Security 4624/4625)

---

### 2) Process & Execution Evidence
**Why it matters:** Process execution provides intent and context for activity on endpoints, including malware and admin actions.

**Coverage complete checklist:**
- Event timestamp
- Process name and executable path
- Process ID
- Command line
- Parent process name/path and parent process ID
- User context

**Example sources:** Sysmon EventID 1, EDR process telemetry.

**Current status:** **Partial** (Sysmon EventID 1 but missing full lineage/commandline coverage)

---

### 3) File & Artifact Evidence
**Why it matters:** File creation/modification signals data staging, persistence, or payload delivery.

**Coverage complete checklist:**
- Event timestamp
- File path
- File name
- File hash (if available)
- Operation type (create/modify/delete)
- User context

**Example sources:** Sysmon EventID 11, file artifact collections, AV/forensics tooling.

**Current status:** **Covered** (File Artifact + Sysmon EventID 11; with optional context)

---

### 4) Network Activity Evidence
**Why it matters:** Network activity reveals external communication, C2, data exfiltration, and lateral movement.

**Coverage complete checklist:**
- Event timestamp
- Source/destination IPs
- Source/destination ports
- Protocol
- Direction
- Bytes/packets (if available)
- Duration (if available)

**Example sources:** Sysmon EventID 3, Zeek DNS, NetFlow/Zeek conn.log, firewall logs.

**Current status:** **Partial** (Sysmon EventID 3 + DNS via Sysmon 22 and Zeek DNS, but missing full flow/bytes/duration)

---

### 5) Security Detection Evidence
**Why it matters:** Alerts provide high-signal detection of known threats and suspicious behaviors.

**Coverage complete checklist:**
- Event timestamp
- Detection name/signature
- Severity or priority
- Source sensor/product
- Affected host or asset
- Related network or file indicators

**Example sources:** Suricata alerts, IDS/IPS, EDR detections.

**Current status:** **Covered** (Suricata alerts)

---

### 6) System Configuration & Persistence Evidence
**Why it matters:** Configuration and persistence changes show how adversaries maintain access.

**Coverage complete checklist:**
- Event timestamp
- Configuration object (registry key/service/task)
- Operation type (create/modify/delete)
- New value or configuration
- User/process context
- Host/device

**Example sources:** Sysmon EventID 12/13/14, Windows Service Control Manager, scheduled task logs.

**Current status:** **Missing**

---

### 7) Application & Access Evidence
**Why it matters:** Application logs reveal user actions, access attempts, and data interactions beyond OS-level events.

**Coverage complete checklist:**
- Event timestamp
- Application or service name
- User identity
- Action type (read/write/update)
- Resource or object accessed
- Outcome (success/failure)

**Example sources:** Web server logs, database audit logs, SaaS audit trails.

**Current status:** **Missing**

---

### 8) Cloud & Infrastructure Evidence
**Why it matters:** Cloud control plane and infrastructure telemetry show API activity and configuration drift.

**Coverage complete checklist:**
- Event timestamp
- Cloud account/tenant
- Actor identity
- API or action name
- Resource identifiers
- Source IP/region
- Outcome

**Example sources:** AWS CloudTrail, Azure Activity Logs, GCP Audit Logs.

**Current status:** **Missing**

---

## Phase 1 Baseline Coverage
Phase 1 is complete when:
- Strong endpoint + network baseline is present (process, network, file, DNS, auth, detections).
- Every output includes: `time`, `class_uid`, `activity_id`, `type_uid`, `metadata.product`, `unmapped.original_event`.

## Next recommended implementations (priority order)
1) **Process lineage (parent/child) improvements** — enrich process relationships to improve pivoting and provenance.
2) **Network flow evidence (Zeek conn.log or NetFlow style)** — add flow/bytes/duration for full network context.
3) **Persistence evidence (registry/services/scheduled tasks)** — capture long-lived changes that enable re-entry.
