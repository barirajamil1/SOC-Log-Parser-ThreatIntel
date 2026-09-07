# 🛡️ Automated Threat Intel & SOC Triage Parser

A lightweight, automated Python security tool designed to parse system logs (`auth.log`, web logs), detect brute-force login attempts and IOCs, and query public Threat Intelligence APIs (AbuseIPDB / VirusTotal) for real-time risk enrichment and alert triage.

Developed by **Barira Jamil** | *Cyber Security Specialist*

---

## ✨ Features
- **Log Parsing Engine:** Extracts IPv4 addresses and failure signatures using Regular Expressions (Regex).
- **Brute-Force Detection:** Flags IPs exceeding user-defined threshold limits (e.g., SSH login failures).
- **Threat Intel Enrichment:** Automatically queries AbuseIPDB REST API to check IP reputation & confidence scores.
- **Structured SOC Alerts:** Outputs JSON-formatted incident reports for SIEM ingestion or Tier-1 SOC triage.

---

## 🚀 Quick Start & Usage

### Prerequisites
```bash
pip install requests
