Cyber-Security Educational Sandbox
Introduction

This project is a beginner-friendly cyber-security sandbox designed to help students understand basic security concepts using simple Python scripts.
It includes three main modules:

File Integrity Checker

Network Monitor

Simple Honeypot

These modules teach how to monitor file changes, track network activity, and detect suspicious connections.
The project is fully customizable and easy to extend.

Features
🟦 1. File Integrity Checker

A tool to detect unwanted or accidental changes in important files.

Calculates SHA-256 hash of target files

Compares the hash with saved hashes

Detects modifications instantly

Sends email alert when a change is found

Stores hash history for auditing

Logs every change with a timestamp

Why it is useful:
Helps understand how systems detect unauthorized file changes such as tampering, malware edits, or misconfigurations.

🟩 2. Network Monitor

A real-time tool to watch active network connections in your system.

Shows local IP, active processes, and used ports

Highlights suspicious ports in red

Auto-refreshes every 5 seconds

Performs reverse DNS lookup

Displays protocol (TCP/UDP), PID, program name, and status

Why it is useful:
Teaches how to detect malware connections, unknown services, or hidden background traffic.

🟧 3. Simple Honeypot

A basic honeypot that listens on a fake port (e.g., 9999).

Logs every connection attempt

Captures attacker IP, timestamp, and request details

Helps simulate port scanning behavior

Very safe for beginners

Why it is useful:
Shows how cyber-security teams detect attackers by using honeypots.

How to Run
1. Install dependencies
pip install -r requirements.txt

2. Run the File Integrity Checker
python file_integrity_checker.py

3. Run the Network Monitor
python network_monitor.py

4. Run the Honeypot
python honeypot.py

View Logs

Logs are stored in:

logs/ → Network & honeypot logs

hash_history/ → Previous file hashes

honeypot_logs/ → Honeypot alerts

You can open these files to study behavior and events.

Screenshots

All screenshots are stored in:

/screenshots

Recordings

All recordings are stored in:

/recordings

Folder Structure
Cyber-Security-Sandbox/
│
├── README.md
├── requirements.txt
├── license/
│   └── LICENSE
│
├── main.py
│
├── 05_sandbox/
│   ├── network_monitor.py
│   ├── file_integrity.py
│   ├── honeypot.py
│   ├── hash_history/
│   ├── archive_versions/
│   ├── alerts/
│   └── honeypot_logs/
│
├── docs/
├── screenshots/
└── recordings/

Author

Divyansh Mukati
25MEI100754
VIT Bhopal
