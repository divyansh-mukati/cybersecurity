Cyber-Security Educational Sandbox

Introduction:
This project is a beginner-friendly cyber-security sandbox designed to help students understand basic security concepts using simple Python scripts.
It includes three main modules:
                                File Integrity Checker
                                Network Monitor
                                Simple Honeypot

These modules teach how to monitor file changes, track network activity, and detect suspicious connections.
The project is fully customizable and can be extended easily.

Features:

🟦 1. File Integrity Checker:
                             A tool to detect unwanted or accidental changes in important files.
                             Calculates SHA-256 hash of target files.
                             Compares the hash with saved hashes to check for tampering.
                             Detects modifications instantly.
                             Stores hash history in a folder for auditing.
                             Logs every change with timestamp.
                             When they detect any change it sends mail.


Why it is useful:
It helps you understand how security systems detect unauthorized changes in files such as configuration files, passwords, or system binaries.

🟩 2. Network Monitor:
                       A real-time monitoring utility that shows all active network connections on your system.
                       Displays local IP, processes, and ports in use.
                       Highlights suspicious or unknown ports in red.
                       Refreshes automatically every 5 seconds.
                       Performs reverse DNS lookup to find domain names of remote connections.
                       Shows protocol (TCP/UDP), program name, PID, and connection status.

Why it is useful:
You learn how to detect unwanted background connections, malware communication, or unknown services using your system network.

🟧 3. Simple Honeypot
                       A small server that listens on a fake port (e.g., 9999).
                       Logs every attempt to connect.
                       Captures IP, timestamp, and attempted data.
                       Helps simulate basic attacker scanning or port-scanning behavior.
                       Very safe for beginners, does not expose your system.

Why it is useful:
You understand how attackers scan open ports and how security teams track suspicious behavior using honeypots.

How to Run
          1) Install dependencies
               pip install -r requirements.txt
          2) Run the File Integrity Checker
               python file_integrity_checker.py
          3) Run the Network Monitor
               python network_monitor.py
          4) Run the Simple Honeypot
               python honeypot.py
          5) View Logs
               Logs are stored in organized folders:
               logs/ → Network logs, honeypot logs
               hash_history/ → Old file hashes
               honeypot_logs/ → Detected connection attempts
               You can read these log files to study behavior and events.


Screenshots:
             All screenshots are stored inside /screenshots


Recordings:
           All recordings are stored inside /recordings



Folder Structure:
                 Cyber-Security-Sandbox/
                                         ├── README.md
                                         ├── requirements.txt
                                         ├── license
                                         ├── main.py
                                         ├── 05_sandbox/
                                             ├── network_monitor.py
                                             ├── file_integrity.py
                                             ├── honeypot.py
                                             ├── hash_history/
                                             ├── archive_versions/
                                             ├── alerts/
                                             └── honeypot_logs/
                                         ├── docs/
                                         ├── screenshots/
                                         └── recordings/


Author:
Divyansh Mukati
25MEI100754
VIT Bhopal 
