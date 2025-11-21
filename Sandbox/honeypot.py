import socket
import threading
import logging
import datetime
import time
import queue
import os
import sys
import traceback
from collections import defaultdict, deque

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
except Exception:
    class Dummy:
        RESET_ALL = ''
    Fore = type('x', (), {'RED':'','YELLOW':'','GREEN':'','CYAN':'','MAGENTA':'','WHITE':''})
    Style = Dummy()

PORTS = [9999, 2222, 8080]        
LOGFILE = "honeypot_logs.txt"
REALTIME_REFRESH = True          
REALTIME_INTERVAL = 2.0          
SUSPICIOUS_THRESHOLD = 5         
WINDOW = 10.0                    
ENABLE_EMAIL_ALERT = False       
ENABLE_TELEGRAM_ALERT = False    
AUTO_BAN = True                  
SYSTEM_BLOCK_COMMAND = None      

EMAIL_SMTP_SERVER = "smtp.example.com"
EMAIL_SMTP_PORT = 587
EMAIL_USERNAME = "you@example.com"
EMAIL_PASSWORD = "yourpassword"
EMAIL_TO = ["admin@example.com"]

TELEGRAM_BOT_TOKEN = "123456:ABC-DEF..."
TELEGRAM_CHAT_ID = "-1001234567890"

SUSPICIOUS_KEYWORDS = ["nmap", "masscan", "sqlmap", "admin", "/etc/passwd", "uname", "curl", "wget"]

MAX_LOG_BYTES = 1024

logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

console_lock = threading.Lock()

connections_by_ip = defaultdict(lambda: deque()) 
ban_list = set()                                
alert_queue = queue.Queue()

def now_ts():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def is_suspicious_payload(data):
    low = data.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in low:
            return True
    return False

def send_email_alert(subject, body):
    if not ENABLE_EMAIL_ALERT:
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USERNAME
        msg['To'] = ','.join(EMAIL_TO)

        s = smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT, timeout=10)
        s.starttls()
        s.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        s.sendmail(EMAIL_USERNAME, EMAIL_TO, msg.as_string())
        s.quit()
        return True
    except Exception as e:
        logging.info(f"Email alert failed: {e}")
        return False


def send_telegram_alert(text):
    if not ENABLE_TELEGRAM_ALERT:
        return False
    try:
        import requests
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text})
        return r.status_code == 200
    except Exception as e:
        logging.info(f"Telegram alert failed: {e}")
        return False


def queue_alert(subject, body):
    alert_queue.put((subject, body))


def alert_worker():
    while True:
        try:
            subject, body = alert_queue.get()
            send_email_alert(subject, body)
            send_telegram_alert(subject + "\n" + body)
        except Exception:
            logging.info("Alert worker exception:\n" + traceback.format_exc())
        finally:
            alert_queue.task_done()

def ban_ip(ip):
    if ip in ban_list:
        return False
    ban_list.add(ip)
    logging.info(f"BANNED IP (simulated): {ip}")

    if SYSTEM_BLOCK_COMMAND:
        try:
            cmd = SYSTEM_BLOCK_COMMAND.format(ip=ip)
            logging.info(f"Would run system block command: {cmd}")
        except Exception as e:
            logging.info(f"System block failed: {e}")
    return True


def handle_client(client_socket, client_address, listening_port):
    ip, remote_port = client_address

    if ip in ban_list:
        try:
            client_socket.close()
        except:
            pass
        return

    hostname = get_reverse_dns(ip)
    ts = now_ts()

    t = time.time()
    dq = connections_by_ip[ip]
    dq.append(t)
    while dq and dq[0] < t - WINDOW:
        dq.popleft()

    conn_count = len(dq)

    try:
        data = client_socket.recv(2048)
        data_str = data.decode(errors='ignore')[:MAX_LOG_BYTES] if data else ''
    except Exception:
        data_str = ''

    log_msg = f"ListeningPort={listening_port} - Connection from IP: {ip}, Port: {remote_port}, Host: {hostname}, CountWindow={conn_count}"
    if data_str:
        log_msg += f", Data={repr(data_str)}"
    logging.info(log_msg)

    with console_lock:
        header = f"[{ts}] Port {listening_port} <- {ip}:{remote_port} ({hostname})"
        if conn_count >= SUSPICIOUS_THRESHOLD or is_suspicious_payload(data_str):
            print(Fore.RED + header + Style.RESET_ALL)
        else:
            print(Fore.CYAN + header + Style.RESET_ALL)
        if data_str:
            first_line = data_str.splitlines()[0]
            if is_suspicious_payload(data_str):
                print(Fore.YELLOW + f"  PAYLOAD (suspicious): {first_line[:200]}" + Style.RESET_ALL)
            else:
                print(f"  Payload: {first_line[:200]}")

    if conn_count >= SUSPICIOUS_THRESHOLD or is_suspicious_payload(data_str):
        reason = []
        if conn_count >= SUSPICIOUS_THRESHOLD:
            reason.append(f"{conn_count} connections in {WINDOW}s")
        if is_suspicious_payload(data_str):
            reason.append("suspicious payload")
        reason_text = ' & '.join(reason)

        subject = f"[HONEYPOT] Suspicious activity from {ip}"
        body = f"Time: {ts}\nIP: {ip}\nHost: {hostname}\nPort: {listening_port}\nReason: {reason_text}\nSample: {data_str[:500]}"
        queue_alert(subject, body)

        if AUTO_BAN:
            ban_ip(ip)

    try:
        client_socket.close()
    except:
        pass

def server_thread(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    with console_lock:
        print(Fore.GREEN + f"[+] Honeypot listening on port {port}" + Style.RESET_ALL)
    while True:
        try:
            client_socket, client_address = server.accept()
            t = threading.Thread(target=handle_client, args=(client_socket, client_address, port), daemon=True)
            t.start()
        except Exception:
            logging.info("Server thread exception:\n" + traceback.format_exc())

def tail_log_and_dashboard():
    last_size = 0
    try:
        while True:
            total_conns = sum(len(v) for v in connections_by_ip.values())
            top_ips = sorted(connections_by_ip.items(), key=lambda kv: len(kv[1]), reverse=True)[:5]
            with console_lock:
                print('\n' + '-'*60)
                print(Fore.MAGENTA + f"[DASHBOARD] Time: {now_ts()} | Ports: {PORTS} | Active tracked IPs: {len(connections_by_ip)} | Total recent events: {total_conns}" + Style.RESET_ALL)
                print("Top IPs (recent window):")
                for ip, dq in top_ips:
                    mark = Fore.RED + ' SUSPICIOUS' + Style.RESET_ALL if ip in ban_list or len(dq) >= SUSPICIOUS_THRESHOLD else ''
                    print(f"  {ip:20}  count={len(dq):2}{mark}")
                print('-'*60)
            time.sleep(REALTIME_INTERVAL)
    except KeyboardInterrupt:
        print("Stopping dashboard")

def main():
    tw = threading.Thread(target=alert_worker, daemon=True)
    tw.start()

    for p in PORTS:
        t = threading.Thread(target=server_thread, args=(p,), daemon=True)
        t.start()

    if REALTIME_REFRESH:
        try:
            tail_log_and_dashboard()
        except Exception:
            logging.info("Dashboard exception:\n" + traceback.format_exc())
    else:
        while True:
            time.sleep(60)

if __name__ == '__main__':
    try:
        print("Starting enhanced honeypot...")
        main()
    except Exception:
        logging.info("Fatal exception:\n" + traceback.format_exc())
        raise