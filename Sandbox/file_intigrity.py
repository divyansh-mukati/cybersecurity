import hashlib
import os
import shutil
import traceback
from pathlib import Path
from datetime import datetime
from getpass import getpass
import smtplib
import ssl
from email.message import EmailMessage

HASH_FILE = "file_hash.txt"
HASH_HISTORY_DIR = Path("hash_history")
ARCHIVE_DIR = Path("archive_versions")
ALERTS_DIR = Path("alerts")
PEER_CERT = Path("peer_cert.pem")   
EMAIL_DEBUG_LOG = Path("email_debug.log")

def log_debug(text: str):
    ts = datetime.now().isoformat()
    entry = f"{ts} {text}\n"
    EMAIL_DEBUG_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(EMAIL_DEBUG_LOG, "a", encoding="utf-8") as lf:
        lf.write(entry)

def sanitize_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in s)[:120]

def get_path_from_user():
    while True:
        raw = input("📁 Drag & drop file or folder here OR type path (or 'quit'): ").strip()
        if not raw:
            print("❌ Please enter a path or 'quit'.")
            continue
        if raw.lower() in ("quit", "exit"):
            return None
        if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
            raw = raw[1:-1]
        p = Path(raw).expanduser()
        try:
            p = p.resolve()
        except Exception:
            p = p.absolute()
        if not p.exists():
            print(f"❌ Path does NOT exist: {p}")
            continue
        print(f"✅ Selected: {p} ({'folder' if p.is_dir() else 'file'})")
        return p

def hash_file(path: Path):
    sha = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception as e:
        print("❌ Error hashing file:", e)
        log_debug(f"Error hashing file {path}: {e}\n{traceback.format_exc()}")
        return None

def hash_folder(folder: Path):
    sha = hashlib.sha256()
    base = folder.resolve()
    files = []
    for root, dirs, filenames in os.walk(base):
        dirs.sort()
        filenames.sort()
        for name in filenames:
            filepath = Path(root) / name
            if not filepath.is_file():
                continue
            files.append(filepath)
    files.sort(key=lambda p: str(p.relative_to(base)).lower())
    for f in files:
        rel = str(f.relative_to(base)).replace("\\", "/")
        size = f.stat().st_size
        sha.update(b"PATH:" + rel.encode("utf-8") + b"\n")
        sha.update(b"SIZE:" + str(size).encode("utf-8") + b"\n")
        try:
            with f.open("rb") as fh:
                for chunk in iter(lambda: fh.read(4096), b""):
                    sha.update(chunk)
            sha.update(b"\n---FILE-END---\n")
        except Exception as e:
            print(f"⚠️ Warning: could not read {f}: {e}")
            log_debug(f"Warning reading {f}: {e}\n{traceback.format_exc()}")
            sha.update(b"\n---FILE-ERROR---\n")
    return sha.hexdigest()

def compute_hash(path: Path):
    if path.is_file():
        return ("file", hash_file(path))
    elif path.is_dir():
        return ("folder", hash_folder(path))
    return (None, None)

def read_saved_hash():
    if not Path(HASH_FILE).exists():
        return None
    try:
        with open(HASH_FILE, "r") as f:
            return f.read().strip()
    except Exception as e:
        log_debug(f"Error reading baseline {HASH_FILE}: {e}\n{traceback.format_exc()}")
        return None

def save_hash(hash_value: str):
    try:
        with open(HASH_FILE, "w") as f:
            f.write(hash_value)
        print("✅ New baseline saved to", HASH_FILE)
    except Exception as e:
        print("❌ Failed to write baseline:", e)
        log_debug(f"Failed to write baseline: {e}\n{traceback.format_exc()}")

def archive_old_state(path: Path, old_hash: str):
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_name(path.name)
    HASH_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    hist_file = HASH_HISTORY_DIR / f"{now}_{safe_name}.hash"
    try:
        with open(hist_file, "w") as hf:
            hf.write(f"timestamp: {now}\npath: {str(path)}\nold_hash: {old_hash}\n")
        print("📦 Old hash archived to:", hist_file)
    except Exception as e:
        print("⚠️ Failed to save old hash:", e)
        log_debug(f"Failed to save old hash: {e}\n{traceback.format_exc()}")

    archive_target = ARCHIVE_DIR / f"{now}_{safe_name}"
    try:
        if path.is_file():
            dest = archive_target.with_suffix(path.suffix)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            print("📁 Previous file copied to:", dest)
        elif path.is_dir():
            dest_dir = archive_target
            if dest_dir.exists():
                dest_dir = ARCHIVE_DIR / f"{now}_{safe_name}_dup"
            shutil.copytree(path, dest_dir)
            print("📂 Previous folder copied to:", dest_dir)
    except Exception as e:
        print("⚠️ Failed to archive previous state:", e)
        log_debug(f"Failed to archive {path}: {e}\n{traceback.format_exc()}")

def ask_gmail_settings():
    choice = input("Do you want Gmail alerts on modification? (y/n): ").strip().lower()
    if choice not in ("y", "yes"):
        return None
    sender = input("Sender Gmail address (e.g. you@gmail.com): ").strip()
    recipient = input("Recipient email address: ").strip()
    print("Enter your Gmail App Password (16 characters). It will be hidden.")
    app_pass = getpass("App password (hidden): ").strip().replace(" ", "")
    return {"sender": sender, "recipient": recipient, "app_pass": app_pass}

def build_ssl_context_secure():
    """
    Attempt to build an SSLContext using certifi and optional peer_cert.pem (if present).
    Returns (context, description) or (None, msg) on failure.
    """
    try:
        import certifi
        certifi_path = certifi.where()
    except Exception as e:
        certifi_path = None
        log_debug(f"certifi import failed: {e}\n{traceback.format_exc()}")

    if PEER_CERT.exists():
        try:
            if certifi_path and Path(certifi_path).exists():
                base = Path(certifi_path).read_bytes()
                peer = PEER_CERT.read_bytes()
                COMBINED = Path("combined-ca.pem")
                COMBINED.write_bytes(base + b"\n" + peer)
                ctx = ssl.create_default_context(cafile=str(COMBINED.resolve()))
                return ctx, f"Using combined CA bundle: {COMBINED}"
            else:
                ctx = ssl.create_default_context(cafile=str(PEER_CERT.resolve()))
                return ctx, f"Using peer_cert.pem as CA file: {PEER_CERT}"
        except Exception as e:
            log_debug(f"Failed to build combined CA: {e}\n{traceback.format_exc()}")

    if certifi_path and Path(certifi_path).exists():
        try:
            ctx = ssl.create_default_context(cafile=certifi_path)
            return ctx, f"Using certifi CA bundle: {certifi_path}"
        except Exception as e:
            log_debug(f"Failed to use certifi: {e}\n{traceback.format_exc()}")

    try:
        ctx = ssl.create_default_context()
        return ctx, "Using system default SSL context (may fail)"
    except Exception as e:
        log_debug(f"Failed to create any SSL context: {e}\n{traceback.format_exc()}")
        return None, "Could not create SSL context"

def send_email_secure(subject, body, sender_email, app_password, recipient_email):
    """
    Try secure send (STARTTLS) with built SSL context.
    Returns (True, None) on success, or (False, error_message) on failure.
    """
    smtp_server = "smtp.gmail.com"
    port = 587
    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.set_content(body)

    ctx, desc = build_ssl_context_secure()
    log_debug(f"Attempting secure send. Context: {desc}")
    try:
        with smtplib.SMTP(smtp_server, port, timeout=30) as server:
            server.set_debuglevel(1)
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(sender_email, app_password)
            server.send_message(msg)
        log_debug("Secure send succeeded.")
        return True, None
    except Exception as e:
        tb = traceback.format_exc()
        err = f"{type(e).__name__}: {e}"
        log_debug("Secure send failed: " + err + "\n" + tb)
        return False, err

def send_email_insecure(subject, body, sender_email, app_password, recipient_email):
    """
    INSECURE: disables SSL certificate verification. Use only temporarily.
    Returns (True, None) on success, or (False, error_message) on failure.
    """
    smtp_server = "smtp.gmail.com"
    port = 587
    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.set_content(body)

    ctx = ssl._create_unverified_context()  
    log_debug("Attempting INSECURE send (no cert verification).")
    try:
        with smtplib.SMTP(smtp_server, port, timeout=30) as server:
            server.set_debuglevel(1)
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(sender_email, app_password)
            server.send_message(msg)
        log_debug("INSECURE send succeeded.")
        return True, None
    except Exception as e:
        tb = traceback.format_exc()
        err = f"{type(e).__name__}: {e}"
        log_debug("INSECURE send failed: " + err + "\n" + tb)
        return False, err

def notify_local_and_log(subject, body, smtp_debug=None, show_toast=False):
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = sanitize_name(subject)[:80]
    fn = ALERTS_DIR / f"{ts}_{safe}.txt"
    with open(fn, "w", encoding="utf-8") as f:
        f.write(f"timestamp: {ts}\nsubject: {subject}\n\n{body}\n")
    print("✅ Local alert saved to:", fn)
    if smtp_debug:
        log_debug(f"SMTP debug for alert '{subject}':\n{smtp_debug}")
    if show_toast:
        try:
            from win10toast import ToastNotifier
            t = ToastNotifier()
            t.show_toast(subject, body[:200], duration=8, threaded=True)
        except Exception as e:
            log_debug(f"Toast not shown: {e}")

def main():
    print("=== File/Folder Integrity Checker (with INSECURE SMTP fallback option) ===")
    email_cfg = ask_gmail_settings()

    path = get_path_from_user()
    if path is None:
        print("Exiting.")
        return

    kind, new_hash = compute_hash(path)
    if new_hash is None:
        print("Could not compute hash. Exiting.")
        return

    print(f"\n🔍 Computed {kind} hash: {new_hash}")

    old_hash = read_saved_hash()
    if old_hash is None:
        print("ℹ️ No baseline found. Saving current hash as baseline.")
        save_hash(new_hash)
        return

    print("🔍 Saved baseline hash:", old_hash)
    if old_hash == new_hash:
        print("\n✅ No changes detected.")
        return

    print("\n⚠️ CHANGES DETECTED!")
    try:
        archive_old_state(path, old_hash)
    except Exception as e:
        print("⚠️ Error while archiving old state:", e)
        log_debug(f"Archive error: {e}\n{traceback.format_exc()}")

    save_hash(new_hash)

    if email_cfg:
        subject = f"ALERT: {kind.capitalize()} changed - {path.name}"
        body = (f"{kind.capitalize()} path: {path}\n\nOld hash:\n{old_hash}\n\nNew hash:\n{new_hash}\n\n"
                f"Archived old state to {ARCHIVE_DIR} and saved new baseline to {HASH_FILE}.")
        ok, err = send_email_secure(subject, body, email_cfg["sender"], email_cfg["app_pass"], email_cfg["recipient"])
        if ok:
            print("✉️ Secure email sent successfully.")
        else:
            print("❌ Secure email failed:", err)
            ans = input("Secure send failed due to TLS. Retry once with INSECURE TLS (disable verification)? (y/n): ").strip().lower()
            if ans in ("y","yes"):
                ok2, err2 = send_email_insecure(subject, body, email_cfg["sender"], email_cfg["app_pass"], email_cfg["recipient"])
                if ok2:
                    print("✉️ INSECURE email sent successfully (temporary).")
                    print("⚠️ Reminder: This disabled certificate verification — revert to secure when possible.")
                else:
                    print("❌ INSECURE email also failed:", err2)
                    notify_local_and_log(subject, body, smtp_debug=(err + "\n" + err2), show_toast=True)
            else:
                print("ℹ️ User declined INSECURE retry. Saving local alert instead.")
                notify_local_and_log(subject, body, smtp_debug=err, show_toast=True)
    else:
        print("ℹ️ Email alerts are disabled. Saving local alert.")
        notify_local_and_log(f"ALERT: {kind} changed - {path.name}", body, show_toast=True)

if __name__ == "__main__":
    main()