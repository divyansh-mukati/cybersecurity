import socket
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.live import Live
from rich.console import Console
from rich.text import Text
from rich.panel import Panel

console = Console()

REFRESH_INTERVAL = 5.0  
DNS_WORKERS = 20
DNS_TIMEOUT = 2.0  
MAX_DNS_LOOKUPS = 60  

RISKY_PORTS = {
    23: "Telnet (23)",
    3389: "RDP (3389)",
    5900: "VNC (5900)",
    21: "FTP (21)",
    22: "SSH (22)",
    27017: "MongoDB (27017)",
    3306: "MySQL (3306)",
    1433: "MSSQL (1433)",
    6379: "Redis (6379)",
}

PRIVATE_PREFIXES = (
    ("10.",),
    ("172.",),  
    ("192.168.",),
    ("127.",),
    ("169.254.",),
    ("::1",),
    ("fc",), ("fd",)  
)


def is_private_ip(ip):
    if not ip:
        return False
    try:
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("169.254."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    return 16 <= second <= 31
                except Exception:
                    return False
        if ip.startswith("::1") or ip.startswith("fe80") or ip.startswith("fc") or ip.startswith("fd"):
            return True
    except Exception:
        pass
    return False


def get_local_ip(remote_host="8.8.8.8", remote_port=53):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect((remote_host, remote_port))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def reverse_dns_lookup(ips, timeout=DNS_TIMEOUT):
 
    results = {}
    unique_ips = list(dict.fromkeys([ip for ip in ips if ip]))[:MAX_DNS_LOOKUPS]

    def _resolve(ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
            return ip, name
        except Exception:
            return ip, ""

    with ThreadPoolExecutor(max_workers=min(DNS_WORKERS, len(unique_ips) or 1)) as exe:
        futures = {exe.submit(_resolve, ip): ip for ip in unique_ips}
        for fut in as_completed(futures, timeout=timeout * len(unique_ips) + 1):
            try:
                ip, host = fut.result(timeout=timeout)
                results[ip] = host
            except Exception:
                ip = futures.get(fut)
                if ip:
                    results[ip] = ""
    for ip in unique_ips:
        if ip not in results:
            results[ip] = ""
    return results


def format_addr(addr):
    if not addr:
        return ""
    return f"{addr.ip}:{addr.port}"


def build_tables():
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        console.print("[red]Error reading net connections (permissions?)[/red]", e)
        conns = []

    remote_ips = []
    for c in conns:
        if c.raddr:
            remote_ips.append(c.raddr.ip)

    dns_map = reverse_dns_lookup(remote_ips)

    active = Table(title="Active Connections (refreshed every {}s)".format(REFRESH_INTERVAL), expand=True, show_lines=False)
    active.add_column("Proto", width=5)
    active.add_column("Local Address", width=22)
    active.add_column("Remote Address", width=26)
    active.add_column("Remote Hostname", width=30)
    active.add_column("Status", width=12)
    active.add_column("PID", width=6)
    active.add_column("Program", width=20)

    listening = Table(title="Listening / Open Ports", expand=True, show_lines=False)
    listening.add_column("Proto", width=5)
    listening.add_column("Local Address", width=22)
    listening.add_column("PID", width=6)
    listening.add_column("Program", width=20)
    listening.add_column("Notes", width=30)

    for c in conns:
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        laddr = format_addr(c.laddr)
        raddr = format_addr(c.raddr)
        pid = str(c.pid) if c.pid else ""
        pname = ""
        try:
            if c.pid:
                pname = psutil.Process(c.pid).name()
        except Exception:
            pname = ""

        notes = ""
        row_style = None

        if c.raddr:
            rip = c.raddr.ip
            host = dns_map.get(rip, "")
            if not is_private_ip(rip) and not host:
                row_style = "yellow"
                notes = "Public IP, no rDNS"
            elif not is_private_ip(rip) and host:
                pass
        if proto == "TCP" and c.status == "LISTEN":
            pass
        else:
            active.add_row(proto, laddr, raddr, dns_map.get(c.raddr.ip, "") if c.raddr else "", c.status, pid, pname, style=row_style)

    listeners = [c for c in conns if getattr(c, "status", "").upper() == "LISTEN" or (c.laddr and (c.laddr.port is not None))]
    seen_listen = set()
    for c in listeners:
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        if not c.laddr:
            continue
        port = c.laddr.port
        lstr = format_addr(c.laddr)
        pid = str(c.pid) if c.pid else ""
        pname = ""
        try:
            if c.pid:
                pname = psutil.Process(c.pid).name()
        except Exception:
            pname = ""

        key = (proto, port, pid)
        if key in seen_listen:
            continue
        seen_listen.add(key)

        note_text = ""
        row_style = None

        ip_only = c.laddr.ip if c.laddr else ""
        if ip_only in ("0.0.0.0", "::", "") or ip_only.startswith("::"):
            row_style = "yellow"
            note_text += "Bound to all interfaces; exposed. "

        if port in RISKY_PORTS:
            row_style = "red"
            note_text += f"Risky port: {RISKY_PORTS[port]}. "

        if port in (135, 139, 445):
            note_text += "Windows service port. "

        listening.add_row(proto, lstr, pid, pname, note_text, style=row_style)

    local_ip = get_local_ip()
    header = Panel(
        Text(f"Local IP: {local_ip}\nRefresh: {REFRESH_INTERVAL}s    Reverse DNS timeout: {DNS_TIMEOUT}s    DNS lookups (cap): {MAX_DNS_LOOKUPS}", justify="left"),
        title="Network Monitor (live)",
        expand=True,
    )

    return header, active, listening


def main_loop():
    with Live(console=console, refresh_per_second=4, screen=True) as live:
        try:
            while True:
                header, active_table, listening_table = build_tables()
                from rich.layout import Layout
                layout = Layout()
                layout.split_column(
                    Layout(header, name="header", size=3),
                    Layout(active_table, name="active"),
                    Layout(listening_table, name="listening", size=14),
                )
                live.update(layout)
                time.sleep(REFRESH_INTERVAL)
        except KeyboardInterrupt:
            console.print("\n[bold]Stopped by user.[/bold]")


if __name__ == "__main__":
    console.print("[green]Starting real-time network monitor.[/green] Press Ctrl+C to stop.")
    console.print("Note: run with elevated privileges for more complete info (paths/PIDs).")
    main_loop()