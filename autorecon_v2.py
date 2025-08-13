#!/usr/bin/env python3
import subprocess, os, sys, re, csv, datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

BANNER = r"""
   ___        __        ____                       __
  / _ | ___  / /__ ____/ __ \ ____ ___  ___  ___  / /_
 / __ |/ _ \/ / -_) __/ /_/ // __/(_-</ _ \/ _ \/ __/
/_/ |_/_//_/_/\__/_/  \____/ \__/___/\___/\___/\__/   v2
"""

def sh(cmd:list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def ensure_nmap():
    if sh(["which", "nmap"]).returncode != 0:
        print("[-] nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)

def ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def mkdirp(d:str):
    os.makedirs(d, exist_ok=True)

def discover_hosts(cidr:str):
    print(f"[+] Host discovery on {cidr} ...")
    # Fast ping sweep, no reverse DNS
    p = sh(["nmap", "-sn", "-n", cidr])
    live = []
    current_ip = None
    for line in p.stdout.splitlines():
        # Nmap scan report for 10.10.128.1
        m = re.search(r"^Nmap scan report for ([0-9.]+)$", line.strip())
        if m:
            current_ip = m.group(1)
        if "Host is up" in line and current_ip:
            live.append(current_ip)
            current_ip = None
    print(f"[+] Discovered {len(live)} live host(s).")
    return live, p.stdout

def scan_host(ip:str, ports:str, outdir:str):
    """
    Returns: dict with parsed fields + paths
    """
    # XML for parsing + normal text for humans
    xml_path = os.path.join(outdir, f"{ip}.xml")
    txt_path = os.path.join(outdir, f"{ip}.txt")

    cmd = ["nmap", "-sS", "-sV", "-O", "-T4", "-n", "-p", ports, "-oX", "-", ip]
    proc = sh(cmd)

    # Save pretty text too (same command but normal output for readability)
    human = sh(["nmap", "-sS", "-sV", "-O", "-T4", "-n", "-p", ports, ip])

    with open(xml_path, "w") as f:
        f.write(proc.stdout)
    with open(txt_path, "w") as f:
        f.write(human.stdout)

    # Parse XML
    parsed = {"ip": ip, "os": "", "ports": []}
    try:
        root = ET.fromstring(proc.stdout)
        # OS guess
        for osmatch in root.findall(".//os/osmatch"):
            parsed["os"] = osmatch.get("name")
            break
        # Ports
        for port in root.findall(".//port"):
            state = port.find("state").get("state")
            if state != "open":
                continue
            proto = port.get("protocol")
            portid = port.get("portid")
            svc = port.find("service")
            name = svc.get("name") if svc is not None else ""
            product = svc.get("product") if svc is not None else ""
            version = svc.get("version") if svc is not None else ""
            parsed["ports"].append({
                "proto": proto,
                "port": portid,
                "service": name,
                "product": product,
                "version": version
            })
    except ET.ParseError:
        pass

    parsed["xml_path"] = xml_path
    parsed["txt_path"] = txt_path
    return parsed

def write_csv(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP", "OS (guess)", "Proto", "Port", "Service", "Product", "Version"])
        for r in rows:
            if not r["ports"]:
                w.writerow([r["ip"], r["os"], "", "", "", "", ""])
            else:
                for p in r["ports"]:
                    w.writerow([r["ip"], r["os"], p["proto"], p["port"], p["service"], p["product"], p["version"]])

def write_html(rows, path, cidr, started_at):
    total_open = sum(len(r["ports"]) for r in rows)
    live = len(rows)
    with open(path, "w") as f:
        f.write(f"""<!doctype html>
<html lang="en"><meta charset="utf-8">
<title>AutoRecon v2 Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;margin:24px;background:#0b0f14;color:#e5e7eb}}
h1{{margin:0 0 6px}} .sub{{color:#93a1ad}}
.card{{background:#111827;padding:16px;border-radius:14px;box-shadow:0 4px 30px rgba(0,0,0,.2);margin:16px 0}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:8px 10px;border-bottom:1px solid #253044;text-align:left}}
th{{color:#a5b4fc}}
.badge{{display:inline-block;background:#1f2937;border-radius:999px;padding:4px 10px;margin-right:6px}}
</style>
<h1>AutoRecon v2 Report</h1>
<div class="sub">Range: {cidr} • Generated: {started_at} • Live Hosts: {live} • Open Ports: {total_open}</div>
""")
        for r in rows:
            f.write(f'<div class="card"><h2>{r["ip"]}</h2>')
            f.write(f'<div class="sub">OS (guess): {r["os"] or "Unknown"}</div>')
            if r["ports"]:
                f.write("<table><tr><th>Proto</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>")
                for p in r["ports"]:
                    f.write(f"<tr><td>{p['proto']}</td><td>{p['port']}</td><td>{p['service']}</td><td>{p['product']}</td><td>{p['version']}</td></tr>")
                f.write("</table>")
            else:
                f.write('<div class="sub">No open ports found in selected range.</div>')
            f.write("</div>\n")
        f.write("</html>")

def main():
    print(BANNER)
    ensure_nmap()

    cidr = input("Enter network range: ").strip()
    ports = input("Ports to scan: ").strip() or "1-1000"
    if ports.lower() == "full":
        ports = "1-65535"
    try:
        threads = int(input("Threads (suggest 50-200): ").strip() or "100")
    except ValueError:
        threads = 100

    started_at = ts()
    base_dir = os.path.join("results", f"scan_{started_at}")
    hosts_dir = os.path.join(base_dir, "hosts")
    mkdirp(hosts_dir)

    # 1) Host discovery
    live_hosts, discovery_txt = discover_hosts(cidr)
    with open(os.path.join(base_dir, "discovery.txt"), "w") as f:
        f.write(discovery_txt)

    if not live_hosts:
        print("[-] No live hosts found. Exiting.")
        return

    # 2) Multi-threaded per-host scans
    print(f"[+] Scanning {len(live_hosts)} host(s) with {threads} threads, ports {ports} ...\n")
    rows = []
    futures = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for ip in live_hosts:
            futures.append(executor.submit(scan_host, ip, ports, hosts_dir))
        for fut in as_completed(futures):
            r = fut.result()
            rows.append(r)
            opened = len(r["ports"])
            print(f"[>] {r['ip']} — open ports: {opened} {'(' + (r['os'] or 'OS?') + ')'}")

    # 3) Save combined outputs
    txt_summary = os.path.join(base_dir, "summary.txt")
    with open(txt_summary, "w") as f:
        for r in rows:
            f.write(f"{r['ip']} | OS: {r['os'] or 'Unknown'}\n")
            if r["ports"]:
                for p in r["ports"]:
                    f.write(f"  - {p['proto']}/{p['port']}  {p['service']}  {p['product']} {p['version']}\n")
            else:
                f.write("  - No open ports in selected range\n")
            f.write("\n")

    csv_path = os.path.join(base_dir, "results.csv")
    write_csv(rows, csv_path)

    html_path = os.path.join(base_dir, "report.html")
    write_html(rows, html_path, cidr, started_at)

    print("\n[+] Done!")
    print(f"[+] Results folder: {base_dir}")
    print(f"    - discovery.txt (ping sweep output)")
    print(f"    - summary.txt   (human summary)")
    print(f"    - results.csv   (spreadsheet-friendly)")
    print(f"    - report.html   (pretty report)")
    print(f"    - hosts/*.txt & *.xml per-host raw outputs")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
