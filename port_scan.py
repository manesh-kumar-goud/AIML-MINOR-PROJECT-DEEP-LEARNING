"""
port_scan.py
============
Port Scan Attack Simulation Script
------------------------------------
Simulates a full TCP SYN port scan of a target IP (ports 1–65535).
Sends SYN packets to every port and records which ports respond.
This triggers the Port Scan detection in the IDS dashboard.

USAGE:
    python port_scan.py <target_ip> [start_port] [end_port]

EXAMPLES:
    python port_scan.py 192.168.43.1
    python port_scan.py 192.168.43.1 1 1024

WARNING:
    Use ONLY on your own test devices / networks.
    This script is for educational/lab demonstration only.
"""

import os
import sys
import time

def check_scapy():
    try:
        from scapy.all import IP, TCP, sr1
        return True
    except ImportError:
        print("[ERROR] Scapy not installed. Run: pip install scapy")
        sys.exit(1)

check_scapy()

from scapy.all import IP, TCP, sr1, conf, RandShort

conf.verb = 0          # Silent


def port_scan(target_ip: str, start_port: int = 1, end_port: int = 65535):
    """Perform a TCP SYN scan on target_ip from start_port to end_port."""
    total_ports = end_port - start_port + 1

    print("=" * 55)
    print("  [ALERT] PORT SCAN SIMULATION")
    print("=" * 55)
    print(f"  Target     : {target_ip}")
    print(f"  Port Range : {start_port} - {end_port}  ({total_ports:,} ports)")
    print("=" * 55)
    print("  [WARNING]  For educational/lab use ONLY!")
    print("=" * 55)
    print()

    open_ports   = []
    closed_ports = 0
    start_time   = time.time()
    scanned      = 0

    print(f"  [>] Scanning {total_ports:,} ports on {target_ip} ...")
    print()

    try:
        from scapy.all import conf
        # Decide sending method
        use_l3socket = False
        sender = None
        if os.name == 'nt' and not conf.use_pcap:
            try:
                sender = conf.L3socket(iface=conf.iface)
                use_l3socket = True
                print(f"  [INFO] Using Windows L3 socket on: {conf.iface.name}")
            except (OSError, PermissionError) as exc:
                print(f"\n  [ERROR] Cannot open raw sockets: {exc}")
                print("  Run this terminal as Administrator to send packets.")
                print("  Or install Npcap from https://npcap.com/\n")
                return

        from scapy.all import Ether, sendp
        first_error = None
        for port in range(start_port, end_port + 1):
            scanned += 1

            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / TCP(
                sport=int(RandShort()),
                dport=port,
                flags='S'           # SYN only
            )

            try:
                if use_l3socket and sender:
                    sender.send(pkt)
                else:
                    sendp(pkt, verbose=False)
            except Exception as exc:
                closed_ports += 1
                if first_error is None:
                    first_error = str(exc)

            # Progress every 1000 ports or at the end
            if scanned % 1000 == 0 or port == end_port:
                elapsed = time.time() - start_time
                pps = scanned / max(elapsed, 0.001)
                pct = (scanned / total_ports) * 100
                bar = '#' * int(pct / 3.33)
                print(f"\r  [{bar:<30}] {pct:>5.1f}%  |  "
                      f"{scanned:>6}/{total_ports}  |  {pps:.0f} ports/s",
                      end='', flush=True)

    except KeyboardInterrupt:
        print("\n\n  [STOP] Stopped by user.")

    elapsed = time.time() - start_time

    print(f"\n\n{'='*55}")
    print(f"  [SUCCESS] Port Scan Simulation Complete!")
    print(f"  Ports Scanned   : {scanned:,}")
    print(f"  Duration        : {elapsed:.2f} seconds")
    print(f"  Rate            : {scanned/max(elapsed,0.001):.0f} ports/second")
    print(f"{'='*55}")
    print(f"\n  [INFO] Check the IDS dashboard for PORT SCAN ALERT!")


if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()
    env_target = os.getenv("IOT_DEVICE_IP")

    if len(sys.argv) < 2 and not env_target:
        print("\nUsage: python port_scan.py <target_ip> [start_port] [end_port]")
        print("Example: python port_scan.py 192.168.43.1")
        print("Example: python port_scan.py 192.168.43.1 1 1024")
        sys.exit(1)

    target_ip = sys.argv[1] if len(sys.argv) >= 2 else env_target
    sp        = int(sys.argv[2]) if len(sys.argv) >= 3 else 1
    ep        = int(sys.argv[3]) if len(sys.argv) >= 4 else 1024

    port_scan(target_ip, sp, ep)
