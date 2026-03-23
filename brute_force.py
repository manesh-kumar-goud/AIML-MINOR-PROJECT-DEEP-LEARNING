"""
brute_force.py
==============
Brute Force Attack Simulation Script
--------------------------------------
Simulates rapid SSH brute force login attempts against a target device
(e.g., Android phone running SimpleSSHD on port 22).
Sends 1000 rapid TCP SYN packets to port 22 from random source ports,
mimicking successive connection attempts.

USAGE:
    python brute_force.py <target_ip> [attempts] [port]

EXAMPLES:
    python brute_force.py 192.168.43.1
    python brute_force.py 192.168.43.1 1000 22

WARNING:
    Use ONLY on your own test devices / networks.
    This script is for educational/lab demonstration only.
"""

import os
import sys
import time
import random

def check_scapy():
    try:
        from scapy.all import IP, TCP, send
        return True
    except ImportError:
        print("[ERROR] Scapy not installed. Run: pip install scapy")
        sys.exit(1)

check_scapy()

from scapy.all import IP, TCP, send, conf, RandShort

conf.verb = 0   # Silence Scapy


def brute_force(target_ip: str, attempts: int = 1000, target_port: int = 22):
    """
    Simulate brute force by sending rapid TCP SYN packets to
    target_port (SSH port 22 by default).
    """
    print("=" * 55)
    print("  [ALERT] BRUTE FORCE SIMULATION")
    print("=" * 55)
    print(f"  Target     : {target_ip}")
    print(f"  Port       : {target_port} (SSH)")
    print(f"  Attempts   : {attempts:,}")
    print("=" * 55)
    print("  [WARNING]  For educational/lab use ONLY!")
    print("=" * 55)
    print()

    # Pre-build list of random usernames/passwords just for display
    sample_users = [
        "admin", "root", "user", "guest", "pi", "ubuntu",
        "admin123", "password", "test", "oracle",
    ]
    sample_passes = [
        "123456", "password", "admin", "root", "letmein",
        "welcome", "monkey", "1234", "000000", "qwerty",
    ]

    start_time = time.time()
    sent       = 0
    errors     = 0

    print(f"  [>] Launching {attempts:,} rapid login attempts to "
          f"{target_ip}:{target_port} ...\n")

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
        for i in range(1, attempts + 1):
            # Random source port each time = each looks like a new connection
            src_port = random.randint(1024, 65535)

            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / TCP(
                sport=src_port,
                dport=target_port,
                flags='S',          # SYN – simulate connection initiation
                seq=random.randint(0, 2**32 - 1)
            )
            try:
                if use_l3socket and sender:
                    sender.send(pkt)
                else:
                    sendp(pkt, verbose=False)
                sent += 1
            except Exception as exc:
                errors += 1
                if first_error is None:
                    first_error = str(exc)

            # Progress every 100 attempts
            if i % 100 == 0 or i == attempts:
                elapsed = time.time() - start_time
                rate    = sent / max(elapsed, 0.001)
                bar     = '#' * int((i / attempts) * 30)
                u = sample_users[i % len(sample_users)]
                p = sample_passes[i % len(sample_passes)]
                print(f"\r  [{bar:<30}] {i:>5}/{attempts}  |  "
                      f"{rate:>.0f} att/s  |  Trying: {u}/{p}",
                      end='', flush=True)

    except KeyboardInterrupt:
        print("\n\n  [STOP] Stopped by user.")

    elapsed = time.time() - start_time
    rate    = sent / max(elapsed, 0.001)

    print(f"\n\n{'='*55}")
    print(f"  [SUCCESS] Brute Force Simulation Complete!")
    print(f"  Attempts Sent : {sent:,}")
    print(f"  Errors        : {errors}")
    print(f"  Duration      : {elapsed:.2f} seconds")
    print(f"  Rate          : {rate:.0f} attempts/second")
    print(f"  Target Port   : {target_port} (SSH)")
    print(f"{'='*55}")
    print(f"\n  [INFO] Check the IDS dashboard for BRUTE FORCE ALERT!")


if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()
    env_target = os.getenv("IOT_DEVICE_IP")

    if len(sys.argv) < 2 and not env_target:
        print("\nUsage: python brute_force.py <target_ip> [attempts] [port]")
        print("Example: python brute_force.py 192.168.43.1")
        print("Example: python brute_force.py 192.168.43.1 1000 22")
        sys.exit(1)

    target_ip = sys.argv[1] if len(sys.argv) >= 2 else env_target
    attempts  = int(sys.argv[2]) if len(sys.argv) >= 3 else 1000
    port      = int(sys.argv[3]) if len(sys.argv) >= 4 else 22

    brute_force(target_ip, attempts, port)
