"""
load_and_detect.py
==================
Deep Learning IDS — Live Traffic Capture & PyTorch Detection Engine
--------------------------------------------------------------------
Loads the pre-trained CNN+BiLSTM+Attention PyTorch model from disk and
continuously captures network packets using Scapy. Packets are grouped
into time-windowed flows, features are extracted and fed into the model,
and predictions are emitted to the Flask dashboard via a shared queue.

Smart alert rules applied:
  - Consecutive detection threshold (3 in a row)
  - Cooldown period (30 seconds between alerts)
  - IP whitelist (trusted IPs never trigger alerts)
  - Packet count thresholds (DDoS pps, port scan count, brute force count)

This module is imported by app.py - do NOT run it directly.
"""

import os
import time
import pickle
import queue
import threading
import logging
import traceback
import numpy as np
from datetime import datetime
from collections import defaultdict

import torch
import torch.nn as nn

from config import (
    MODEL_PATH, SCALER_PATH, FEATURES_PATH, THRESHOLD_PATH,
    IOT_DEVICE_IP, CAPTURE_INTERFACE,
    DDOS_PPS_THRESHOLD, PORTSCAN_PORT_THRESHOLD,
    BRUTE_PORT_COUNT, FLOW_WINDOW_SECONDS, ALERT_LOG_PATH,
    CONSECUTIVE_THRESHOLD, COOLDOWN_SECONDS, WHITELIST_IPS,
)

logger = logging.getLogger(__name__)

# ─── Device ───────────────────────────────────────────────────────────────────
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
DEVICE_NAME = (
    torch.cuda.get_device_name(0) if device.type == 'cuda' else 'CPU'
)

# ─── Shared State (read by app.py) ────────────────────────────────────────────
alert_queue: queue.Queue = queue.Queue()
stats: dict = {
    "pps":            0,
    "total_packets":  0,
    "status":         "NORMAL",
    "active_devices": [],
    "graph_data":     [],
    "device":         str(device).upper(),
    "device_name":    DEVICE_NAME,
}

# ─── Model globals ────────────────────────────────────────────────────────────
_model     = None
_scaler    = None
_features  = []
_threshold = 0.5


# ─── PyTorch Model Architecture (must match train_model.py) ──────────────────
class IDS_Model(nn.Module):
    def __init__(self, input_size):
        super(IDS_Model, self).__init__()
        self.conv1 = nn.Conv1d(1, 64, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.pool  = nn.MaxPool1d(2)
        self.bn1   = nn.BatchNorm1d(64)
        self.bn2   = nn.BatchNorm1d(128)
        self.lstm  = nn.LSTM(
            input_size=128, hidden_size=128, num_layers=2,
            batch_first=True, dropout=0.3, bidirectional=True,
        )
        self.attention = nn.Linear(256, 1)
        self.fc1 = nn.Linear(256, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 1)
        self.dropout = nn.Dropout(0.4)
        self.relu    = nn.ReLU()
        self.bn3     = nn.BatchNorm1d(128)
        self.bn4     = nn.BatchNorm1d(64)

    def forward(self, x):
        x = x.unsqueeze(1)
        x = self.relu(self.bn1(self.conv1(x)))
        x = self.relu(self.bn2(self.conv2(x)))
        x = self.pool(x)
        x = x.permute(0, 2, 1)
        x, _ = self.lstm(x)
        attn = torch.softmax(self.attention(x), dim=1)
        x = torch.sum(attn * x, dim=1)
        x = self.relu(self.bn3(self.fc1(x)))
        x = self.dropout(x)
        x = self.relu(self.bn4(self.fc2(x)))
        x = self.dropout(x)
        x = self.fc3(x)
        return x


# ─── Model Loading ────────────────────────────────────────────────────────────
def load_model_from_disk():
    """Load the saved PyTorch IDS model, scaler, features, and threshold."""
    global _model, _scaler, _features, _threshold

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"\n[ERROR] No trained model found at '{MODEL_PATH}'.\n"
            "   Please run:  python train_model.py\n"
            "   to train and save the model first."
        )

    # Load model checkpoint
    checkpoint = torch.load(MODEL_PATH, map_location=device)
    input_size = checkpoint['input_size']
    _model = IDS_Model(input_size).to(device)
    _model.load_state_dict(checkpoint['model_state_dict'])
    _model.eval()

    _scaler    = pickle.load(open(SCALER_PATH, 'rb'))
    _features  = pickle.load(open(FEATURES_PATH, 'rb'))
    _threshold = pickle.load(open(THRESHOLD_PATH, 'rb'))

    logger.info(f"[OK] Model loaded from '{MODEL_PATH}'. Device: {device}")
    print(f"[OK] Model loaded! Device: {device.type.upper()} ({DEVICE_NAME})")
    print(f"[OK] Using tuned threshold: {_threshold:.4f}")
    return _model, _scaler, _features, _threshold


# ─── Feature Defaults ─────────────────────────────────────────────────────────
FEATURE_DEFAULTS = {f: 0.0 for f in [
    'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Fwd IAT Total', 'Fwd IAT Mean',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'Packet Length Mean', 'Packet Length Std',
    'Average Packet Size', 'Fwd Packet Length Mean',
    # lowercase fallbacks
    'duration', 'fwd_packets_count', 'bwd_packets_count',
    'fwd_total_payload_bytes', 'bwd_total_payload_bytes',
    'bytes_rate', 'packets_rate', 'packets_IAT_mean',
    'syn_flag_counts', 'rst_flag_counts', 'psh_flag_counts', 'ack_flag_counts',
    'dst_port', 'payload_bytes_mean', 'payload_bytes_std',
    'fwd_payload_bytes_mean', 'fwd_payload_bytes_max', 'fwd_payload_bytes_min',
]}


def _build_feature_vector(flow: dict, duration: float) -> np.ndarray:
    """Convert a raw flow dict into the feature vector the model expects."""
    pkt_lens = flow['pkt_lengths']
    fwd_lens = flow['fwd_lengths']
    bwd_lens = flow['bwd_lengths']

    n_pkts = len(pkt_lens)
    n_fwd  = len(fwd_lens)
    n_bwd  = len(bwd_lens)
    dur    = max(duration, 1e-9)

    feat = dict(FEATURE_DEFAULTS)
    # CICIDS-style names (original column headers)
    feat['Destination Port']             = flow['dst_port']
    feat['Flow Duration']                = dur * 1e6   # microseconds
    feat['Total Fwd Packets']            = n_fwd
    feat['Total Backward Packets']       = n_bwd
    feat['Total Length of Fwd Packets']  = sum(fwd_lens)
    feat['Total Length of Bwd Packets']  = sum(bwd_lens)
    feat['Flow Bytes/s']                 = sum(pkt_lens) / dur
    feat['Flow Packets/s']               = n_pkts / dur
    feat['Flow IAT Mean']                = (dur / n_pkts) * 1e6 if n_pkts > 1 else 0
    feat['Flow IAT Std']                 = 0.0
    feat['Fwd IAT Total']                = dur * 1e6
    feat['Fwd IAT Mean']                 = (dur / n_fwd) * 1e6 if n_fwd > 1 else 0
    feat['SYN Flag Count']               = flow['flags']['SYN']
    feat['RST Flag Count']               = flow['flags']['RST']
    feat['PSH Flag Count']               = flow['flags']['PSH']
    feat['ACK Flag Count']               = flow['flags']['ACK']
    feat['Packet Length Mean']           = (sum(pkt_lens) / n_pkts) if n_pkts else 0
    feat['Packet Length Std']            = float(np.std(pkt_lens)) if len(pkt_lens) > 1 else 0
    feat['Average Packet Size']          = feat['Packet Length Mean']
    feat['Fwd Packet Length Mean']       = (sum(fwd_lens) / n_fwd) if n_fwd else 0
    # Also fill lowercase names for compatibility
    feat['duration']                     = dur
    feat['fwd_packets_count']            = n_fwd
    feat['bwd_packets_count']            = n_bwd
    feat['fwd_total_payload_bytes']      = sum(fwd_lens)
    feat['bwd_total_payload_bytes']      = sum(bwd_lens)
    feat['bytes_rate']                   = feat['Flow Bytes/s']
    feat['packets_rate']                 = feat['Flow Packets/s']
    feat['packets_IAT_mean']             = feat['Flow IAT Mean']
    feat['syn_flag_counts']              = flow['flags']['SYN']
    feat['rst_flag_counts']              = flow['flags']['RST']
    feat['psh_flag_counts']              = flow['flags']['PSH']
    feat['ack_flag_counts']              = flow['flags']['ACK']
    feat['dst_port']                     = flow['dst_port']
    feat['payload_bytes_mean']           = feat['Packet Length Mean']
    feat['payload_bytes_std']            = feat['Packet Length Std']
    feat['fwd_payload_bytes_mean']       = feat['Fwd Packet Length Mean']
    feat['fwd_payload_bytes_max']        = max(fwd_lens) if fwd_lens else 0
    feat['fwd_payload_bytes_min']        = min(fwd_lens) if fwd_lens else 0

    vec = np.array([feat.get(f.strip(), 0.0) for f in _features], dtype=np.float32)
    return vec


# ─── Smart Alert State ────────────────────────────────────────────────────────
_consecutive_count = 0
_last_alert_time   = 0.0


def _smart_alert_check(prediction: str, src_ip: str) -> bool:
    """Returns True if an alert should actually fire according to smart rules."""
    global _consecutive_count, _last_alert_time

    # Rule 1: Whitelist
    if src_ip in WHITELIST_IPS:
        return False

    # Rule 2: Cooldown
    if time.time() - _last_alert_time < COOLDOWN_SECONDS:
        return False

    # Rule 3: Consecutive count
    if prediction == "ATTACK":
        _consecutive_count += 1
    else:
        _consecutive_count = 0
        return False

    if _consecutive_count >= CONSECUTIVE_THRESHOLD:
        _last_alert_time   = time.time()
        _consecutive_count = 0
        return True

    return False


# ─── Attack Type Classifier ───────────────────────────────────────────────────
def _classify_attack(flow: dict, duration: float, total_ports: int = None) -> tuple:
    """Returns (attack_type, severity) using heuristics."""
    pps        = len(flow['pkt_lengths']) / max(duration, 1e-9)
    port_count = len(flow['dst_ports_seen']) if total_ports is None else total_ports

    if flow['flags']['SYN'] >= BRUTE_PORT_COUNT and port_count <= 2:
        return "Brute Force", "HIGH"
    if pps >= DDOS_PPS_THRESHOLD:
        return "DDoS", "HIGH"
    if port_count >= PORTSCAN_PORT_THRESHOLD:
        return "Port Scan", "MEDIUM"
    return "Network Attack", "MEDIUM"


# ─── Alert Logging ────────────────────────────────────────────────────────────
def _log_alert(alert: dict):
    line = (f"[{alert['time']}] {alert['attack_type']} | "
            f"Src: {alert['src_ip']} | Target: {alert['target_ip']} | "
            f"Severity: {alert['severity']} | Confidence: {alert['confidence']}%\n")
    with open(ALERT_LOG_PATH, 'a') as fh:
        fh.write(line)


# ─── Capture Loop ─────────────────────────────────────────────────────────────
def start_capture():
    """Start live packet capture in a background daemon thread."""
    t = threading.Thread(target=_capture_loop, daemon=True)
    t.start()
    return t


def _capture_loop():
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError:
        logger.error("[ERROR] Scapy not installed. Run: pip install scapy")
        return

    flows: dict = defaultdict(lambda: {
        'pkt_lengths': [], 'fwd_lengths': [], 'bwd_lengths': [],
        'flags': {'SYN': 0, 'ACK': 0, 'RST': 0, 'PSH': 0},
        'dst_ports_seen': set(), 'dst_port': 0,
        'start_time': time.time(),
    })
    window_start = time.time()
    device_ips   = set()

    def process_packet(pkt):
        nonlocal window_start
        if not pkt.haslayer(IP):
            return

        ip     = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        length = len(pkt)

        for ip_addr in (src_ip, dst_ip):
            device_ips.add(ip_addr)

        proto    = "OTHER"
        dst_port = 0
        tcp_flags: dict = {'SYN': 0, 'ACK': 0, 'RST': 0, 'PSH': 0}

        if pkt.haslayer(TCP):
            proto    = "TCP"
            dst_port = pkt[TCP].dport
            f = int(pkt[TCP].flags)
            tcp_flags['SYN'] = int(bool(f & 0x02))
            tcp_flags['ACK'] = int(bool(f & 0x10))
            tcp_flags['RST'] = int(bool(f & 0x04))
            tcp_flags['PSH'] = int(bool(f & 0x08))
        elif pkt.haslayer(UDP):
            proto    = "UDP"
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        fk   = (src_ip, dst_ip, dst_port, proto)
        flow = flows[fk]
        flow['pkt_lengths'].append(length)
        flow['dst_ports_seen'].add(dst_port)
        flow['dst_port'] = dst_port
        for flag, val in tcp_flags.items():
            flow['flags'][flag] += val

        if dst_ip == IOT_DEVICE_IP:
            flow['fwd_lengths'].append(length)
        else:
            flow['bwd_lengths'].append(length)

        stats['total_packets'] += 1

        now = time.time()
        if now - window_start >= FLOW_WINDOW_SECONDS:
            _analyse_flows(flows, now - window_start, device_ips)
            flows.clear()
            window_start = now

    # Build Scapy sniff kwargs with Windows L3 fallback
    kwargs = {'prn': process_packet, 'store': False}
    if os.name == 'nt':
        try:
            from scapy.all import conf as scapy_conf
            if not scapy_conf.use_pcap:
                kwargs['L2socket'] = scapy_conf.L3socket
                kwargs['iface']    = scapy_conf.iface
                print(f"[INFO] Using Windows L3 fallback on: {scapy_conf.iface.name}")
            else:
                kwargs['iface'] = CAPTURE_INTERFACE
        except Exception:
            kwargs['iface'] = CAPTURE_INTERFACE
    else:
        kwargs['iface'] = CAPTURE_INTERFACE

    logger.info(f"[CAPTURE] Starting packet capture...")
    print("[CAPTURE] Packet capture started.")

    try:
        sniff(**kwargs)
    except (PermissionError, OSError) as exc:
        msg = (
            f"\n[ERROR] Capture failed: {exc}\n"
            "  Run this terminal as Administrator to capture packets.\n"
            "  Or install Npcap from https://npcap.com/\n"
        )
        logger.error(msg)
        print(msg)
    except Exception as exc:
        logger.error(f"[ERROR] Scapy: {exc}\n{traceback.format_exc()}")


def _analyse_flows(flows: dict, duration: float, device_ips: set):
    """Run PyTorch inference on all flows from the last window."""
    if not flows or _model is None:
        return

    total_pkts = sum(len(f['pkt_lengths']) for f in flows.values())
    pps = total_pkts / max(duration, 1e-9)

    stats['pps'] = round(float(pps), 1)
    stats['active_devices'] = list(device_ips)[-10:]
    ts = datetime.now().strftime('%H:%M:%S')
    stats['graph_data'].append({'time': ts, 'pps': round(float(pps), 1)})
    if len(stats['graph_data']) > 60:
        stats['graph_data'].pop(0)

    has_attack = False

    from collections import defaultdict
    src_ip_ports = defaultdict(set)
    for flow_key, flow in flows.items():
        src_ip_ports[flow_key[0]].add(flow_key[2])

    for flow_key, flow in flows.items():
        src_ip, dst_ip, dst_port, proto = flow_key
        if not flow['pkt_lengths']:
            continue
            
        # 1. Ignore background local multicast
        if dst_ip.startswith("239.") or dst_ip.startswith("224.") or dst_ip == "255.255.255.255":
            continue

        # 2. Only analyse traffic involving the monitored IoT device
        if src_ip != IOT_DEVICE_IP and dst_ip != IOT_DEVICE_IP:
            continue

        try:
            vec    = _build_feature_vector(flow, duration)
            scaled = _scaler.transform(vec.reshape(1, -1)).astype(np.float32)
            tensor = torch.from_numpy(scaled).to(device)

            with torch.no_grad():
                logit = _model(tensor)
                prob  = torch.sigmoid(logit).item()

            is_attack = prob >= _threshold
            
            # Hybrid override: Hard threshold violations trigger alerts instantly
            flow_pps = len(flow['pkt_lengths']) / max(duration, 1e-9)
            if flow_pps >= DDOS_PPS_THRESHOLD:
                is_attack = True
            elif len(src_ip_ports[src_ip]) >= PORTSCAN_PORT_THRESHOLD:
                is_attack = True
            elif flow['flags']['SYN'] >= BRUTE_PORT_COUNT:
                is_attack = True

        except Exception as exc:
            logger.debug(f"Prediction error: {exc}")
            continue

        label = "ATTACK" if is_attack else "NORMAL"

        if is_attack and _smart_alert_check(label, src_ip):
            has_attack = True
            total_ports = len(src_ip_ports.get(src_ip, []))
            attack_type, severity = _classify_attack(flow, duration, total_ports)
            alert = {
                "time":         datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "attack_type":  attack_type,
                "src_ip":       src_ip,
                "target_ip":    dst_ip,
                "severity":     severity,
                "packet_count": len(flow['pkt_lengths']),
                "dst_port":     dst_port,
                "protocol":     proto,
                "confidence":   round(prob * 100, 1),
            }
            alert_queue.put(alert)
            _log_alert(alert)
            logger.warning(f"[ALERT] {attack_type} from {src_ip} -> {dst_ip}")
            print(f"[ALERT] {attack_type} detected | Src: {src_ip} | "
                  f"Confidence: {round(prob*100,1)}%")

    stats['status'] = "ATTACK" if has_attack else "NORMAL"
