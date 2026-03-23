import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ─── NETWORK SETTINGS ─────────────────────────────────────────────────────────
# IP address of the IoT device (Android phone) on the same WiFi/Hotspot
IOT_DEVICE_IP = os.getenv("IOT_DEVICE_IP", "192.168.29.142")

# Network interface used by the laptop for WiFi capture
# On Windows: "Wi-Fi" or "Ethernet"
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "Wi-Fi")

# Check if Windows; if so, default to None to let Scapy auto-detect the active Npcap interface UUID
if os.name == 'nt' and CAPTURE_INTERFACE in ["Wi-Fi", "Ethernet"]:
    import scapy.config
    CAPTURE_INTERFACE = scapy.config.conf.iface
    print(f"[INFO] Windows detected. Auto-binding to interface: {CAPTURE_INTERFACE}")

# ─── MODEL PATHS ──────────────────────────────────────────────────────────────
MODEL_DIR        = "saved_model"
MODEL_PATH       = f"{MODEL_DIR}/ids_model.pth"
SCALER_PATH      = f"{MODEL_DIR}/scaler.pkl"
FEATURES_PATH    = f"{MODEL_DIR}/features.pkl"
ENCODER_PATH     = f"{MODEL_DIR}/encoder.pkl"
THRESHOLD_PATH   = f"{MODEL_DIR}/threshold.pkl"

# ─── DATASET ──────────────────────────────────────────────────────────────────
DATASET_DIR = "dataset"

# ─── TRAINING HYPER-PARAMETERS ────────────────────────────────────────────────
EPOCHS      = 30
BATCH_SIZE  = 512      # Large batch — optimal for GPU
TEST_SPLIT  = 0.20
K_FEATURES  = 20       # Top features selected by SelectKBest

# ─── DETECTION THRESHOLDS ─────────────────────────────────────────────────────
# Packets per second that triggers DDoS alert
DDOS_PPS_THRESHOLD      = 100

# Distinct ports per second for Port-Scan alert
PORTSCAN_PORT_THRESHOLD = 100

# Rapid same-port attempts for Brute-Force alert
BRUTE_PORT_COUNT        = 50

# Flow aggregation window (seconds)
FLOW_WINDOW_SECONDS = 2

# ─── SMART ALERT RULES ────────────────────────────────────────────────────────
# Alert only after this many consecutive attack detections (reduces false alerts)
CONSECUTIVE_THRESHOLD = 1

# Seconds to wait before allowing a new alert (prevents alert spam)
COOLDOWN_SECONDS = 5

# IPs that will never trigger an alert (your own devices)
WHITELIST_IPS = [
    os.getenv("LAPTOP_IP", "192.168.29.228"),  # Your laptop (IDS machine) — never alert on its own traffic
    IOT_DEVICE_IP,                             # Your phone (IoT device) — monitored but not self-alerting
    "192.168.1.1",                             # Router
    "127.0.0.1",                               # Localhost
]

# ─── ALERT LOGGING ────────────────────────────────────────────────────────────
ALERT_LOG_PATH = "alerts.log"

# ─── FLASK DASHBOARD ──────────────────────────────────────────────────────────
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
