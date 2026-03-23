# 🛡️ Deep Learning IDS for IoT Devices

A real-time **Intrusion Detection System** using a **CNN + LSTM** deep learning model to monitor IoT device network traffic and detect **DDoS, Port Scan, and Brute Force** attacks instantly.

---

## 📁 Project Structure

```
IDS_Project/
├── saved_model/          ← Model saved here after training
│   ├── ids_model.h5
│   ├── scaler.pkl
│   └── features.pkl
├── dataset/              ← Put CICIDS 2017 CSV files here
├── templates/
│   └── dashboard.html    ← Web dashboard UI
├── static/
│   └── style.css         ← Dashboard styles
├── config.py             ← ⚙️ Edit your IP & settings here
├── train_model.py        ← 🔁 Run ONCE to train the model
├── load_and_detect.py    ← Detection engine (used by app.py)
├── app.py                ← 🚀 Main server - run every time
├── ddos_attack.py        ← DDoS simulation script
├── port_scan.py          ← Port Scan simulation script
├── brute_force.py        ← Brute Force simulation script
├── alerts.log            ← Alert history (auto-created)
└── requirements.txt      ← Python dependencies
```

---

## ⚙️ Setup

### Step 1: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Edit `config.py`
```python
IOT_DEVICE_IP    = "192.168.43.1"   # Phone IP on your WiFi
CAPTURE_INTERFACE = "Wi-Fi"          # Your laptop's WiFi adapter name
```
> To find your WiFi interface name, run Python and type:
> ```python
> from scapy.all import show_interfaces; show_interfaces()
> ```

### Step 3: Download CICIDS 2017 Dataset
- Download from: https://www.unb.ca/cic/datasets/ids-2017.html
- Place the `.csv` files inside the `dataset/` folder

---

## 🚀 Running the Project

### Train the Model (First Time Only — ~30-60 min)
```bash
python train_model.py
```
Model is saved to `saved_model/`. **Never need to retrain!**

### Start the IDS Dashboard (Every Time)
> ⚠️ Run as Administrator (required for packet capture)
```bash
python app.py
```
Open browser → **http://localhost:5000**

---

## 🧪 Simulate Attacks

Open a **new terminal** and run any attack script:

```bash
# DDoS Attack - sends 10,000 ICMP flood packets
python ddos_attack.py 192.168.43.1

# Port Scan - scans all 65535 ports
python port_scan.py 192.168.43.1

# Brute Force - 1000 rapid SSH login attempts on port 22
python brute_force.py 192.168.43.1
```

Watch the dashboard at **http://localhost:5000** turn 🔴 RED with real-time alerts!

---

## 🔬 Model Details

| Setting       | Value                    |
|---------------|--------------------------|
| Dataset       | CICIDS 2017              |
| Architecture  | CNN + LSTM               |
| CNN Layer     | Conv1D (64 filters)      |
| LSTM Layers   | 100 units → 50 units     |
| Training      | 80/20 split, 10 epochs   |
| Target Acc    | 95%+                     |
| Output        | Binary (BENIGN / ATTACK) |

---

## 🌐 Hardware Setup

```
Android Phone (IoT Device)
  └─ Install: SimpleSSHD (opens port 22)
  └─ Install: IP Webcam (opens port 8080)
  └─ Connect to WiFi

Laptop (IDS System)
  └─ Connected to same WiFi
  └─ Run: python app.py (as Administrator)
  └─ Open: http://localhost:5000
```

---

## ⚠️ Important Notes

1. **Run `app.py` as Administrator** (Windows) for Scapy packet capture
2. Both phone and laptop must be on the **same WiFi network**
3. **Never retrain** unless you want to — model loads from disk every time
4. Attack scripts are for **educational/lab use only**

---

## 📊 Expected Dashboard Behavior

| Event        | Dashboard Color | Alert                          |
|--------------|-----------------|--------------------------------|
| Normal       | 🟢 GREEN        | —                              |
| DDoS         | 🔴 RED FLASH    | 🚨 DDoS ATTACK DETECTED        |
| Port Scan    | 🔴 RED FLASH    | 🚨 PORT SCAN DETECTED          |
| Brute Force  | 🔴 RED FLASH    | 🚨 BRUTE FORCE DETECTED        |
