"""
app.py
======
Deep Learning IDS — Flask + SocketIO Dashboard (PyTorch Edition)
-----------------------------------------------------------------
Run this EVERY TIME to start the IDS system:

    python app.py

The server will:
  1. Load the saved PyTorch model from disk (no retraining).
  2. Start live packet capture in a background thread.
  3. Serve the dashboard at http://localhost:5000
  4. Push real-time alerts and traffic stats via WebSocket.
"""

import os
import logging
import threading
import time
from datetime import datetime

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

from config import FLASK_HOST, FLASK_PORT, IOT_DEVICE_IP, ALERT_LOG_PATH

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

_alerts_history: list = []   # max 200 entries in memory

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    from load_and_detect import stats
    return render_template(
        'dashboard.html',
        iot_ip=IOT_DEVICE_IP,
        device=stats.get('device', 'CPU'),
        device_name=stats.get('device_name', 'CPU'),
    )


@app.route('/api/stats')
def api_stats():
    """REST fallback for polling clients."""
    from load_and_detect import stats
    return jsonify(stats)


@app.route('/api/alerts')
def api_alerts():
    """Return alert history as JSON."""
    return jsonify(_alerts_history[-50:])


@app.route('/api/sysinfo')
def api_sysinfo():
    """Return device/GPU info."""
    from load_and_detect import stats, DEVICE_NAME, device
    return jsonify({
        'device':      str(device).upper(),
        'device_name': DEVICE_NAME,
    })


# ─── SocketIO Broadcaster ─────────────────────────────────────────────────────
def _broadcast_loop():
    """Push traffic stats every 2s and drain alerts queue instantly."""
    from load_and_detect import stats, alert_queue

    while True:
        socketio.emit('traffic_update', {
            'pps':            stats['pps'],
            'total_packets':  stats['total_packets'],
            'status':         stats['status'],
            'active_devices': stats['active_devices'],
            'graph_data':     stats['graph_data'][-30:],
            'timestamp':      datetime.now().strftime('%H:%M:%S'),
            'device':         stats.get('device', 'CPU'),
            'device_name':    stats.get('device_name', 'CPU'),
        })

        while not alert_queue.empty():
            try:
                alert = alert_queue.get_nowait()
                _alerts_history.append(alert)
                if len(_alerts_history) > 200:
                    _alerts_history.pop(0)
                socketio.emit('new_alert', alert)
                logger.info(f"[EMIT] Alert: {alert['attack_type']} from {alert['src_ip']}")
            except Exception:
                break

        time.sleep(2)


# ─── Startup ──────────────────────────────────────────────────────────────────
def startup():
    """Initialize model, capture thread, and broadcaster."""
    try:
        from load_and_detect import load_model_from_disk, start_capture
        load_model_from_disk()
    except FileNotFoundError as exc:
        logger.error(str(exc))
        print(str(exc))
        print("\n  Run 'python train_model.py' first to train the model.\n")
        os._exit(1)

    start_capture()
    logger.info("[OK] Packet capture started.")

    broadcaster = threading.Thread(target=_broadcast_loop, daemon=True)
    broadcaster.start()
    logger.info("[OK] Dashboard broadcaster started.")


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    from load_and_detect import DEVICE_NAME, device as torch_device
    print("=" * 60)
    print("  Deep Learning IDS — Dashboard (PyTorch Edition)")
    print("=" * 60)
    print(f"  IoT Device    : {IOT_DEVICE_IP}")
    print(f"  AI Device     : {str(torch_device).upper()} ({DEVICE_NAME})")
    print(f"  Dashboard URL : http://localhost:{FLASK_PORT}")
    print("=" * 60)

    startup()

    socketio.run(
        app,
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=False,
        use_reloader=False,
    )
