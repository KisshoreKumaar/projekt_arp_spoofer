import sys
import time
import socket
import struct
import numpy as np
from bcc import BPF
from sklearn.ensemble import IsolationForest
from collections import deque

# --- CONFIGURATION ---
INTERFACE = "lo" # Listening on Loopback for the demo (or use your eth0)
MAX_HISTORY = 1000 # Keep last 1000 packets for training

print(f"Loading XDP program on {INTERFACE}...")

# 1. Load the eBPF program
b = BPF(src_file="xdp_prog.c")
fn = b.load_func("xdp_ddos_filter", BPF.XDP)

# 2. Attach XDP to the network interface
try:
    b.attach_xdp(INTERFACE, fn, 0)
except Exception as e:
    print(f"Error attaching XDP: {e}")
    sys.exit(1)

# Maps reference
blacklist_map = b.get_table("blacklist")

# Data storage for ML
packet_history = deque(maxlen=MAX_HISTORY)
ip_counts = {}

# Simple ML Model: Isolation Forest
# In a real scenario, you'd pre-train this. Here we train on the fly.
clf = IsolationForest(contamination=0.1, random_state=42)
trained = False

def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def process_packet(cpu, data, size):
    global trained
    event = b["packet_events"].event(data)
    src_ip = event.src_ip
    length = event.len
    
    # Feature Engineering: [Packet Length, Frequency (simplified)]
    ip_str = int_to_ip(src_ip)
    ip_counts[ip_str] = ip_counts.get(ip_str, 0) + 1
    
    features = [length, ip_counts[ip_str]]
    packet_history.append(features)

    # Train/Predict logic
    if len(packet_history) >= 100:
        data_np = np.array(packet_history)
        
        # Periodically retrain (simulated adaptive learning)
        if not trained or len(packet_history) % 200 == 0:
            clf.fit(data_np)
            trained = True
            print("ML Model Retrained/Updated.")

        # Predict anomaly
        prediction = clf.predict([features])
        
        # -1 means Anomaly (Attack)
        if prediction[0] == -1:
            print(f"[ALERT] Malicious traffic detected from {ip_str}! Blocking...")
            
            # Add to eBPF Blacklist Map
            # The key must be ctypes c_uint32
            import ctypes
            key = ctypes.c_uint32(src_ip)
            val = ctypes.c_long(1)
            blacklist_map[key] = val
            print(f"-> IP {ip_str} added to Kernel Blocklist (XDP DROP)")

# 3. Start Event Loop
print("System Ready. Listening for packets...")
b["packet_events"].open_perf_buffer(process_packet)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching XDP...")
    b.remove_xdp(INTERFACE, 0)