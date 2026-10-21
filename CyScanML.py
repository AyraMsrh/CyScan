import socket
import time
import sys
import pyfiglet
import joblib
from datetime import datetime

# --- ASCII Banner ---
ascii_banner = pyfiglet.figlet_format("CyScan ML SCANNER")
print(ascii_banner)

# --- Load Pre-trained ML Model ---
try:
    model = joblib.load("cic_model.pkl")  # Your trained model file
    print("[✔] ML model loaded successfully.\n")
except:
    print("[✘] ML model could not be loaded. Make sure 'cic_model.pkl' is present.")
    sys.exit()

# --- Get Target IP from User ---
target_input = input("Enter target IP or hostname: ")
try:
    target = socket.gethostbyname(target_input)
except socket.gaierror:
    print("[✘] Invalid hostname or IP. Please check and try again.")
    sys.exit()


# --- Scan Banner ---
print("-" * 50)
print(f"Scanning Target: {target}")
print("Scanning started at: " + str(datetime.now()))
print("-" * 50)

open_ports = []
try:
    for port in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)

        start_time = time.time()
        result = s.connect_ex((target, port))
        end_time = time.time()

        response_time = round(end_time - start_time, 4)

        prediction = model.predict([[port, response_time]])

        if prediction[0] == 1:
            if result == 0:
                print(f"[+] Port {port} is OPEN (Predicted + Confirmed)")
                open_ports.append(port)
        s.close()

except KeyboardInterrupt:
    print("\n[!] Scan interrupted by user.")
    sys.exit()
except socket.error:
    print("[✘] Socket error. Host might be down.")
    sys.exit()

print("-" * 50)
print(f"Scan completed at: {datetime.now()}")
print(f"Total open ports detected: {len(open_ports)}")
print("-" * 50)

# --- Simulated Firewall Action ---
firewall_log = []

if open_ports:
    print("\n--- Firewall Action Menu (Simulation) ---")
    for port in open_ports:
        print(f"\n[!] Port {port} is open.")
        print("Choose action:")
        print("1. Block fully (all traffic)")
        print("2. Ignore")

        choice = input("Enter choice [1-2]: ").strip()
        if choice == '1':
            log_entry = f"Port {port}: [BLOCKED]"
        else:
            log_entry = f"Port {port}: [IGNORED]"

        firewall_log.append(log_entry)

    print("\n--- Firewall Simulation Log ---")
    for entry in firewall_log:
        print(entry)
else:
    print("[✔] No open ports detected by ML and scan.")

