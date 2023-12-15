import subprocess
from scapy.all import sniff, IP, TCP
import socket
import sys
import time
from datetime import datetime

# Fonctions pour l'installation de paquets
def install(package):
    subprocess.Popen(["python", "-m", "pip", "install", package, "-q"],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.STDOUT)

install("setuptools")
install("scapy")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

local_ip = get_local_ip()
local_network = ".".join(local_ip.split(".")[:3]) + "."
specific_network = "192.168.27."

MAX_PORTS = 3
ALERT_RATE_LIMIT = 1
port_scans = {}
alerts = {}

capture_mode = "ALL"

def set_capture_mode(mode):
    global capture_mode
    capture_mode = mode
    print_status(f"Mode de capture défini sur {capture_mode}")

def print_status(message):
    print(f"[STATUS] {message}")

def log_alert(alert):
    with open("network_alerts.log", "a") as log_file:
        log_file.write(f"{datetime.now()} - {alert}\n")

def print_alerts():
    current_time = time.time()
    for ip, (alert, timestamp) in alerts.items():
        if current_time - timestamp < ALERT_RATE_LIMIT:
            continue
        alert_message = f"[ALERT] {alert} - Detected from IP {ip}"
        print(alert_message)
        log_alert(alert_message)

def packet_callback(packet):
    current_time = time.time()
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src

        if capture_mode == "LAN" and not (ip_src.startswith(local_network) or ip_src.startswith(specific_network)):
            return
        tcp_port = packet[TCP].dport

        if ip_src not in port_scans:
            port_scans[ip_src] = set()
        port_scans[ip_src].add(tcp_port)

        if len(port_scans[ip_src]) > MAX_PORTS:
            if ip_src not in alerts or current_time - alerts[ip_src][1] >= ALERT_RATE_LIMIT:
                alert = f"Activité suspecte détectée : scan de ports"
                alerts[ip_src] = (alert, current_time)
                print_alerts()

def menu():
    print("Menu de l'analyseur de trames réseau")
    print("1. Changer le mode de capture (actuellement : " + capture_mode + ")")
    print("2. Démarrer l'analyse")
    print("3. Quitter")

    while True:
        choice = input("Entrez votre choix (1-3) : ")
        if choice == "1":
            new_mode = input("Entrez le nouveau mode de capture (LAN/ALL) : ").upper()
            if new_mode in ["LAN", "ALL"]:
                set_capture_mode(new_mode)
            else:
                print("Mode non valide. Veuillez choisir entre LAN et ALL.")
        elif choice == "2":
            return
        elif choice == "3":
            sys.exit(0)
        else:
            print("Choix non valide. Veuillez entrer un numéro entre 1 et 3.")

def main():
    menu()
    print_status("Démarrage de l'analyse de trames...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
