from flask import Flask, render_template, send_file
from scapy.all import *
import threading
import time

app = Flask(__name__)

CHEMIN_FICHIER_SAUVEGARDE = 'resultats_scan.txt'

scapy_scan_resultats = []
nombre_ports_detectes = 0
scapy_scan_en_cours = False

def sauvegarder_resultats_scan(resultats):
    with open(CHEMIN_FICHIER_SAUVEGARDE, 'a') as fichier:
        for packet in resultats:
            if IP in packet and TCP in packet:
                fichier.write(str(packet.summary()) + '\n')

def detecter_scan_ports(packets):
    global nombre_ports_detectes
    for packet in packets:
        if IP in packet and TCP in packet:
            ip_src, tcp_dport = packet[IP].src, packet[TCP].dport
            if tcp_dport == 21:
                nombre_ports_detectes += 1
            print(f"Packet from {ip_src} to port {tcp_dport} detected.")

def scanner_scapy():
    global scapy_scan_resultats
    while scapy_scan_en_cours:
        packets = sniff(count=10)
        scapy_scan_resultats = packets
        detecter_scan_ports(scapy_scan_resultats)
        sauvegarder_resultats_scan(scapy_scan_resultats)
        time.sleep(1)

def demarrer_detection_scan():
    global scapy_scan_en_cours
    while True:
        if scapy_scan_en_cours:
            detecter_scan_ports(scapy_scan_resultats)
        time.sleep(1)


## ---------------
    # ROUTE
## ---------------

@app.route('/')
def accueil():
    return render_template('accueil.html')

@app.route('/start_scan')
def demarrer_scan():
    global scapy_scan_en_cours
    if not scapy_scan_en_cours:
        scapy_scan_en_cours = True
        threading.Thread(target=scanner_scapy).start()
        threading.Thread(target=demarrer_detection_scan).start()
    return "Scan démarré avec succès"

@app.route('/stop_scan')
def arreter_scan():
    global scapy_scan_en_cours, scapy_scan_resultats
    scapy_scan_en_cours = False
    scapy_scan_resultats = []
    return "Scan arrêté avec succès"

@app.route('/get_scan_results')
def obtenir_resultats_scan():
    return {'resultats': [str(packet.summary()) for packet in scapy_scan_resultats]}

@app.route('/afficher_fichier')
def afficher_fichier():
    return send_file(CHEMIN_FICHIER_SAUVEGARDE, as_attachment=True)

@app.route('/get_nombre_ports_detectes')
def obtenir_nombre_ports_detectes():
    global nombre_ports_detectes
    return {'nombre_ports_detectes': nombre_ports_detectes}

@app.route('/detect_scan')
def detecter_scan():
    global scapy_scan_resultats, nombre_ports_detectes
    detecter_scan_ports(scapy_scan_resultats)
    nombre_ports_detectes += 1
    return "Detection de scan effectuée avec succès"

if __name__ == '__main__':
    app.run(debug=True)
