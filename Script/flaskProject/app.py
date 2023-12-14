from flask import Flask, render_template, send_file, request
import threading
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from scapy.all import *
from datetime import datetime
import requests
from collections import defaultdict


# Flask App
from scapy.layers.l2 import ARP

app = Flask(__name__)

# Constantes
CHEMIN_FICHIER_SAUVEGARDE = 'resultats_scan.txt'
EMAIL_SMTP_SERVER = 'smtp.example.com'
EMAIL_SMTP_PORT = 587
EMAIL_SMTP_USERNAME = 'your_username'
EMAIL_SMTP_PASSWORD = 'your_password'
EMAIL_FROM = 'your_email@example.com'
EMAIL_TO = 'recipient@example.com'

# Variables globales
scapy_scan_resultats = []
scans_par_ip = {}

nombre_ports_detectes = 0
mitm_Detecter = 0
scapy_scan_en_cours = False
detection_ports_active = False
arp_spoffing_active = False
bruteforce_detection_active = False
scans_par_ip = {}

mitm_active = False
selected_interface = "en0"  # Interface par défaut


MAX_PORTS_SCAN_THRESHOLD = 50  # Vous pouvez ajuster ce seuil selon vos besoins
HISTORY_THRESHOLD = 3
history = {}
WINDOW_TIME = 60  # Fenêtre de temps en secondes
MAX_SCANS_IN_WINDOW = 5

# Attaque par brute force
ssh_failed_attempts = {}  # Dictionnaire pour stocker les tentatives échouées par adresse IP
threshold_attempts = 3  # Seuil de tentatives avant de considérer une attaque

ip_mac_mapping = {
'192.168.56.150': '08:00:27:7E:B5:3C'
} # mac adress

ntfy_server_url = 'http://89.116.181.163:81/AqlusogVuyQrodFN'

LOG_DIRECTORY = "logs"


# Historique des vulnérabilités détectées
vulnerability_history = defaultdict(list)


def check_vulnerability_history(ip, scan_type, timestamp):
    global vulnerability_history

    key = (ip, scan_type)
    history = vulnerability_history[key]

    # Vérifier si une alerte similaire a été émise récemment
    if history and (timestamp - history[-1]).seconds < WINDOW_TIME:
        return True  # La vulnérabilité a déjà été signalée récemment
    else:
        # Ajouter le timestamp actuel à l'historique
        history.append(timestamp)
        # Conserver uniquement les timestamps dans la fenêtre temporelle
        vulnerability_history[key] = [t for t in history if (timestamp - t).seconds < WINDOW_TIME]
        return False

# Assurez-vous que le répertoire existe
if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)



def fichier_saveVul(data):
    with open(os.path.join(LOG_DIRECTORY, "vulnerability.txt"), "a") as vuln_file:
        vuln_file.write(f"{data}\n")

# Fonction pour détecter les scans de ports
def detecter_scan_ports(packets):
    global nombre_ports_detectes
    scan_type = "Nmap"

    src_ip_to_ports = defaultdict(set)
    for packet in packets:
        if IP in packet and (TCP in packet or UDP in packet) and detection_ports_active:
            ip_src = packet[IP].src
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            src_ip_to_ports[ip_src].add(dst_port)

    for src_ip, ports in src_ip_to_ports.items():
        for port in ports:
            if len(ports) > MAX_PORTS_SCAN_THRESHOLD and not check_vulnerability_history(src_ip, scan_type,   datetime.now()):
                alert = f"Activité suspecte détectée : scan Nmap de ports depuis {src_ip} vers {port}"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                requests.get(ntfy_server_url, params={'message': alert})

                ligne = timestamp + "-" + alert
                fichier_saveVul(ligne)
                nombre_ports_detectes += 1





# Fonction pour gérer les paquets Scapy
def detection_bruteforce(packet):
    scan_type = "SSH"
    if 'IP' in packet and 'TCP' in packet:
        ip_address = packet['IP'].src
        if packet['TCP'].dport == 22:  # Vérifier si le paquet est destiné au port SSH

            if ip_address not in ssh_failed_attempts:
                ssh_failed_attempts[ip_address] = 1
            else:
                ssh_failed_attempts[ip_address] += 1
            if ssh_failed_attempts[ip_address] >= threshold_attempts and  not check_vulnerability_history(ip_address, scan_type,   datetime.now()):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert = f"{timestamp} - Possible attaque de force brute depuis {ip_address}"
                # Enregistrez dans un fichier spécifique pour cette IP
                requests.get(ntfy_server_url, params={'message': alert})

                ligne =  alert
                fichier_saveVul(ligne)



# Fonction de callback pour le paquet ARP
def Arp_Spoffing(packet):
    scan_type = "ARP"
    if  arp_spoffing_active and ARP in packet:
        arp_src_ip = packet[ARP].psrc
        arp_src_mac = packet[ARP].hwsrc
        if arp_src_ip in ip_mac_mapping :

            if ip_mac_mapping[arp_src_ip] != arp_src_mac and  not check_vulnerability_history(arp_src_ip, scan_type,   datetime.now()):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert = f"Possible ARP spoofing detected! IP: {arp_src_ip}, Old MAC: {ip_mac_mapping[arp_src_ip]}, New MAC: {arp_src_mac}"
                # Enregistrez dans un fichier spécifique pour cette IP
                requests.get(ntfy_server_url, params={'message': alert})
                ligne = timestamp + "-" + alert
                fichier_saveVul(ligne)
        else:
            ip_mac_mapping[arp_src_ip] = arp_src_mac

# Fonction de callback pour chaque paquet capturé
def packet_callback(packet):
    if bruteforce_detection_active:
        detection_bruteforce(packet)
    Arp_Spoffing(packet)

def scanner_scapy():
    global scapy_scan_resultats
    while scapy_scan_en_cours:
        try:
            packets = sniff(count=100, iface=selected_interface, prn=packet_callback)
            scapy_scan_resultats = packets
            sauvegarder_resultats_scan(scapy_scan_resultats)
            time.sleep(1)
        except Exception as e:
            arreter_scan()
            print(f"An error occurred while scanning: {str(e)}")

def demarrer_detection_scan():
    global scapy_scan_en_cours
    print(scapy_scan_en_cours)
    while True:
        if scapy_scan_en_cours:
            detecter_scan_ports(scapy_scan_resultats)
        time.sleep(1)

def sauvegarder_resultats_scan(resultats):
    with open(CHEMIN_FICHIER_SAUVEGARDE, 'a') as fichier:
        for packet in resultats:
            if IP in packet and TCP in packet:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                fichier.write(f"{timestamp} {str(packet.summary())}\n")


def envoyer_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_SMTP_USERNAME, EMAIL_SMTP_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

# Routes Flask
@app.route('/')
def accueil():
    return render_template('home.html')

@app.route('/start_scan', methods=['POST'])
def demarrer_scan():
    global scapy_scan_en_cours, detection_ports_active, selected_interface
    selected_interface = request.form.get('interface', 'enO')
    if not scapy_scan_en_cours:
        scapy_scan_en_cours = True
        detection_ports_active = False  # Activer la détection lors du démarrage du scan
        threading.Thread(target=scanner_scapy).start()
        threading.Thread(target=demarrer_detection_scan).start()
    return "Scan démarré avec succès"

@app.route('/stop_scan')
def arreter_scan():
    global scapy_scan_en_cours, scapy_scan_resultats, detection_ports_active
    scapy_scan_en_cours = False
    scapy_scan_resultats = []
    detection_ports_active = False  # Désactiver la détection lors de l'arrêt du scan
    return "Scan arrêté avec succès"

# Switch ON - OFF
@app.route('/toggle_detection_ports')
def basculer_detection_ports():
    global detection_ports_active
    detection_ports_active = not detection_ports_active
    return f"La détection des ports est maintenant {'activée' if detection_ports_active else 'désactivée'}."


@app.route('/toggle_arp_spoofing')
def basculer_arp_spoffing():
    global arp_spoffing_active
    arp_spoffing_active = not arp_spoffing_active
    return f"La détection ARP Spoofing est maintenant {'activée' if arp_spoffing_active else 'désactivée'}."

# Activer/désactiver la détection Brute Force
@app.route('/toggle_bruteforce_detection')
def basculer_bruteforce_detection():
    global bruteforce_detection_active
    bruteforce_detection_active = not bruteforce_detection_active
    return f"La détection Brute Force est maintenant {'activée' if bruteforce_detection_active else 'désactivée'}."




# LE Print
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

@app.route('/get_nombre_mitm')
def obtenir_nombre_mitm():
    global mitm_Detecter
    return {'Mitn': mitm_Detecter}

@app.route('/generer_rapport')
def generer_rapport():
    subject = "Rapport de l'analyse du réseau"
    body = f"Nombre de ports détectés: {nombre_ports_detectes}\n" \
           f"Nombre d'attaques Man-In-The-Middle détectées: {mitm_Detecter}"
    envoyer_email(subject, body)
    return "Rapport généré et envoyé par e-mail avec succès."

@app.route('/detect_scan')
def detecter_scan():
    global scapy_scan_resultats, nombre_ports_detectes
    detecter_scan_ports(scapy_scan_resultats)
    nombre_ports_detectes += 1
    return "Detection de scan effectuée avec succès"





if __name__ == '__main__':
    app.run(debug=True)
