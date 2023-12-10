from flask import Flask, render_template, send_file, request
import threading
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from scapy.all import *

# Flask App
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
nombre_ports_detectes = 0
mitm_Detecter = 0
scapy_scan_en_cours = False
detection_ports_active = False
mitm_active = True
selected_interface = "en0"  # Interface par défaut


# Fonctions utilitaires
def detecter_scan_ports(packets):
    global nombre_ports_detectes
    for packet in packets:
        if IP in packet and TCP in packet and detection_ports_active:
            ip_src, tcp_dport = packet[IP].src, packet[TCP].dport
            if tcp_dport == 21:
                nombre_ports_detectes += 1
            print(f"Packet from {ip_src} to port {tcp_dport} detected.")


def detecter_attaque_mitm(packet):
    global mitm_active, mitm_Detecter

    print("attente d allumage ")
    if mitm_active:
        print("Actif ")
        mitm_Detecter += 1
        if IP in packet:
            print("herre 2 ")
            expected_length = packet[IP].len
            actual_length = len(packet)
            print(len(packet))
            mitm_Detecter += 1
            if expected_length != actual_length:
                return True
        return False
    return False


def scanner_scapy():
    global scapy_scan_resultats
    while scapy_scan_en_cours:
        try:
            packets = sniff(count=10, iface=selected_interface)
            scapy_scan_resultats = packets
            detecter_scan_ports(scapy_scan_resultats)
            detecter_attaque_mitm(scapy_scan_resultats)
            sauvegarder_resultats_scan(scapy_scan_resultats)
            time.sleep(1)
        except Exception as e:
            arreter_scan()
            print(f"An error occurred while scanning: {str(e)}")


def demarrer_detection_scan():
    global scapy_scan_en_cours
    while True:
        if scapy_scan_en_cours:
            detecter_scan_ports(scapy_scan_resultats)
        time.sleep(1)


def sauvegarder_resultats_scan(resultats):
    with open(CHEMIN_FICHIER_SAUVEGARDE, 'a') as fichier:
        for packet in resultats:
            if IP in packet and TCP in packet:
                fichier.write(str(packet.summary()) + '\n')


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
    return render_template('accueil.html')


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


@app.route('/toggle_mitm')
def basculer_attaque_mitm():
    global mitm_active
    mitm_active = not mitm_active
    return f"L'attaque Man-In-The-Middle est maintenant {'activée' if mitm_active else 'désactivée'}."


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
    body = f"Nombre de ports détectés: {nombre_ports_detectes}\nNombre d'attaques Man-In-The-Middle détectées: {mitm_Detecter}"
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
