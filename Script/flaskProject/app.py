from flask import Flask, render_template, send_file
from scapy.all import *
import threading
import time

from scapy.layers.inet import TCP

app = Flask(__name__)

# Chemin du fichier de sauvegarde
CHEMIN_FICHIER_SAUVEGARDE = 'resultats_scan.txt'

# Cette variable globale sera utilisée pour indiquer l'état du scan (en cours ou arrêté)
scapy_scan_en_cours = False

# Cette variable globale stockera les résultats du scan
scapy_scan_resultats = []


# Fonction pour écrire les résultats du scan dans un fichier
def sauvegarder_resultats_scan(resultats):
    with open(CHEMIN_FICHIER_SAUVEGARDE, 'a') as fichier:
        for resultat in resultats:
            fichier.write(resultat + '\n')





def detecter_scan_ports(packets):
    for packet in packets:
        # Vous pouvez personnaliser ces conditions en fonction de vos besoins
        if packet.haslayer(IP) and packet.haslayer(TCP):
            tcp_dport = packet[TCP].dport
            ip_src = packet[IP].src
            print(f"Packet from {ip_src} to port {tcp_dport} detected.")

            if tcp_dport == 21 :
                print(f"Intrusion")

            # Ajoutez ici votre logique de détection, par exemple, enregistrer dans un fichier


# Cette fonction sera exécutée dans un thread pour effectuer le scan Scapy en temps réel
def scanner_scapy():
    global scapy_scan_en_cours, scapy_scan_resultats

    while scapy_scan_en_cours:
        # Ajoutez ici le code Scapy pour effectuer le scan
        packets = sniff(count=10)
        # Appeler la fonction de détection de scan de ports
        detecter_scan_ports(packets)
        # Stocker les résultats dans la variable globale
        scapy_scan_resultats = [str(packet.summary()) for packet in packets]
        # Sauvegarder les résultats dans un fichier
        sauvegarder_resultats_scan(scapy_scan_resultats)

        # Pause pour éviter de surcharger le serveur avec des scans continus
        time.sleep(1)


# Route pour la page d'accueil
@app.route('/')
def accueil():
    return render_template('accueil.html')



@app.route('/detect_scan')
def detecter_scan():
    global scapy_scan_resultats
    # Vous pouvez personnaliser cette logique en fonction de vos besoins
    detecter_scan_ports(scapy_scan_resultats)

    return "Detection de scan effectuée avec succès"

# Route pour démarrer le scan
@app.route('/start_scan')
def demarrer_scan():
    global scapy_scan_en_cours, scapy_scan_resultats

    # Démarrer le thread de scan
    if not scapy_scan_en_cours:
        scapy_scan_en_cours = True
        scapy_thread = threading.Thread(target=scanner_scapy)
        scapy_thread.start()

    return "Scan démarré avec succès"


# Route pour arrêter le scan
@app.route('/stop_scan')
def arreter_scan():
    global scapy_scan_en_cours, scapy_scan_resultats
    scapy_scan_en_cours = False
    scapy_scan_resultats = []  # Réinitialiser les résultats
    return "Scan arrêté avec succès"


# Route pour obtenir les résultats du scan
@app.route('/get_scan_results')
def obtenir_resultats_scan():
    global scapy_scan_resultats
    return {'resultats': scapy_scan_resultats}


# Route pour afficher le contenu du fichier
@app.route('/afficher_fichier')
def afficher_fichier():
    return send_file(CHEMIN_FICHIER_SAUVEGARDE, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
