import nmap
import subprocess
import threading
import socket
import time
import requests
import os
import logging

__version__ = "1.2"

# Configureer logging
logging.basicConfig(filename='network_tool.log', level=logging.INFO)

def print_header():
    """Print een mooie header voor het script."""
    header = r"""
$$\   $$\            $$\                                       $$\             $$$$$$$$\                  $$\ 
$$$\  $$ |           $$ |                                      $$ |            \__$$  __|                 $$ |
$$$$\ $$ | $$$$$$\ $$$$$$\   $$\  $$\  $$\  $$$$$$\   $$$$$$\  $$ |  $$\          $$ | $$$$$$\   $$$$$$\  $$ |
$$ $$\$$ |$$  __$$\\_$$  _|  $$ | $$ | $$ |$$  __$$\ $$  __$$\ $$ | $$  |         $$ |$$  __$$\ $$  __$$\ $$ |
$$ \$$$$ |$$$$$$$$ | $$ |    $$ | $$ | $$ |$$ /  $$ |$$ |  \__|$$$$$$  /          $$ |$$ /  $$ |$$ /  $$ |$$ |
$$ |\$$$ |$$   ____| $$ |$$\ $$ | $$ | $$ |$$ |  $$ |$$ |      $$  _$$<           $$ |$$ |  $$ |$$ |  $$ |$$ |
$$ | \$$ |\$$$$$$$\  \$$$$  |\$$$$$\$$$$  |\$$$$$$  |$$ |      $$ | \$$\          $$ |\$$$$$$  |\$$$$$$  |$$ |
\__|  \__| \_______|  \____/  \_____\____/  \______/ \__|      \__|  \__|         \__| \______/  \______/ \__|
                                                                                                              
                                                                                                              
                                                                                                              """
    print(header)

def print_disclaimer():
    """Print de disclaimer met ASCII-art."""
    header = print_header()
    disclaimer = """
    Network Scanner Tool - By Dutch Cyber Sec

    A Python script for network scanning, port scanning, OS detection, and additional information gathering.

    This script is created by Dutch Cyber Sec for educational and ethical hacking purposes.
    Use it responsibly and ensure that you have proper authorization before scanning any network or system.

    DISCLAIMER: The use of this tool without proper authorization may violate applicable laws. The author is not responsible for any misuse or damage caused by this script.
    """
    print(header + disclaimer)

def get_ip_info(domain):
    """Haal IP-informatie op voor het opgegeven domein."""
    try:
        ip_addresses = socket.gethostbyname_ex(domain)
        print(f"\nIP-adressen voor {domain}:")
        for ip in ip_addresses[2]:
            print(ip)
    except socket.gaierror:
        print(f"Kan geen IP-adressen vinden voor {domain}")

def scan_ports(host, ports, intense, service_detection):
    """Voer poortscan uit voor de opgegeven host."""
    nm = nmap.PortScanner()
    args = f'-p {ports} -O --version-all' if intense else '-p 1-1024 -O --version-all'

    if service_detection:
        args += ' -sV'

    nm.scan(hosts=host, arguments=args)
    
    # Toon open poorten
    for proto in nm[host].all_protocols():
        print(f"\n{proto.upper()} poorten voor {host}:")
        ports = nm[host][proto].keys()
        for port in ports:
            print(f"Poort {port}: {nm[host][proto][port]['state']}")

            # Voer banner grabbing uit voor bekende services
            if service_detection and nm[host][proto][port]['state'] == 'open':
                service_name = nm[host][proto][port]['name']
                service_version = nm[host][proto][port]['version']
                print(f"  - Service: {service_name} {service_version}")

    # Log resultaten
    logging.info(f"Scanresultaten voor {host}:\n{nm[host]}")

    # ... (Voeg hier verdere logica toe, zoals het opslaan van resultaten in een database)

def scan_active_hosts(active_hosts, intense, service_detection):
    """Scan actieve hosts."""
    # Maak threads voor het scannen van actieve hosts
    threads = []
    for host in active_hosts:
        thread = threading.Thread(target=scan_ports, args=(host, '1-1024', intense, service_detection))
        threads.append(thread)
        thread.start()

    # Wacht tot alle threads zijn voltooid
    for thread in threads:
        thread.join()

def print_active_hosts(active_hosts):
    """Druk informatie af over de actieve hosts."""
    print("\nActieve hosts:")
    for host in active_hosts:
        print(host)

def check_for_update():
    """Controleer op updates op GitHub en installeer deze automatisch."""
    try:
        response = requests.get("https://raw.githubusercontent.com/DutchCyberSec/Network_Tool/main/Network_Tool.py")
        latest_script = response.text

        with open(os.path.basename(__file__), 'r') as current_file:
            current_script = current_file.read()

        if current_script != latest_script:
            print("\nEr is een update beschikbaar. Het script wordt bijgewerkt...")
            with open(os.path.basename(__file__), 'w') as current_file:
                current_file.write(latest_script)
            print("Script is succesvol bijgewerkt.")
        else:
            print("\nJe hebt al de nieuwste versie van het script.")

    except Exception as e:
        print(f"Fout bij het controleren op updates: {e}")

def contact_menu():
    """Menu voor contactinformatie."""
    print("\n--- Contact Menu ---")
    print("1. Bekijk GitHub-pagina")
    print("2. Terug naar hoofdmenu")

    choice = input("\nSelecteer een optie (1/2): ")
    if choice == '1':
        print("\nBezoek mijn GitHub-pagina voor updates en meer:")
        print("https://github.com/DutchCyberSec")
    elif choice == '2':
        return
    else:
        print("\nOngeldige keuze. Probeer opnieuw.")

def version_menu():
    """Menu voor het controleren van de versie."""
    print("\n--- Versie Menu ---")
    print(f"Huidige scriptversie: {__version__}")

    try:
        # Probeer de nieuwste versie op GitHub op te halen
        response = requests.get("https://raw.githubusercontent.com/DutchCyberSec/Network_Tool/main/Network_Tool.py")
        latest_script = response.text
        latest_version = [line for line in latest_script.split('\n') if '__version__' in line][0].split('=')[1].strip(' "\'\t')

        print(f"Nieuwste versie op GitHub: {latest_version}")
        
        if __version__ != latest_version:
            print("\nEr is een nieuwe versie beschikbaar. Overweeg om bij te werken.")
    except Exception as e:
        print(f"Fout bij het ophalen van de nieuwste versie op GitHub: {e}")

def main_menu():
    """Hoofdmenu van het script."""
    while True:
        print_disclaimer()
        print("\n--- Hoofdmenu ---")
        print("1. Uitvoeren scan")
        print("2. Controleer op updates")
        print("3. Contactinformatie")
        print("4. Versie controleren")
        print("5. Afsluiten")

        choice = input("\nSelecteer een optie (1/2/3/4/5): ")
        if choice == '1':
            run_scan_menu()
        elif choice == '2':
            check_for_update()
        elif choice == '3':
            contact_menu()
        elif choice == '4':
            version_menu()
        elif choice == '5':
            print("\nAfsluiten...")
            break
        else:
            print("\nOngeldige keuze. Probeer opnieuw.")

def run_scan_menu():
    """Menu voor het uitvoeren van de scan."""
    print_disclaimer()
    target = input("\nVoer het doel-IP-adres, het IP-bereik, of de domeinnaam in: ")
    intense_scan = input("Wil je een intensieve scan uitvoeren? (ja/nee): ").lower() == 'ja'
    service_detection = input("Wil je service-detectie inschakelen? (ja/nee): ").lower() == 'ja'
    
    # ... (Voeg hier verdere gebruikersinvoer toe, zoals aangepaste NMAP-argumenten)

    nm = nmap.PortScanner()

    # Voer een ping-scan uit om actieve hosts te detecteren
    nm.scan(hosts=target, arguments='-sn')
    
    # Lijst met actieve hosts
    active_hosts = [x for x in nm.all_hosts() if nm[x]['status']['state'] == 'up']
    
    # Druk de header en disclaimer af
    print_disclaimer()

    # Wacht 20 seconden met de timer
    print("\nWachten op 20 seconden...")
    time.sleep(20)

    # Voer de scan uit op actieve hosts
    scan_active_hosts(active_hosts, intense_scan, service_detection)

# Start het script
if __name__ == "__main__":
    main_menu()
