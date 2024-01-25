import nmap
import subprocess
import threading
import socket
import time
import requests
import os

# Stel de huidige werkmap in op de map van het script
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Definieer de scriptversie
__version__ = "1.6"

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
    return header

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

def scan_ports(host, ports, intense):
    """Voer poortscan uit voor de opgegeven host."""
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments=f'-p {ports} -O' if intense else '-p 1-1024 -O')
    print(disclaimer)
    # Toon open poorten
    for proto in nm[host].all_protocols():
        print(f"\n{proto.upper()} poorten voor {host}:")
        ports = nm[host][proto].keys()
        for port in ports:
            print(f"Poort {port}: {nm[host][proto][port]['state']}")
            
            # Voer banner grabbing uit voor bekende services
            if nm[host][proto][port]['state'] == 'open':
                if port == 80 or port == 443:
                    subprocess.run(['curl', f'http://{host}:{port}', '--head'])
                elif port == 21:
                    subprocess.run(['ftp', '-v', f'{host}'])

    # Toon besturingssysteeminformatie
    os_info = nm[host].get('osclass', [])
    if os_info:
        print(f"\nBesturingssysteeminformatie voor {host}:")
        for os_class in os_info:
            print(f"Type: {os_class['osfamily']}, Vendor: {os_class['vendor']}, OS Gen: {os_class['osgen']}")
            
    # Voer DNS-query uit voor extra informatie
    get_ip_info(host)

def scan_active_hosts(active_hosts, intense):
    """Scan actieve hosts."""
    # Maak threads voor het scannen van actieve hosts
    threads = []
    for host in active_hosts:
        thread = threading.Thread(target=scan_ports, args=(host, '1-1024', intense))
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

def whois_menu():
    """Menu voor Whois-opties."""
    print("\n--- Whois Menu ---")
    print("1. Voer Whois uit op een domein")
    print("2. Terug naar hoofdmenu")

    choice = input("\nSelecteer een optie (1/2): ")
    if choice == '1':
        domain = input("Voer het domein in: ")
        # Voer Whois uit
        subprocess.run(['whois', domain])
    elif choice == '2':
        return
    else:
        print("\nOngeldige keuze. Probeer opnieuw.")

def print_version_info():
    """Druk scriptversie en GitHub-versie-informatie af."""
    script_content = ""
    try:
        with open(os.path.basename(__file__), 'r') as current_file:
            script_content = current_file.read()
        
        current_version = [line for line in script_content.split('\n') if '__version__' in line][0]
        print(f"Huidige scriptversie: {current_version}")

        response = requests.get("https://raw.githubusercontent.com/DutchCyberSec/Network_Tool/main/Network_Tool.py")
        latest_script = response.text
        latest_version = [line for line in latest_script.split('\n') if '__version__' in line][0]
        print(f"Nieuwste versie op GitHub: {latest_version}")

    except Exception as e:
        print(f"Fout bij het ophalen van versie-informatie: {e}")

def main_menu():
    """Hoofdmenu van het script."""
    while True:
        print_disclaimer()
        print("\n--- Hoofdmenu ---")
        print("1. Uitvoeren scan")
        print("2. Controleer op updates")
        print("3. Contactinformatie")
        print("4. Whois")
        print("5. Versie-info")
        print("6. Afsluiten")

        choice = input("\nSelecteer een optie (1/2/3/4/5/6): ")
        if choice == '1':
            run_scan_menu()
        elif choice == '2':
            check_for_update()
        elif choice == '3':
            contact_menu()
        elif choice == '4':
            whois_menu()
        elif choice == '5':
            print_version_info()
        elif choice == '6':
            print("\nAfsluiten...")
            break
        else:
            print("\nOngeldige keuze. Probeer opnieuw.")

def run_scan_menu():
    """Menu voor het uitvoeren van de scan."""
    print_disclaimer()
    target = input("\nVoer het doel-IP-adres, het IP-bereik, of de domeinnaam in: ")
    intense_scan = input("Wil je een intensieve scan uitvoeren? (ja/nee): ").lower() == 'ja'
    
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

    print_active_hosts(active_hosts)
    scan_active_hosts(active_hosts, intense_scan)

if __name__ == "__main__":
    print_header()
    main_menu()
