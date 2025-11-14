#!/usr/bin/env python3
"""
ADB Network Scanner & Auto Shutdown Tool
Scansiona la rete locale alla ricerca di dispositivi con porta 5555 aperta (ADB)
e li spegne automaticamente
"""

import socket
import ipaddress
import threading
from queue import Queue
from typing import List, Tuple
import subprocess
import sys
import time

class ADBScanner:
    def __init__(self, subnet: str = None, port: int = 5555, timeout: float = 1.0, threads: int = 50):
        """
        Inizializza lo scanner ADB

        Args:
            subnet: Subnet da scannerizzare (es. "192.168.1.0/24"). Se None, rileva automaticamente
            port: Porta da scannerizzare (default: 5555 per ADB)
            timeout: Timeout per la connessione in secondi
            threads: Numero di thread da utilizzare
        """
        self.port = port
        self.timeout = timeout
        self.threads = threads
        self.open_devices = []
        self.print_lock = threading.Lock()
        self.queue = Queue()

        # Rileva automaticamente la subnet se non specificata
        if subnet is None:
            self.subnet = self.get_local_subnet()
        else:
            self.subnet = subnet

        print(f"[*] Subnet da scannerizzare: {self.subnet}")
        print(f"[*] Porta target: {self.port}")
        print(f"[*] Thread utilizzati: {self.threads}")
        print(f"[*] Timeout: {self.timeout}s\n")

    def get_local_ip(self) -> str:
        """Ottiene l'indirizzo IP locale della macchina"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            # Non serve che sia raggiungibile
            s.connect(('10.254.254.254', 1))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'

    def get_local_subnet(self) -> str:
        """
        Rileva automaticamente la subnet /24 della rete locale
        """
        local_ip = self.get_local_ip()
        # Crea una subnet /24 dall'IP locale
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)

    def check_port(self, ip: str) -> bool:
        """
        Verifica se una porta è aperta su un determinato IP

        Args:
            ip: Indirizzo IP da controllare

        Returns:
            True se la porta è aperta, False altrimenti
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_worker(self):
        """Worker thread che preleva IP dalla queue e li scansiona"""
        while True:
            ip = self.queue.get()
            if ip is None:
                break

            if self.check_port(ip):
                with self.print_lock:
                    print(f"[+] DISPOSITIVO TROVATO: {ip}:{self.port}")
                    self.open_devices.append(ip)

            self.queue.task_done()

    def scan_network(self) -> List[str]:
        """
        Scansiona la rete alla ricerca di dispositivi con la porta aperta

        Returns:
            Lista di indirizzi IP con la porta aperta
        """
        print(f"[*] Inizio scansione...\n")
        start_time = time.time()

        # Crea e avvia i thread worker
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.scan_worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Popola la queue con tutti gli IP della subnet
        network = ipaddress.ip_network(self.subnet)
        for ip in network.hosts():
            self.queue.put(str(ip))

        # Aspetta che tutti i task siano completati
        self.queue.join()

        # Ferma i thread worker
        for _ in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()

        elapsed_time = time.time() - start_time
        print(f"\n[*] Scansione completata in {elapsed_time:.2f} secondi")
        print(f"[*] Dispositivi trovati: {len(self.open_devices)}\n")

        return self.open_devices

    def connect_adb(self, ip: str) -> bool:
        """
        Connette ADB a un dispositivo via TCP/IP

        Args:
            ip: Indirizzo IP del dispositivo

        Returns:
            True se la connessione ha successo, False altrimenti
        """
        try:
            cmd = f"adb connect {ip}:{self.port}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return "connected" in result.stdout.lower() or "already connected" in result.stdout.lower()
        except Exception as e:
            with self.print_lock:
                print(f"[-] Errore connessione ADB a {ip}: {str(e)}")
            return False

    def shutdown_device(self, ip: str) -> bool:
        """
        Spegne un dispositivo Android via ADB

        Args:
            ip: Indirizzo IP del dispositivo

        Returns:
            True se il comando è stato eseguito, False altrimenti
        """
        try:
            # Prima connetti al dispositivo
            if not self.connect_adb(ip):
                with self.print_lock:
                    print(f"[-] Impossibile connettersi a {ip}")
                return False

            # Comando per spegnere il dispositivo
            # Utilizziamo 'reboot -p' che è il comando standard per lo spegnimento
            cmd = f"adb -s {ip}:{self.port} shell reboot -p"

            with self.print_lock:
                print(f"[*] Invio comando di spegnimento a {ip}...")

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            with self.print_lock:
                if result.returncode == 0:
                    print(f"[✓] Dispositivo {ip} spento con successo")
                else:
                    # Prova comando alternativo
                    cmd_alt = f"adb -s {ip}:{self.port} shell svc power shutdown"
                    result_alt = subprocess.run(cmd_alt, shell=True, capture_output=True, text=True, timeout=10)
                    if result_alt.returncode == 0:
                        print(f"[✓] Dispositivo {ip} spento con successo (metodo alternativo)")
                    else:
                        print(f"[-] Errore spegnimento {ip}: {result.stderr}")
                        return False

            # Disconnetti il dispositivo
            subprocess.run(f"adb disconnect {ip}:{self.port}", shell=True, capture_output=True, timeout=5)
            return True

        except subprocess.TimeoutExpired:
            with self.print_lock:
                print(f"[-] Timeout durante lo spegnimento di {ip}")
            return False
        except Exception as e:
            with self.print_lock:
                print(f"[-] Errore durante lo spegnimento di {ip}: {str(e)}")
            return False

    def shutdown_all_devices(self):
        """Spegne tutti i dispositivi trovati"""
        if not self.open_devices:
            print("[!] Nessun dispositivo da spegnere")
            return

        print(f"\n[*] Inizio procedura di spegnimento per {len(self.open_devices)} dispositivo/i...\n")

        success_count = 0
        for ip in self.open_devices:
            if self.shutdown_device(ip):
                success_count += 1
            time.sleep(0.5)  # Piccola pausa tra uno spegnimento e l'altro

        print(f"\n[*] Operazione completata: {success_count}/{len(self.open_devices)} dispositivi spenti")


def main():
    """Funzione principale"""
    print("=" * 60)
    print("  ADB Network Scanner & Auto Shutdown Tool")
    print("=" * 60)
    print()

    # Verifica che ADB sia installato
    try:
        result = subprocess.run("adb version", shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print("[!] ATTENZIONE: ADB non sembra essere installato o non è nel PATH")
            print("[!] Lo scanner funzionerà ma non sarà possibile spegnere i dispositivi")
            print()
    except Exception:
        print("[!] ATTENZIONE: Impossibile verificare l'installazione di ADB")
        print()

    # Puoi specificare una subnet manualmente o lasciare None per auto-detect
    # Esempi:
    # scanner = ADBScanner(subnet="192.168.1.0/24")
    # scanner = ADBScanner(subnet="10.0.0.0/24")
    scanner = ADBScanner(subnet=None)  # Auto-detect

    # Scansiona la rete
    devices = scanner.scan_network()

    # Se sono stati trovati dispositivi, chiedi conferma prima di spegnerli
    if devices:
        print("[*] Dispositivi con porta ADB aperta:")
        for i, device in enumerate(devices, 1):
            print(f"    {i}. {device}:{scanner.port}")

        print()
        try:
            choice = input("[?] Vuoi spegnere questi dispositivi? (s/n): ").strip().lower()
            if choice == 's' or choice == 'y' or choice == 'si' or choice == 'yes':
                scanner.shutdown_all_devices()
            else:
                print("[*] Operazione annullata dall'utente")
        except KeyboardInterrupt:
            print("\n[*] Operazione annullata dall'utente")
            sys.exit(0)
    else:
        print("[!] Nessun dispositivo con porta ADB aperta trovato nella rete")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Programma interrotto dall'utente")
        sys.exit(0)
