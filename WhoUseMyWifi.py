import os
import subprocess
import platform
import socket
import requests
import json
import time
import threading
from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.progress import Progress

console = Console()

def print_banner():
    banner = """
           Playing:
𝕎𝕙𝕠 𝕌𝕤𝕖 𝕄𝕪 𝕎𝕚𝕗𝕚 - Powerfull Wifi Tool" 
01:57 ───────●─── 02:55
ㅤ◁ㅤ ❚❚ ㅤ▷ ㅤㅤ↻ ♡                                                                         
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold magenta]🔍 Find out who is in your network. - Ağında kimlerin olduğunu öğren.[/bold magenta]\n")
    console.print("[bold yellow]📌 Developer: [cyan]https://github.com/Mmthxnce[/cyan][/bold yellow]")

def install_dependencies():
    try:
        import scapy
    except ImportError:
        console.print("[bold yellow][*] Scapy yüklenmemiş. Yükleniyor...[/bold yellow]")
        os.system("pip install scapy")

install_dependencies()

def network_scan(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=1.5, verbose=False)[0]

    devices = []
    threads = []

    def process_device(sent, received):
        device_info = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": get_hostname(received.psrc),
            "vendor": get_mac_vendor(received.hwsrc),
            "wifi_signal": get_wifi_signal_strength(),
            "location": get_location_info(received.psrc)
        }
        devices.append(device_info)

    for sent, received in result:
        thread = threading.Thread(target=process_device, args=(sent, received))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return devices

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Bilinmiyor"

def get_mac_vendor(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=2)
        return response.text if response.status_code == 200 else "Bilinmiyor"
    except:
        return "Bilinmiyor"

def get_location_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        data = response.json()
        return f"{data.get('city', 'Bilinmiyor')}, {data.get('region', 'Bilinmiyor')}, {data.get('country', 'Bilinmiyor')}"
    except:
        return "Bilinmiyor"

def get_wifi_signal_strength():
    try:
        if platform.system() == "Linux":
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            lines = result.stdout.split("\n")
            for line in lines:
                if "Signal level" in line:
                    return line.strip().split("Signal level=")[-1].split(" ")[0] + " dBm"
        elif platform.system() == "Windows":
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
            lines = result.stdout.split("\n")
            for line in lines:
                if "Signal" in line:
                    return line.strip().split(":")[-1].strip()
        return "Bilinmiyor"
    except:
        return "Bilinmiyor"

def save_results(devices):
    with open("network_scan_results.json", "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=4, ensure_ascii=False)
    console.print("[green]📁 Sonuçlar 'network_scan_results.json' dosyasına kaydedildi.[/green]")

if __name__ == "__main__":
    print_banner()
    ip_range = "192.168.1.1/24"

    console.print("\n[bold magenta]⚡ Tarama Başlıyor, lütfen bekleyiniz...[/bold magenta]\n")

    total_time = 10  # Tarama süresi (saniye)
    start_time = time.time()

    with Progress() as progress:
        task = progress.add_task("[cyan]🔍 Tarama yapılıyor...", total=total_time)

        devices = []
        scan_thread = threading.Thread(target=lambda: devices.extend(network_scan(ip_range)))
        scan_thread.start()

        while not progress.finished:
            elapsed_time = time.time() - start_time
            remaining_time = max(0, total_time - elapsed_time)
            progress.update(task, completed=elapsed_time)

            progress.tasks[0].description = f"[cyan]🔍 Tarama devam ediyor... ({int(remaining_time)} saniye kaldı)"

            if elapsed_time >= total_time:
                progress.update(task, completed=total_time)
                break

            time.sleep(1)

        scan_thread.join()

    console.print("\n✅ [bold green]Tarama tamamlandı![/bold green]\n")
    console.print("[bold yellow]Ağda bağlı cihazlar:[/bold yellow]\n")
    console.print("[cyan]IP Address\tMAC Address\tHost Name\tVendor\tLocation\tWiFi Signal[/cyan]")
    console.print("-" * 100)

    for device in devices:
        console.print(f"[cyan]{device['ip']}[/cyan]\t[magenta]{device['mac']}[/magenta]\t[green]{device['hostname']}[/green]\t[yellow]{device['vendor']}[/yellow]\t[red]{device['location']}[/red]\t[blue]{device['wifi_signal']}[/blue]")

    choice = console.input("\n💾 [bold cyan]Sonuçları kaydetmek istiyor musunuz? (E/H) | Do you want to save results? (Y/N):[/bold cyan] ").strip().lower()
    
    if choice in ["e", "y"]:
        save_results(devices)
    else:
        console.print("[red]❌ Sonuçlar kaydedilmedi.[/red]")