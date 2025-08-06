
This repository contains a powerful penetration testing utility developed in Python for automating Man-in-the-Middle (MITM) attacks on a local network.
The tool uses the Scapy library to perform network discovery, execute ARP spoofing, and intercept network traffic for analysis.

Prerequisites
For Linux
Python 3

Scapy library (pip install scapy)

For Windows
Python 3 (Ensure "Add Python to PATH" is checked during installation)

Scapy library (pip install scapy)

PyWin32 library (pip install pywin32)

Npcap: The Npcap packet capture library is required.

Download from the Npcap website.

During installation, you must check the box for "Install Npcap in WinPcap API-compatible Mode".

Usage Guide
On Linux
Open a terminal.

Navigate to the project directory.

Run the script with sudo privileges:

sudo python3 mitm_linux.py

The script will scan the network and display a list of potential targets.

Enter the ID of the victim you wish to target and press Enter.

Press Ctrl+C to stop the attack and restore the network.

On Windows
Running the script on Windows is a two-step process due to the requirement of a system reboot.

Step 1: Enable IP Forwarding

Open PowerShell as an Administrator.

Navigate to the project directory.

Run the script:

python mitm_windows.py

The script will update the registry and prompt you to reboot. Press Enter to exit the script.

Reboot your computer.

Step 2: Launch the Attack

After rebooting, open PowerShell as an Administrator again.

Navigate to the project directory.

Run the same script again:

python mitm_windows.py

The script will now list your network interfaces. Select the correct one.

It will then scan the network and list available targets.

Enter the ID of the victim and press Enter to begin the attack.

Press Ctrl+C to stop the attack and restore the network.

Output
The script will generate a file named intercepted_traffic.pcap in the directory you specified within the script. This file can be opened and analyzed with Wireshark to inspect the captured traffic in detail.

Ethical Disclaimer
This tool is intended for educational purposes and for use in authorized penetration testing environments only. Running this script on a network you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for any misuse or damage caused by this script.
