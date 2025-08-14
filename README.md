# AutoRecon for Local Network

![Python](https://img.shields.io/badge/python-3.x-blue)
![Nmap](https://img.shields.io/badge/nmap-required-green)


## Goal
A simple Python/Bash script to automatically scan your local network and gather information about all connected devices using Kali Linux tools like `nmap` and `whois`.

## Features
- Detect all devices on your local network
- Collect device details such as IP, MAC address, and open ports

## Requirements

- Python 3.x  
- [nmap]

## Installation
1. Clone the repository:
   ```bash
    git clone https://github.com/Mayuresh-02/autorecon
    cd autorecon

2. Run the Script:
   ```bash
   python autorecon.py

3. Follow promots to enter:
  - Enter your network range

4. Find the result saved:
   ```bash
   less scan_results.txt



# AutoRecon v2 - Automated Network Reconnaissance Tool
![Python](https://img.shields.io/badge/python-3.x-blue)
![Nmap](https://img.shields.io/badge/nmap-required-green)

AutoRecon v2 is a Python-based ethical hacking tool that automates network host discovery and port scanning using **nmap**. It helps identify live hosts and their open ports with service and OS details, outputting results in multiple formats for easy analysis.

## Features

- 🔍 Fast host discovery with ping sweep  
- ⚡ Multi-threaded TCP SYN scan with service/version and OS detection  
- 📄 Saves detailed XML and human-readable outputs per host  
- 📊 Generates consolidated CSV and stylish HTML reports  
- ⚙️ Supports custom port ranges and configurable threading

## Requirements

- Python 3.x  
- [nmap](https://nmap.org/) installed and accessible in your system PATH  
  > On Debian/Ubuntu: `sudo apt install nmap`

## Usage

1. Clone the repo:
   ```bash
   git clone https://github.com/Mayuresh-02/autorecon
   cd autorecon

2. Run the Script:
   ```bash
   python autorecon_v2.py

3. Follow promots to enter:
  - Target network range (CIDR, e.g. 192.168.1.0/24)
  - Ports to scan (default 1-1000 or type full for all ports)
  - Number of threads (recommended 50-200)

4. Find the result saved:
   ```bash
   xdg-open "$(ls -td results/scan_*/ | head -1)/report.html"


## Disclaimer

This tool is intended only for authorized security testing and educational purposes.
Always obtain explicit permission before scanning any network or host.

**Feel free to open issues or contribute improvements!** 🚀
   
