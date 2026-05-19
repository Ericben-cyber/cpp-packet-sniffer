# C++ Packet Sniffer

A lightweight packet capture and protocol analysis tool built in C++ using PcapPlusPlus for Windows environments. It captures live traffic, supports optional port filtering and writes it to a .pcap file for Wireshark analysis.

## Dependencies

This program requires Npcap in order to run, or libpcap if intended for a Linux operating system. Before running, make sure you have administrator or root privileges as they are required for packet capture.

## Setup

- Install Npcap from the link: https://npcap.com/#download
- Install PcapPlusPlus: https://pcapplusplus.github.io/docs/install
- Open the Visual Studio solution 
- Select the required build configuration ( e.g. x64 Release ) 
- Build the project

## Features

- Captures live network packets
- Supports optional port filtering
- Detects and summarizes packet protocol layers
- Counts Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, TLS/SSL, and ARP packets
- Exports captured traffic to a .pcap file for Wireshark analysis

## Why I Built This

I built this project to better understand packet capture, protocol parsing, and traffic analysis from a SOC analyst and networking perspective.

## Future Improvements

- Expand on filtering options
- Develop a better command line argument input method
- Packet capture live summaries 
- Implement basic IDS/IPS detection rules

## Usage

```powershell
.\PacketCapture
.\PacketCapture 443
```