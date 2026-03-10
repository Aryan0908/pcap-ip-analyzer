# PCAP IP Analyzer

A Python tool for network forensics investigations that automatically extracts 
external IP addresses from PCAP files and checks their reputation 
against VirusTotal.

## What it does
- Parses PCAP capture files
- Extracts and deduplicates all external IP addresses
- Filters out internal, private and broadcast traffic automatically
- Queries VirusTotal API for malicious/suspicious reputation
- Generates a structured investigation report

## Requirements
pip install pyshark requests

## Setup
1. Get a free VirusTotal API key at virustotal.com
2. Replace the API key in ipextractor.py with your own key

## Usage
python ipextractor.py -p <pcap_file> -d <output_directory> -f <report_filename>

## Example
python ipextractor.py -p investigation.pcap -d reports -f findings.txt

## Example Output
=== PCAP INVESTIGATION REPORT ===
Total External IPs Analyzed: 47
Malicious/Suspicious IPs Found: 3

=== MALICIOUS/SUSPICIOUS IPs ===
IP: 185.220.101.x
Stats: {'malicious': 12, 'suspicious': 3...}

## Tools Used
- PyShark — PCAP parsing
- VirusTotal API v3 — IP reputation
- Argparse — CLI interface
