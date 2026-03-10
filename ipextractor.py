import time
import pyshark
import requests
import json
import datetime
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--pcap')
parser.add_argument('-d', '--destination')
parser.add_argument('-f', '--file')
args = parser.parse_args()

cap = pyshark.FileCapture(args.pcap)
report_path = os.path.join(args.destination, args.file)
url = 'https://www.virustotal.com/api/v3/ip_addresses/'
headers = {"accept": "application/json", "x-apikey":"YOUR_VIRUS_TOTAL_API_KEY"}
external_ip = set()
ip_health = {}
malicious_ip = {}

def report(ip):
    if ip not in external_ip:
        external_ip.add(ip)
        health_check(ip)

def health_check(ip):
    try:
        time.sleep(15)
        response = requests.get(url + ip, headers=headers)
        response_dict = json.loads(response.text)
        malicious_rating = response_dict["data"]["attributes"]['last_analysis_stats']['malicious']
        suspicious_rating = response_dict["data"]["attributes"]['last_analysis_stats']['suspicious']

        ip_health[ip] = response_dict["data"]["attributes"]['last_analysis_stats']

        if malicious_rating > 0 or suspicious_rating > 0:
            malicious_ip[ip] = response_dict["data"]["attributes"]['last_analysis_stats']

    except Exception as e:
        print(f"{ip} and {e}")

def generate_report():
    with open(report_path, 'w') as f:
        f.write("=== PCAP INVESTIGATION REPORT ===\n")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        f.write(f"Generated: {timestamp}\n\n")
        f.write(f"Total External IPs Analyzed: {len(external_ip)}\n")
        f.write(f"Malicious/Suspicious IPs Found: {len(malicious_ip)}\n\n")

        if malicious_ip:
            f.write("=== MALICIOUS/SUSPICIOUS IPs ===\n")
            f.write(f"Count: {len(malicious_ip)}")
            for i, s in malicious_ip.items():
                f.write(f"\nIP: {i}\n")
                f.write(f"Stats: {s}\n")

        f.write("\n=== ALL EXTERNAL IPs ANALYZED ===\n")
        for i in external_ip:
            f.write(f"{i}: {ip_health.get(i, 'No data')}\n")

    print(f"\nReport saved as: {args.file}")

for packet in cap:
    if hasattr(packet, "ip"):
        src = packet.ip.src
        dst = packet.ip.dst

        if not src.startswith('10.') and not src.startswith('192.168.') and not src.startswith('172.') and not src.startswith('0.0.0') and not src.startswith('255.'):
            report(src)
        if not dst.startswith('10.') and not dst.startswith('192.168.') and not dst.startswith('172.') and not dst.startswith('0.0.0') and not dst.startswith('255.'):
            report(dst)

generate_report()




