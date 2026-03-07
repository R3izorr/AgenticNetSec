import os
import subprocess
from pathlib import Path
from shutil import which
import json
from typing import Union
from openai import OpenAI
import time
import re

# Set OpenAI API key
openai_api_key = os.getenv('OPENAI_API_KEY')
if not openai_api_key:
    raise ValueError("OPENAI_API_KEY environment variable is not set")
client = OpenAI(api_key=openai_api_key)

# Function to convert PCAP to CSV using tshark
def convert_pcap_to_csv(pcap_path: Union[str, Path]) -> str:
    if which("tshark") is None:
        raise RuntimeError("tshark binary not found in PATH")

    pcap_path = Path(pcap_path).expanduser().resolve()

    tshark_cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-T", "fields",
        "-e", "frame.time_epoch",  # Changed to epoch for easier processing
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "tcp.flags",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.reset",
        "-e", "frame.len",
        "-e", "data.len",
        "-e", "ip.ttl",
        "-e", "tcp.window_size",
        "-e", "tcp.ack",
        "-e", "http.request.method",
        "-e", "http.response.code",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    result = subprocess.run(
        tshark_cmd,
        check=True,
        capture_output=True,
        text=True
    )
    return result.stdout

# Preprocess CSV to extract valid packets and compute metrics
def preprocess_csv(csv_content):
    lines = csv_content.splitlines()
    if not lines:
        return "", [], 0, 0

    header = lines[0]
    packets = lines[1:]
    valid_packets = []
    timestamps = []
    src_ips = []

    for packet in packets:
        fields = packet.split(',')
        if len(fields) >= 12:  # Ensure we have enough fields up to frame.len
            valid_packets.append(packet)
            try:
                timestamps.append(float(fields[0]))  # frame.time_epoch
                src_ips.append(fields[1])  # ip.src
            except (IndexError, ValueError):
                pass

    # Calculate packet rate (packets per second)
    if timestamps:
        duration = max(timestamps) - min(timestamps)
        packet_rate = len(timestamps) / duration if duration > 0 else 0
    else:
        packet_rate = 0

    # Calculate unique source IPs
    unique_src_ips = len(set(src_ips))

    return header, valid_packets, packet_rate, unique_src_ips

# Sample packets to reduce data size while preserving diversity
def sample_packets(packets, sample_rate=50, max_packets=500):
    # Separate UDP and TCP packets based on ip.proto
    udp_packets = [p for p in packets if "17" in p.split(',')[3]]  # UDP: 17
    tcp_packets = [p for p in packets if "6" in p.split(',')[3]]   # TCP: 6
    other_packets = [p for p in packets if p not in udp_packets and p not in tcp_packets]

    # Sample each category
    sampled_udp = udp_packets[::sample_rate]
    sampled_tcp = tcp_packets[::sample_rate]
    sampled_other = other_packets[::sample_rate]

    # Combine and limit to max_packets
    sampled = sampled_udp + sampled_tcp + sampled_other
    if len(sampled) > max_packets:
        sampled = sampled[:max_packets]

    return sampled

# Calculate summary statistics
def calculate_summary(packets, packet_rate, unique_src_ips):
    num_packets = len(packets)
    if num_packets == 0:
        return 0, 0, packet_rate, unique_src_ips

    total_len = 0
    for packet in packets:
        fields = packet.split(',')
        try:
            frame_len = int(fields[11])  # frame.len at index 11
            total_len += frame_len
        except (IndexError, ValueError):
            pass

    avg_len = total_len / num_packets if num_packets > 0 else 0
    return num_packets, avg_len, packet_rate, unique_src_ips

# System message for OpenAI
system_message = """
You are an advanced network-traffic classification engine with deep expertise in PCAP-based intrusion detection. You will be given sampled CSV data exported from a PCAP file, containing packet-level features such as timestamps, IPs, ports, protocols, flags, lengths, and HTTP fields, along with summary statistics.

Your task is to analyze this data and determine whether it contains any malicious activity. If it does, specify the type of attack and your confidence level (as an integer percentage). If it does not, indicate that it is normal traffic.

Classification labels:
- Normal
- Reconnaissance
- Denial of Service
- Distributed Denial of Service
- Web Attack
- Malware

Definitions:
- Normal: Refers to normal or non-malicious network traffic or activity that is expected and does not pose any security risk.
- Reconnaissance: The process of gathering information about a target system, network, or environment to prepare for an attack, often through methods like scanning, enumeration, or OS fingerprinting.
- DDoS (Distributed Denial of Service): A type of attack that attempts to disrupt the normal traffic of a targeted server, service, or network by overwhelming it with a flood of internet traffic from multiple sources.
- DoS (Denial of Service): A type of cyberattack that aims to make a system or network unavailable by overwhelming it with traffic or exploiting vulnerabilities.
- Web Attack - SQL Injection: A type of attack where the attacker exploits vulnerabilities in a web application's input handling to execute arbitrary SQL code on the backend database.
- Malware: Refers to any software designed to intentionally disrupt, damage, or gain unauthorized access to computer systems and networks.

When providing your analysis, respond with a JSON object containing the keys "attack_type" and "confidence". For example:
{
  "attack_type": "Denial of Service",
  "confidence": 85
}

Your response should contain only the JSON object and no additional text.
"""

# Main function to detect attacks
def detect_attack_func(path: Union[str, Path], api_key: str) -> str:
    try:
        csv_content = convert_pcap_to_csv(path)
    except Exception as e:
        print(f"Error converting PCAP to CSV: {e}")
        return "error"

    # Preprocess the CSV data
    header, valid_packets, packet_rate, unique_src_ips = preprocess_csv(csv_content)
    if not valid_packets:
        print("No valid packets found after preprocessing")
        return "error"

    # Sample packets
    sampled_packets = sample_packets(valid_packets, sample_rate=50, max_packets=500)
    if not sampled_packets:
        print("No packets after sampling")
        return "error"

    # Calculate summary
    num_packets, avg_len, packet_rate, unique_src_ips = calculate_summary(valid_packets, packet_rate, unique_src_ips)

    # Construct sampled CSV and summary
    sampled_csv = header + "\n" + "\n".join(sampled_packets)
    summary = (f"Total packets: {num_packets}, Average packet length: {avg_len:.2f}, "
               f"Packet rate: {packet_rate:.2f} pps, Unique source IPs: {unique_src_ips}")
    user_message = f"Here is the sampled CSV data:\n\n{sampled_csv}\n\nSummary: {summary}\n\nPlease analyze this data for any malicious activity and provide your response in the specified JSON format."

    # Call OpenAI API with retry mechanism
    res = None
    for attempt in range(5):
        try:
            response = client.chat.completions.create(
                model="o4-mini-2025-04-16",
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                response_format={"type": "json_object"},
            )
            res_text = response.choices[0].message.content.strip()
            res = json.loads(res_text)
            print(res)
            break
        except json.JSONDecodeError:
            print("Failed to parse JSON response")
            return "error"
        except Exception as e:
            error_str = str(e)
            if "context_length_exceeded" in error_str:
                print("Context length exceeded, input too large")
                return "error: context_length_exceeded"
            elif "rate_limit_exceeded" in error_str:
                wait_time_match = re.search(r"try again in (\d+)ms", error_str)
                wait_time = float(wait_time_match.group(1)) / 1000 if wait_time_match else 2.0
                print(f"Rate limit hit, waiting {wait_time} seconds before retry {attempt + 1}/5")
                time.sleep(wait_time)
            elif attempt == 4:
                print(f"API call failed after 5 attempts: {e}")
                return "error"
            else:
                time.sleep(2)

    if res is None:
        print("All API attempts failed")
        return "error"

    # Process API response
    if "attack_type" in res and "confidence" in res:
        attack = res["attack_type"]
        try:
            confidence = int(res["confidence"])
        except ValueError:
            print(f"Error: Confidence value '{res['confidence']}' is not a valid integer")
            return "error"
    else:
        print("Invalid response format")
        return "error"

    # Compute output using preprocessed packet count
    if attack == "Normal":
        op = {"Normal": num_packets}
    else:
        attack_count = int(num_packets * (confidence / 100))
        normal_count = num_packets - attack_count
        op = {"Normal": normal_count, attack: attack_count}

    return str(op)