import os
import subprocess
from pathlib import Path
from shutil import which
import json
from typing import Union
from openai import OpenAI

# print("in attackdetection3.py")

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
        "-e", "frame.time",
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

# System message for OpenAI
system_message = """
You are an advanced network-traffic classification engine with deep expertise in PCAP-based intrusion detection. You will be given CSV data exported from a PCAP file, containing packet-level features such as timestamps, IPs, ports, protocols, flags, lengths, and HTTP fields.

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
    # Convert PCAP to CSV
    try:
        csv_content = convert_pcap_to_csv(path)
    except Exception as e:
        print(f"Error converting PCAP to CSV: {e}")
        return "error"

    # Construct user message
    user_message = f"Here is the CSV data:\n\n{csv_content}\n\nPlease analyze this data and provide your response in the specified JSON format."

    print("calling o3")
    # Call OpenAI API
    try:
        response = client.chat.completions.create(
            # model="gpt-4o-mini-2024-07-18",
            # model="o4-mini-2025-04-16",
            model = "o3-2025-04-16",
            # model="gpt-4o",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message}
            ],
            # temperature=0.1,
            response_format={"type": "json_object"},
            # max_tokens=150  # Adjust as needed
        )
        res_text = response.choices[0].message.content.strip()
        res = json.loads(res_text)
        print(res)
        if "attack_type" in res and "confidence" in res:
            attack = res["attack_type"]
            confidence = res["confidence"]
        else:
            print("Invalid response format")
            return "error"
    except json.JSONDecodeError:
        print("Failed to parse JSON response")
        return "error"
    except Exception as e:
        print(f"Error calling OpenAI API: {e}")
        return "error"

    # Calculate number of packets
    try:
        num_packets = len(csv_content.splitlines()) - 1  # Subtract header
    except Exception as e:
        print(f"Error calculating number of packets: {e}")
        return "error"

    # Compute output
    if attack == "Normal":
        op = {"Normal": num_packets}
    else:
        attack_count = int(num_packets * (confidence / 100))
        normal_count = num_packets - attack_count
        op = {"Normal": normal_count, attack: attack_count}

    return str(op)

# if __name__ == "__main__":
#     # op = detect_attack_func("/Users/thanikella_nikhil/Downloads/four_node_csma-0-0.pcap")
#     op = detect_attack_func("/Users/thanikella_nikhil/Downloads/GoldenEye.pcap")
#     # op = detect_attack_func("/Users/thanikella_nikhil/Downloads/wifi-random-topology-0-0.pcap")
#     # op = detect_attack_func("/Users/thanikella_nikhil/Downloads/spoofing-attack-1-0.pcap")
#     # op = detect_attack_func("/Users/thanikella_nikhil/Downloads/spoofing-attack-2-0.pcap")
#     # op = detect_attack_func("/Users/thanikella_nikhil/Downloads/new_ddos_simulation-0-0.pcap")
#     print(op)

# import os
# import subprocess
# from pathlib import Path
# from shutil import which
# import json
# from typing import Union
# from openai import OpenAI
# import multiprocessing
# import argparse

# # Function to convert PCAP to CSV using tshark
# def convert_pcap_to_csv(pcap_path: Union[str, Path]) -> str:
#     if which("tshark") is None:
#         raise RuntimeError("tshark binary not found in PATH")

#     pcap_path = Path(pcap_path).expanduser().resolve()

#     tshark_cmd = [
#         "tshark",
#         "-r", str(pcap_path),
#         "-T", "fields",
#         "-e", "frame.time",
#         "-e", "ip.src",
#         "-e", "ip.dst",
#         "-e", "ip.proto",
#         "-e", "tcp.srcport",
#         "-e", "tcp.dstport",
#         "-e", "udp.srcport",
#         "-e", "udp.dstport",
#         "-e", "tcp.flags",
#         "-e", "tcp.flags.syn",
#         "-e", "tcp.flags.reset",
#         "-e", "frame.len",
#         "-e", "data.len",
#         "-e", "ip.ttl",
#         "-e", "tcp.window_size",
#         "-e", "tcp.ack",
#         "-e", "http.request.method",
#         "-e", "http.response.code",
#         "-E", "header=y",
#         "-E", "separator=,",
#         "-E", "quote=d",
#         "-E", "occurrence=f",
#     ]

#     result = subprocess.run(
#         tshark_cmd,
#         check=True,
#         capture_output=True,
#         text=True
#     )
#     return result.stdout

# # System message for OpenAI
# system_message = """
# You are an advanced network-traffic classification engine with deep expertise in PCAP-based intrusion detection. You will be given CSV data exported from a PCAP file, containing packet-level features such as timestamps, IPs, ports, protocols, flags, lengths, and HTTP fields.

# Your task is to analyze this data and determine whether it contains any malicious activity. If it does, specify the type of attack and your confidence level (as an integer percentage). If it does not, indicate that it is normal traffic.

# Classification labels:
# - Normal
# - Reconnaissance
# - Denial of Service
# - Distributed Denial of Service
# - Web Attack
# - Malware

# Definitions:
# - Normal: Refers to normal or non-malicious network traffic or activity that is expected and does not pose any security risk.
# - Reconnaissance: The process of gathering information about a target system, network, or environment to prepare for an attack, often through methods like scanning, enumeration, or OS fingerprinting.
# - DDoS (Distributed Denial of Service): A type of attack that attempts to disrupt the normal traffic of a targeted server, service, or network by overwhelming it with a flood of internet traffic from multiple sources.
# - DoS (Denial of Service): A type of cyberattack that aims to make a system or network unavailable by overwhelming it with traffic or exploiting vulnerabilities.
# - Web Attack - SQL Injection: A type of attack where the attacker exploits vulnerabilities in a web application's input handling to execute arbitrary SQL code on the backend database.
# - Malware: Refers to any software designed to intentionally disrupt, damage, or gain unauthorized access to computer systems and networks.

# When providing your analysis, respond with a JSON object containing the keys "attack_type" and "confidence". For example:
# {
#   "attack_type": "Denial of Service",
#   "confidence": 85
# }

# Your response should contain only the JSON object and no additional text.
# """

# # Function to detect attacks
# def detect_attack_func(path: Union[str, Path], api_key: str) -> str:
#     openai_api_key = os.getenv('OPENAI_API_KEY')
#     # Initialize OpenAI client
#     try:
#         client = OpenAI(api_key=openai_api_key)
#     except Exception as e:
#         print(f"Error initializing OpenAI client: {e}")
#         return "error"

#     # Convert PCAP to CSV
#     try:
#         csv_content = convert_pcap_to_csv(path)
#     except Exception as e:
#         print(f"Error converting PCAP to CSV: {e}")
#         return "error"

#     # Construct user message
#     user_message = f"Here is the CSV data:\n\n{csv_content}\n\nPlease analyze this data and provide your response in the specified JSON format."

#     # Call OpenAI API
#     try:
#         response = client.chat.completions.create(
#             model="o4-mini-2025-04-16",
#             messages=[
#                 {"role": "system", "content": system_message},
#                 {"role": "user", "content": user_message}
#             ],
#             response_format={"type": "json_object"},
#         )
#         res_text = response.choices[0].message.content.strip()
#         res = json.loads(res_text)
#         print(res)  # Keep the debug print as in your original
#         if "attack_type" in res and "confidence" in res:
#             attack = res["attack_type"]
#             confidence = res["confidence"]
#         else:
#             print("Invalid response format")
#             return "error"
#     except json.JSONDecodeError:
#         print("Failed to parse JSON response")
#         return "error"
#     except Exception as e:
#         print(f"Error calling OpenAI API: {e}")
#         return "error"

#     # Calculate number of packets
#     try:
#         num_packets = len(csv_content.splitlines()) - 1  # Subtract header
#     except Exception as e:
#         print(f"Error calculating number of packets: {e}")
#         return "error"

#     # Compute output
#     if attack == "Normal":
#         op = {"Normal": num_packets}
#     else:
#         attack_count = int(num_packets * (confidence / 100))
#         normal_count = num_packets - attack_count
#         op = {"Normal": normal_count, attack: attack_count}

#     return str(op)

# # Worker function to process a chunk of files
# def worker(chunk, api_key):
#     results = []
#     for file in chunk:
#         try:
#             result = detect_attack_func(file, api_key)
#             results.append((file, result))
#         except Exception as e:
#             results.append((file, f"error: {str(e)}"))
#     return results

# # Function to split list into chunks
# def split_into_chunks(lst, n):
#     if n <= 0:
#         n = 1  # Ensure at least one group
#     chunk_size = len(lst) // n
#     remainder = len(lst) % n
#     chunks = []
#     start = 0
#     for i in range(n):
#         end = start + chunk_size + (1 if i < remainder else 0)
#         chunks.append(lst[start:end])
#         start = end
#     return chunks

# if __name__ == "__main__":
#     # Set up argument parser
#     parser = argparse.ArgumentParser(description="Process PCAP files in parallel.")
#     parser.add_argument("pcap_dir", help="Directory containing PCAP files")
#     parser.add_argument("--num_processes", type=int, default=multiprocessing.cpu_count(),
#                         help="Number of processes (groups) to use")
#     parser.add_argument("--api_key", required=True, help="OpenAI API key")
#     args = parser.parse_args()

#     # Get list of PCAP files
#     pcap_dir = Path(args.pcap_dir)
#     pcap_files = [str(p) for p in pcap_dir.glob("*.pcap")]

#     if not pcap_files:
#         print("No PCAP files found in the directory.")
#         exit(1)

#     # Determine number of processes and split files into chunks
#     num_processes = min(args.num_processes, len(pcap_files))  # Don't exceed number of files
#     chunks = split_into_chunks(pcap_files, num_processes)

#     # Process chunks in parallel
#     with multiprocessing.Pool(processes=num_processes) as pool:
#         from functools import partial
#         worker_with_key = partial(worker, api_key=args.api_key)
#         results = pool.map(worker_with_key, chunks)

#     # Flatten the list of results
#     all_results = [item for sublist in results for item in sublist]

#     # Output results
#     for file, result in all_results:
#         print(f"{file}: {result}")