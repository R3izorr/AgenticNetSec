# import os
# import time
# import sys
# import google.generativeai as genai
# from google.ai.generativelanguage_v1beta.types import content
# import subprocess
# from pathlib import Path
# from shutil import which
# import json
# from typing import Union

# # Adjust the system path to include backend directory
# backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# sys.path.insert(0, backend_dir)
# from secretKeys import GEMINI_API_KEYS  # Import the list of API keys

# # Function to upload a file to Gemini
# def upload_to_gemini(path: str, mime_type: str = None):
#     file = genai.upload_file(path, mime_type=mime_type)
#     return file

# # Function to wait for uploaded files to become active
# def wait_for_files_active(files):
#     for name in (file.name for file in files):
#         file = genai.get_file(name)
#         while file.state.name == "PROCESSING":
#             print(".", end="", flush=True)
#             time.sleep(10)
#             file = genai.get_file(name)
#         if file.state.name != "ACTIVE":
#             raise Exception(f"File {file.name} failed to process")

# # Configuration for the Gemini model
# generation_config = {
#     "temperature": 0.3,
#     "top_p": 0.95,
#     "top_k": 40,
#     "max_output_tokens": 8192,
#     "response_schema": content.Schema(
#         type=content.Type.OBJECT,
#         required=["attack_type", "confidence"],
#         properties={
#             "attack_type": content.Schema(type=content.Type.STRING),
#             "confidence": content.Schema(type=content.Type.INTEGER),
#         },
#     ),
#     "response_mime_type": "application/json",
# }

# # Prompt for the Gemini model
# prompt = """You are an advanced network-traffic classification engine with deep expertise in PCAP-based intrusion detection. You will be given a CSV file exported from a PCAP, containing packet-level features (timestamps, IPs, ports, protocols, flags, lengths, HTTP fields, etc.). Your sole task is to decide whether this traffic contains an attack, and if so, which one.

# CLASSIFICATION LABELS:
# ['Normal', 'Reconnaissance', 'Denial of Service', 'Distributed Denial of Service', 'Web Attack', 'Malware']

# DEFINITIONS FOR YOUR REFERENCE:
# - Normal: Refers to normal or non-malicious network traffic or activity that is expected and does not pose any security risk.
# - Reconnaissance: The process of gathering information about a target system, network, or environment to prepare for an attack, often through methods like scanning, enumeration, or OS fingerprinting.
# - DDoS (Distributed Denial of Service): A type of attack that attempts to disrupt the normal traffic of a targeted server, service, or network by overwhelming it with a flood of internet traffic from multiple sources.
# - DoS (Denial of Service): A type of cyberattack that aims to make a system or network unavailable by overwhelming it with traffic or exploiting vulnerabilities.
# - Web Attack - SQL Injection: A type of attack where the attacker exploits vulnerabilities in a web application's input handling to execute arbitrary SQL code on the backend database.
# - Malware: Refers to any software designed to intentionally disrupt, damage, or gain unauthorized access to computer systems and networks.

# If you determine there is no malicious activity, set "attack_type": "Normal". Do not include any extra fields, explanations, or formatting."""

# # Function to convert PCAP to CSV using tshark
# def convert_pcap_to_csv(pcap_path: Union[str, Path], csv_path: Union[str, Path]) -> None:
#     if which("tshark") is None:
#         raise RuntimeError("tshark binary not found in PATH")

#     pcap_path = Path(pcap_path).expanduser().resolve()
#     csv_path = Path(csv_path).expanduser().resolve()

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

#     with open(csv_path, "w") as csv_file:
#         subprocess.run(
#             tshark_cmd,
#             check=True,
#             stdout=csv_file,
#             text=True
#         )

# # Main function to detect attacks
# def detect_attack_func(path: Union[str, Path], api_key: str) -> str:
#     # Configure the Gemini API with the provided api_key
#     genai.configure(api_key=api_key)
    
#     # Initialize the model after configuring the api_key
#     model = genai.GenerativeModel(
#         model_name="gemini-2.5-flash-preview-04-17",
#         # model_name="gemini-2.5-pro-exp-03-25",
#         # model_name="gemini-2.5-pro-preview-05-06",
#         # model_name="gemini-1.5-pro",
#         # model_name="gemini-2.0-flash",
#         generation_config=generation_config,
#     )
    
#     path = Path(path)
#     csv_path = path.with_suffix('.csv')
#     convert_pcap_to_csv(path, csv_path)
#     with open(csv_path, 'r') as f:
#         num_packets = sum(1 for line in f) - 1  # Subtract header
#     files = [upload_to_gemini(str(csv_path), mime_type="text/csv")]
#     wait_for_files_active(files)
#     chat_session = model.start_chat(history=[])
#     response = chat_session.send_message([files[0], prompt])
#     res = json.loads(response.text)
#     attack = res["attack_type"]
#     confidence = res["confidence"]
#     if attack == "Normal":
#         op = {"Normal": num_packets}
#     else:
#         attack_count = int(num_packets * (confidence / 100))
#         normal_count = num_packets - attack_count
#         op = {"Normal": normal_count, attack: attack_count}
#     return str(op)

import os
import time
import sys
from google import genai
from google.genai.types import Part
import subprocess
from pathlib import Path
from shutil import which
import json
from typing import Union
from google.cloud import storage

# Adjust the system path to include backend directory
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, backend_dir)
from secretKeys import GEMINI_API_KEYS  # Import the list of API keys (if needed)

# Set environment variables for Vertex AI
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/Users/thanikella_nikhil/Downloads/mythical-mason-460719-n7-66c3e972c0aa.json'
os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'True'
os.environ['GOOGLE_CLOUD_PROJECT'] = 'mythical-mason-460719-n7'
os.environ['GOOGLE_CLOUD_LOCATION'] = 'us-central1'

# Initialize clients
client = genai.Client()
storage_client = storage.Client()
bucket = storage_client.bucket('gemini-images-bucket')  # Replace with your bucket name

# Configuration for the Gemini model
generation_config = {
    "temperature": 0.3,
    "response_schema": {
        "type": "object",
        "properties": {
            "attack_type": {"type": "string"},
            "confidence": {"type": "integer"}
        },
        "required": ["attack_type", "confidence"]
    },
    "response_mime_type": "application/json",
}

# Prompt for the Gemini model
prompt = """You are an advanced network-traffic classification engine with deep expertise in PCAP-based intrusion detection. You will be given a CSV file exported from a PCAP, containing packet-level features (timestamps, IPs, ports, protocols, flags, lengths, HTTP fields, etc.). Your sole task is to decide whether this traffic contains an attack, and if so, which one.

CLASSIFICATION LABELS:
['Normal', 'Reconnaissance', 'Denial of Service', 'Distributed Denial of Service', 'Web Attack', 'Malware']

DEFINITIONS FOR YOUR REFERENCE:
- Normal: Refers to normal or non-malicious network traffic or activity that is expected and does not pose any security risk.
- Reconnaissance: The process of gathering information about a target system, network, or environment to prepare for an attack, often through methods like scanning, enumeration, or OS fingerprinting.
- DDoS (Distributed Denial of Service): A type of attack that attempts to disrupt the normal traffic of a targeted server, service, or network by overwhelming it with a flood of internet traffic from multiple sources.
- DoS (Denial of Service): A type of cyberattack that aims to make a system or network unavailable by overwhelming it with traffic or exploiting vulnerabilities.
- Web Attack - SQL Injection: A type of attack where the attacker exploits vulnerabilities in a web application's input handling to execute arbitrary SQL code on the backend database.
- Malware: Refers to any software designed to intentionally disrupt, damage, or gain unauthorized access to computer systems and networks.

If you determine there is no malicious activity, set "attack_type": "Normal". Do not include any extra fields, explanations, or formatting."""

# Function to convert PCAP to CSV using tshark
def convert_pcap_to_csv(pcap_path: Union[str, Path], csv_path: Union[str, Path]) -> None:
    if which("tshark") is None:
        raise RuntimeError("tshark binary not found in PATH")

    pcap_path = Path(pcap_path).expanduser().resolve()
    csv_path = Path(csv_path).expanduser().resolve()

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

    with open(csv_path, "w") as csv_file:
        subprocess.run(
            tshark_cmd,
            check=True,
            stdout=csv_file,
            text=True
        )

# Main function to detect attacks
def detect_attack_func(path: Union[str, Path], api_key: str) -> str:
    # Convert PCAP to CSV
    path = Path(path)
    csv_path = path.with_suffix('.csv')
    try:
        convert_pcap_to_csv(path, csv_path)
    except Exception as e:
        print(f"Error converting PCAP to CSV: {e}")
        return "error"

    # Upload CSV to GCS
    blob_name = f'temp/{os.path.basename(csv_path)}'
    blob = bucket.blob(blob_name)
    try:
        blob.upload_from_filename(str(csv_path))
    except Exception as e:
        print(f"Error uploading CSV to GCS: {e}")
        return "error"
    csv_gcs_uri = f'gs://{bucket.name}/{blob_name}'

    # Define contents for Gemini API
    contents = [
        Part(text=prompt),
        Part(file_data={"file_uri": csv_gcs_uri, "mime_type": "text/csv"})
    ]

    try:
        # Call Gemini API
        response = client.models.generate_content(
            # model="gemini-2.5-flash-preview-05-20",
            model="gemini-2.5-pro-preview-05-06",
            contents=contents,
            config=generation_config
        )
        res = json.loads(response.text.strip())
        print("imp", res)
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
        print(f"Error calling Gemini: {e}")
        return "error"

    # Clean up GCS
    try:
        blob.delete()
    except Exception as e:
        print(f"Error deleting blob: {e}")

    # Read number of packets from CSV
    try:
        with open(csv_path, 'r') as f:
            num_packets = sum(1 for line in f) - 1  # Subtract header
    except Exception as e:
        print(f"Error reading CSV file: {e}")
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
#     op = detect_attack_func("/Users/thanikella_nikhil/Downloads/spoofing-attack-0-0.pcap")
#     print(op)
