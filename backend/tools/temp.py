import os
import time
import sys
import google.generativeai as genai
from google.ai.generativelanguage_v1beta.types import content
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, backend_dir)
from secretKeys import *
import json

genai.configure(api_key=GEMINI_API_KEY)

def upload_to_gemini(path, mime_type=None):
    file = genai.upload_file(path, mime_type=mime_type)
    print(f"Uploaded file '{file.display_name}' as: {file.uri}")
    return file

def wait_for_files_active(files):
    print("Waiting for file processing...")
    for name in (file.name for file in files):
        file = genai.get_file(name)
        while file.state.name == "PROCESSING":
            print(".", end="", flush=True)
            time.sleep(10)
            file = genai.get_file(name)
        if file.state.name != "ACTIVE":
            raise Exception(f"File {file.name} failed to process")
    print("...all files ready\n")

generation_config = {
    "temperature": 0.3,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
    "response_schema": content.Schema(
        type=content.Type.OBJECT,
        required=["attack_type", "confidence"],
        properties={
            "attack_type": content.Schema(type=content.Type.STRING),
            "confidence": content.Schema(type=content.Type.INTEGER),
        },
    ),
    "response_mime_type": "application/json",
}

model = genai.GenerativeModel(
    model_name="gemini-2.5-pro-exp-03-25",
    generation_config=generation_config,
)

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

import subprocess
from pathlib import Path
from shutil import which

def convert_pcap_to_csv(pcap_path: str | Path, csv_path: str | Path) -> None:
    if which("tshark") is None:
        raise RuntimeError("tshark binary not found in PATH")

    pcap_path = Path(pcap_path).expanduser().resolve()
    csv_path  = Path(csv_path).expanduser().resolve()

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
        
    print(f"✓ Converted {pcap_path} → {csv_path}")

def detect_attack_func(path):
    print(f"Path: {path}")
    csvPath = convert_pcap_to_csv(path)
    files = [upload_to_gemini(csvPath, mime_type="text/csv")]
    wait_for_files_active(files)
    chat_session = model.start_chat(history=[])
    response = chat_session.send_message([files[0], prompt])
    print(response.text)
    res = json.loads(response.text)
    attack = res["attack_type"]
    confidence = res["confidence"]
    if attack == "Normal":
        op = {"Normal": confidence}
    op = {"Normal": 0, attack: confidence}
    return str(op)