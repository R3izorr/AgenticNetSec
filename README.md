# NetMoniAI: An Agentic AI Framework for Network Security & Monitoring

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![arXiv](https://img.shields.io/badge/arXiv-2508.10052-b31b1b.svg)](https://arxiv.org/abs/2508.10052)

**NetMoniAI** is an agentic AI framework for automatic network monitoring and security that integrates decentralized analysis with lightweight centralized coordination. The framework consists of autonomous micro-agents at each node for local traffic analysis, and a central controller that aggregates insights to detect coordinated attacks.

📄 **Paper**: [NetMoniAI: An Agentic AI Framework for Network Security & Monitoring](https://arxiv.org/abs/2508.10052)  
🔗 **GitHub**: https://github.com/pzambare3/NetMoniAI

---

## ✨ Features

- **Hybrid Monitoring**: Combines packet-level and flow-level analysis for scalable threat detection
- **Autonomous Node Agents**: Each node runs integrated agent pipeline with LLM-powered semantic analysis
- **Two-Tier Architecture**: Decentralized node intelligence + centralized threat correlation
- **LLM Integration**: Supports GPT-O3, Gemini Pro, and local BERT for adaptive threat detection
- **Real-Time Dashboard**: WebSocket-based visualization with attacker/victim role identification
- **Validated Performance**: Tested on local testbed and NS-3 simulations (up to 50 nodes)

---

## 🏗️ Architecture

### Node-Level Agents

![Node Agent Architecture](paper/node_agent_architecture.png)

Each node runs an integrated agent pipeline with specialized modules:
- **PerformanceMonitoringAgent** - Metrics collection and threshold monitoring
- **SecurityAnalysisAgent** - LLM-based threat detection
- **ReportingAgent** - Structured report generation
- **ParameterTuningAgent** - Adaptive threshold adjustment
- **ChatAgent** - Natural language interface

### Central Controller (Global Controller)

![Central Controller Architecture](paper/central_controller_architecture.png)

Aggregates node reports to detect coordinated attacks:
- Correlates events across nodes via short-term memory
- Classifies nodes as attackers, victims, or benign
- Maintains system-wide situational awareness

> **Note**: Code uses "Global Controller" (gc prefix) which refers to the Central Controller in the paper.

## 📁 Repository Structure (high level)

```
NetMoniAI/
├── backend/                    # FastAPI backend
│   ├── app.py                 # Main application (local agent mode)
│   ├── appWebsocket.py        # WebSocket server
│   ├── analyze_nodes.py       # Offline PCAP batch analysis
│   ├── config.py              # Configuration
│   ├── nw_agents/             # Agent implementations
│   ├── tools/                 # PCAP analysis utilities
│   ├── segregated/            # PCAP storage (NS-3 outputs)
│   ├── requirements.txt       # Python dependencies
│   └── *.xml                  # NS-3 simulation scenarios
│
├── frontend/                   # React application
│   ├── src/
│   │   ├── components/        # UI components
│   │   │   ├── GlobalControllerDashboard.js
│   │   │   ├── LocalControllerDashboard.js
│   │   │   └── NetworkVisualizer.js
│   │   └── services/          # API clients
│   ├── public/
│   │   ├── nodes_data.json    # Demo 8-node topology
│   │   └── packets_data.json  # Demo packet flows
│   ├── jsons/                 # Additional demo datasets
│   └── package.json
│   └── README.md              # Frontend-specific notes (if any)
│
├── paper/
│   └── figures/               # Architecture diagrams from paper
│
├── requirements.txt           # (root if used)
└── .gitignore
```

---

## 🚀 Quick Start (Developer Setup)

### Prerequisites
- **Python** 3.10+
- **Node.js** 18+ and **npm** 9+
- **Git**

> If you later see CORS or connection issues, it’s usually a URL/port mismatch between the frontend and backend.

### 1) Backend (FastAPI)

```bash
# from repo root
cd backend

# create & activate a virtualenv
# Windows (PowerShell)
python -m venv .venv
. .venv/Scripts/Activate.ps1

# macOS/Linux
# python3 -m venv .venv
# source .venv/bin/activate

# install deps
pip install -r requirements.txt
```

Create a `.env` (optional, recommended). Open `backend/config.py` to see recognized variables (ports, log level, API keys). Example:

```bash
# backend/.env (example)
APP_HOST=0.0.0.0
APP_PORT=8000
LOG_LEVEL=INFO
# If you use any LLM/API keys, define them here too
# OPENAI_API_KEY=...
```

Run the REST API (option A):

```bash
# from repo root so module imports resolve
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

Run a separate WebSocket server (option B, only if your design splits them):

```bash
# check appWebsocket.py for the actual port/path used
python backend/appWebsocket.py
```

> If your WebSocket is integrated into the same FastAPI app, you only need the first command.

---

### 2) Frontend (React)

```bash
# in a new terminal, from repo root
cd frontend
npm install
```

Configure environment for API/WS URLs (either via `.env` or update `src/apiService.js`):

```bash
# frontend/.env (example)
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8001
```

Start the dev server:

```bash
npm start
```

Open **http://localhost:3000** in your browser.

---
## 📖 Usage

### Real-Time Monitoring (Local Testbed)

The system automatically monitors network performance. When anomalies are detected (high latency, packet loss), agents:

1. Capture network traffic using tshark
2. Analyze packets with LLM inference
3. Generate structured reports
4. Send alerts to the dashboard via WebSocket

### Offline Analysis (NS-3 Simulations)

Process PCAP files from NS-3 simulations:

```bash
cd backend
python analyze_nodes.py
```

This script:
- Reads PCAP files from `segregated/segregated_pcaps*`
- Analyzes each node's traffic with SecurityAnalysisAgent
- Posts reports to the central controller (`POST /gcreport`)
- Updates the dashboard with attacker/victim classifications

The `analyze_nodes.py` script handles:
- Rate limiting for Gemini API (5 RPM, 25 RPD)
- Automatic retry with exponential backoff
- Time-series metrics extraction
- JSON serialization for the controller

### Demo Mode (No Backend Required)

The frontend can run independently using demo JSON files:
- `frontend/public/nodes_data.json` - 8-node scenario
- `frontend/jsons/jsons-20-nodes/` - 20-node scenario

Just start the frontend without the backend to explore the UI.

---


## 🔌 API Reference

### Central Controller Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/gcreport` | POST | Submit node analysis report |
| `/gcstatuses` | GET | Get all node statuses |
| `/gccorrelation` | GET | Get attacker/victim correlation |
| `/gctimeline` | GET | Get recent event timeline |
| `/ws` | WebSocket | Real-time metrics and alerts |

**Example: Submit Report**
```python
import requests

report = {
    "node_ip": "192.168.1.4",
    "threat_type": "ddos_flood",
    "severity": "high",
    "summary": "High-volume TCP traffic detected"
}

response = requests.post("http://localhost:8000/gcreport", json=report)
print(response.json())
# {"message": "Report for 192.168.1.4 received", "role": "victim"}
```

**Example: Get Correlation**
```python
response = requests.get("http://localhost:8000/gccorrelation")
data = response.json()

print(f"Attackers: {data['attackers']}")
print(f"Victims: {data['victims']}")
```

---

## 🔧 Tools & Utilities

### PCAP Analysis (`backend/tools/`)

- `pcap_analyzer.py` - Parse and extract features from PCAP files
- `attack_detection.py` - Heuristic-based attack detection
- `data_collection.py` - Metrics aggregation

**Example**:
```bash
python backend/tools/pcap_analyzer.py path/to/capture.pcap
```

### Simulation Files

NS-3 scenario XMLs are included in `backend/`:
- `dos-simulation-animation.xml` - DoS attack scenario
- `syn-flood-animation.xml` - SYN flood scenario

---

## 🧪 Evaluation Results

NetMoniAI was evaluated in two environments:

### Local Micro-Testbed
- **Setup**: Ubuntu 22.04 with network degradation (600ms delay, 1Mbps bandwidth)
- **Tools**: Linux `tc` utility, macOS Network Link Conditioner
- **Result**: Detected anomalies within 5 seconds with accurate threat classification

### NS-3 Simulation
- **Setup**: 8-node virtual network with coordinated TCP flood attack
- **Attack**: Node 1 targeted Nodes 4 and 6 with TCP SYN flood
- **Result**: Successfully identified attackers and victims through real-time correlation

**Key Achievements**:
- ✅ Low-latency detection (< 5 seconds)
- ✅ Accurate role classification (attacker/victim/benign)
- ✅ Scalable distributed architecture
- ✅ Interpretable LLM-generated reports

---

## 🔧 Configuration & Customization

### Changing LLM Models

The framework supports multiple LLM backends, but changing models requires **code modifications**:

**Supported Models**:
- **Gemini Pro** (Google) - Default in evaluation
- **GPT-O3** (OpenAI) - Used in paper experiments
- **Local BERT** (Hugging Face) - For offline/resource-constrained environments

**To switch models**, edit `backend/nw_agents/SecurityAnalysisAgent.py`:

```python
# Example: Change from Gemini to GPT
# Locate the model initialization section and update:

# FROM (Gemini):
import google.generativeai as genai
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-pro')

# TO (GPT):
from openai import OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
# Update inference calls accordingly
```

> **Important**: Model selection is hardcoded in agent implementations and not configurable via environment variables.

### Adjusting Detection Thresholds

Modify thresholds in `backend/config.py` or via environment variables:

```python
# backend/config.py
LATENCY_THRESHOLD = float(os.getenv("LATENCY_THRESHOLD", 200))  # ms
PACKET_LOSS_THRESHOLD = float(os.getenv("PACKET_LOSS_THRESHOLD", 5))  # %
CAPTURE_DURATION = int(os.getenv("CAPTURE_DURATION", 25))  # seconds
```

### Rate Limiting Configuration

The `analyze_nodes.py` script implements rate limiting for Gemini API:

```python
REQUESTS_PER_MINUTE = 5
REQUESTS_PER_DAY = 25
MAX_RETRIES = 3
```

---

## 🗂 Logs & History

- `backend/agent_app.log` - Agent activity logs
- `backend/network_metrics.log` - Performance metrics
- `backend/metrics_metrics.log` - Metric collection logs
- `backend/history.json` - Event history snapshots
- `backend/history_backup.json` - Backup snapshots

These files help with debugging and reviewing prior events.

---

## 🛠 Troubleshooting

**LLM Model Not Working**
- Ensure correct API key is set in `backend/.env`
- Verify model configuration in `SecurityAnalysisAgent.py`
- Check API quota limits (Gemini: 5 RPM, 25 RPD)

**CORS Errors**
- Ensure `REACT_APP_API_URL` matches backend host/port
- CORS is already enabled in FastAPI middleware

**WebSocket Not Connecting**
- Verify `REACT_APP_WS_URL` matches backend WebSocket endpoint
- Check that WebSocket path is `/ws`

**Module Import Issues**
- Run servers from **repo root**: `uvicorn backend.app:app`
- Ensure virtual environment is activated

**Windows PowerShell venv Activation**
- Use `.\.venv\Scripts\Activate.ps1`
- If blocked, run: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

---

## 📦 Deployment (Optional - For Production Use)

> **Note**: This section is only needed if deploying NetMoniAI to a production server. For local development and research purposes, use the [Quick Start](#-quick-start) guide above.

### Frontend Production Build
```bash
cd frontend
npm run build

# The build folder can be served with any static file server:
# - nginx
# - Apache
# - serve (npm package): npx serve -s build
```

### Backend Production Server
```bash
# Install gunicorn
pip install gunicorn

# Run with multiple workers for better performance
gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.app:app --bind 0.0.0.0:8000

# Or use uvicorn directly (single worker)
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --workers 4
```

### Production Checklist
- [ ] Set production environment variables (remove debug flags)
- [ ] Use HTTPS (configure SSL certificates)
- [ ] Set up reverse proxy (nginx/Apache) for both frontend and backend
- [ ] Configure firewall rules
- [ ] Set up logging and monitoring
- [ ] Use process manager (systemd, supervisor, or PM2)

---
## 📚 Citation

If you use NetMoniAI in your research, please cite:

```bibtex
@article{zambare2025netmoniai,
  title={NetMoniAI: An Agentic AI Framework for Network Security \& Monitoring},
  author={Zambare, Pallavi and Thanikella, Venkata Nikhil and 
          Kottur, Nikhil Padmanabh and Akula, Sree Akhil and Liu, Ying},
  journal={arXiv preprint arXiv:2508.10052},
  year={2025}
}
```

---

## 📄 License

This project is dual-licensed under:
- **MIT License** - see LICENSE-MIT
- **Apache License 2.0** - see LICENSE-APACHE

**SPDX-License-Identifier**: MIT OR Apache-2.0

---

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 👥 Authors

- **Pallavi Zambare** - Texas Tech University - pzambare@ttu.edu
- **Venkata Nikhil Thanikella** - nikhilvenkata.t@gmail.com
- **Nikhil Padmanabh Kottur** - nkotturi@ttu.edu
- **Sree Akhil Akula** - sreakula@ttu.edu
- **Dr.Ying Liu** - y.liu@ttu.edu  

---
 
 
 
