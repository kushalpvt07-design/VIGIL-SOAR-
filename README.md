# 🛡️ SentinelGraph: Autonomous Multi-Agent SOAR

## 📌 Overview
Modern Security Operations Centers (SOC) are crippled by alert fatigue. Security analysts cannot manually investigate thousands of firewall and Active Directory anomalies daily. 

**SentinelGraph** is an autonomous, event-driven SOAR (Security Orchestration, Automation, and Response) pipeline. Instead of relying on a single, linear LLM prompt, it utilizes a **Stateful LangGraph Architecture** to partition cognitive load across three specialized AI agents. These agents autonomously triage raw network logs, execute SQL-based forensic investigations, and trigger defensive mitigations in real-time.

## 🏗️ Enterprise Architecture

The system operates on a cyclic state machine passing an immutable `ThreatDossier` (enforced via Pydantic) between nodes:

1. **The Sentinel Agent (Triage):** Ingests raw SIEM network logs, identifies structural anomalies, and elevates high-risk events (e.g., Impossible Travel, Brute Force).
2. **The Forensics Agent (Tool Calling):** Operates with strict API tool execution capabilities. It queries internal Active Directory databases and historical firewall states to verify if an anomaly is a genuine breach or a false positive.
3. **The Responder Agent (Mitigation):** The execution layer. Based on the verified forensic evidence, it autonomously executes defensive database updates (e.g., revoking compromised access tokens, blacklisting malicious IPs).

## 🚀 Tech Stack
* **Orchestration:** [LangGraph](https://python.langchain.com/docs/langgraph) (Stateful multi-agent routing)
* **Inference Engine:** [Groq API](https://groq.com/) running **Llama 3.1** (High-speed, sub-second deterministic inference)
* **Data Validation:** Pydantic (Strict schema enforcement for the AI graph state)
* **Web Server:** FastAPI & WebSockets (Real-time asynchronous dashboard streaming)
* **Mock Infrastructure:** Python (Simulating Active Directory and Edge Firewalls)

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/SentinelGraph.git
   cd SentinelGraph
   ```

2. **Create a virtual environment & install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   pip install langgraph langchain-groq pydantic python-dotenv fastapi uvicorn websockets
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory and add your high-speed Groq API key:
   ```env
   GROQ_API_KEY=your_api_key_here
   ```

4. **Run the Pipeline:**
   ```bash
   python main.py
   ```
   Open your browser and navigate to `http://localhost:8000` to watch the LangGraph orchestration execute live on the WebSockets-driven dashboard.

## 🧠 Why This Architecture?
Standard LLM wrappers fail in enterprise security because they lack tool-calling reliability and state persistence. By utilizing LangGraph, this system ensures a cryptographically auditable trail of why the AI took a specific mitigation action—a strict compliance requirement in modern cybersecurity operations.
