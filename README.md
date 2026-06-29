# CERBERUS: Enterprise Defensive OSINT & Dark Web Leak Monitoring Dashboard

[![Role](https://img.shields.io/badge/Role-Blue_Team_/_Defensive_Security-blue?style=flat-square)](#)
[![Tech Stack](https://img.shields.io/badge/Tech_Stack-Python_|_Flask_|_SQLite_|_Vanilla_JS-brightgreen?style=flat-square)](#)
[![Category](https://img.shields.io/badge/Category-Threat_Intelligence_/_SecOps-red?style=flat-square)](#)

---

## 📌 Project Overview

**CERBERUS** is an enterprise-oriented, defensive security automation dashboard designed to monitor and analyze public leaks, paste sites, and threat feeds. Built with a focus on internal Security Operations Center (SOC) operations, CERBERUS maps the attack surface of target domains and detects exposed credentials, National ID numbers (NIK), and compromised database configurations in real-time.

By combining signature-based regex matching, a live threat intelligence pipeline, and a modern glassmorphic dashboard, this project demonstrates how threat intelligence teams automate OSINT ingestion, analyze data breaches, and orchestrate real-time incident alerting (SOAR).

---

## 🎓 Project Background

**CERBERUS** was built as a personal cybersecurity portfolio project to demonstrate practical engineering capabilities in **Defensive Security, Threat Intelligence, and Security Operations (SecOps) / Blue Teaming**. 

In a modern security ecosystem, early threat detection and proactive monitoring are vital. This project highlights key concepts in:
*   **Attack Surface Monitoring:** Querying public indicators and open data sources to identify threats targeting internal assets.
*   **SOAR (Security Orchestration, Automation, and Response):** Automating incident collection, classification, and alert dispatch to messaging environments (Discord/Telegram) to minimize response times.
*   **Secure Software Engineering:** Adhering to OWASP guidelines for input validation, sanitization, and XSS/SQLi mitigations in web API environments.

---

## 🎯 Key Features

*   **Real-World OSINT Integration:** Queries live public threat intelligence feeds from **URLhaus API (abuse.ch)** (for active malware distribution) and **OpenPhish** (for active phishing campaigns) in real-time. The engine scans these aggregated indicators to detect threats targeting internal networks.
*   **Asynchronous SOAR Scheduling:** Runs an autonomous background daemon thread that periodically pulls new threats, scans them, saves incidents, and dispatches external alerts every 5 minutes without blocking the main web application thread.
*   **Signature-Based Leak Detection:** Employs precise regular expressions to extract:
    *   Exposed emails and domain names (e.g. government `*.go.id` targets).
    *   Leaked Indonesian National ID numbers (16-digit NIK structure).
    *   Exposed database connection parameters (e.g. `DB_PASSWORD`, `db_pass`).
*   **Interactive Leak Simulator:** An inline sandbox interface allowing security analysts to paste raw text data (logs, database dumps, email/password pairs) and instantly test them against the signature engine.
*   **Server-Sent Events (SSE) Terminal:** Streams real-time scanning logs and engine status evaluations directly into an interactive dashboard terminal.
*   **Automated Webhook Alerts (SOAR):** Dispatches high-severity incident notifications to external platforms (Discord/Telegram) with payload truncation and secret token redaction in logs to prevent secondary information leakage.
*   **Interactive Alerts Repository:** SQLite-backed dashboard containing detailed logs with search, severity filtering, and a modal detail inspector to analyze exposed raw payloads.
*   **Automated Quality Assurance:** Includes a unit testing suite consisting of 19 test cases that validate security utilities, API routes, threat analysis logic, and database operations.

---

## 🛠️ Tech Stack

| Layer | Technology / Library | Skill Highlights Demonstrated |
| :--- | :--- | :--- |
| **Backend Core** | Python 3.9+ | Scripting, File I/O, Package Structure |
| **Security Scanning** | Python Regex (`re`) | Signature-based Analysis, Rule Construction |
| **Web API & SSE** | Flask, Flask-CORS | REST API Development, Event Streaming |
| **Asynchronous Engine** | Threading, Time | Concurrent Execution, Background Scheduling |
| **Threat Ingestion** | Requests | Live API Consumption, HTTP Webhook Dispatch |
| **Storage Engine** | SQLite 3 | Structured Database Management |
| **UI Dashboard** | HTML5, Vanilla CSS3 (Glassmorphic) | UI/UX Design, Data Accessibility |
| **Frontend Logic** | Vanilla Javascript (ES6) | DOM Manipulation, API Integration, XSS mitigation |
| **Unit Testing** | Unittest | Automated Quality Assurance, TDD Principles |
| **Data Viz** | Chart.js | Visualizing Incident Trends & Metrics |

---

## 📐 System Architecture

The diagram below illustrates the flow of threat data from external sources and simulators to the dashboard and SOAR webhooks:

```mermaid
graph TD
    A[OSINT Threat Feeds (URLhaus API)] -->|Live API Ingestion| B(Python Tracker Engine)
    A2[Mock Dark Web Forum Logs] -->|Crawler Simulation| B
    A3[Exposed Paste Sites] -->|Crawler Simulation| B
    
    B -->|Signature Matching / Regex| C{Risk Engine}
    C -->|Alert Triggered| D[(SQLite Database)]
    
    E[User Payload Input] -->|Interactive Simulator API| C
    
    D -->|REST JSON Payload| F(Flask API Server)
    F -->|Serve Static Dashboard| G[Glassmorphic HTML/CSS/JS UI]
    
    F -->|Server-Sent Events| H[Dashboard Scanning Terminal]
    D -->|Asynchronous Dispatch| I[SOAR Webhooks: Discord / Telegram]
```

---

## 📂 Project Structure

```text
cybersec_portofolio/
│
├── backend/
│   ├── scrapers/
│   │   └── leak_simulator.py       # Generates random mock datasets
│   ├── app.py                      # Flask routes and business logic
│   ├── database.py                 # SQLite initialization and SQL queries
│   ├── tracker.py                  # Regex signature matching and scan controller
│   ├── security_utils.py           # SQLi, XSS, and command injection sanitizers
│   ├── webhook.py                  # Discord & Telegram webhook SOAR handlers
│   ├── mock_data.py                # Simulated offline dark web and paste data
│   └── test_app.py                 # 19 automated python test cases
│
├── frontend/
│   ├── index.html                  # Glassmorphic HTML5 UI template
│   ├── app.js                      # UI routing, Chart.js, and API bindings
│   └── style.css                   # Custom global CSS stylesheet
│
├── .env.example                    # Environment variable configuration template
├── .gitignore                      # Git ignore list for databases, config, and cache
├── app.py                          # Application entry point supporting .env
├── requirements.txt                # Python package dependency manifest
└── qa_testing_guide.md             # Functional and security testing guidelines
```

---

## 🚀 Installation & Local Running

### 1. Prerequisites
Make sure Python 3.9+ is installed on your system.

### 2. Clone & Install Dependencies
Navigate to the project root directory and run:
```bash
# Install required Python dependencies
pip install -r requirements.txt
```

### 3. Environment Setup
Copy the configuration template to create your local `.env` file:
```bash
# Windows PowerShell
copy .env.example .env

# Linux / macOS
cp .env.example .env
```
*(Open `.env` to customize your host, port, or debugging preferences if needed.)*

### 4. Start the Application
Launch the server using the entry point script:
```bash
python app.py
```
Upon startup, the database `backend/database.db` will initialize, the background scheduling thread will launch, and the server will spin up at:
👉 **[http://localhost:5000](http://localhost:5000)**

### 5. Running Automated Unit Tests
To run the automated security and functionality tests, run:
```bash
python -m backend.test_app
```

---

## 🛡️ Demonstration Walkthrough (For Interviewers & Tech Leads)

To effectively showcase the defensive automation capabilities of CERBERUS:

1.  **Trigger a Live OSINT Scan:** Click **"Run Threat Scan"** on the dashboard control console. The application will switch to the crawler terminal and stream live logs. It connects to the real URLhaus API, pulls the latest 25 threat indicators, scans them for targeting patterns, and prints the results.
2.  **Inspect Database Alert Details:** Go to the **Detailed Alert Incidents** table. Double-click any incident row (or click **"View"**) to inspect the raw leaked credentials, exposed database settings, or malware feed parameters safely rendered in a modal dialog.
3.  **Simulate an Incident (Interactive Demo):**
    *   Navigate to the **Threat Simulator** tab.
    *   Paste the following raw credential snippet:
        ```text
        CRITICAL VULNERABILITY: Internal database exposed in production.
        IP Address: 103.22.45.12
        User Contact: admin_staff@kemhan.go.id
        db_password = SecureNationalPassword2026!
        ```
    *   Click **"Analyze and Scan"**.
    *   The engine will instantly trigger a `HIGH` severity alert, matching the government domain and database credentials.
4.  **Autonomic Webhook Alerting (SOAR):** Configure a Discord or Telegram webhook in the console. When the background thread identifies a live threat or when you simulate a custom threat, watch the real-time notification arrive on your chat channel.
