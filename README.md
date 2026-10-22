# SecureGuard
### AI-Based Healthcare IoT Cybersecurity System

SecureGuard is a healthcare IoT cybersecurity project designed to protect communication between simulated medical devices and a central monitoring server.

The system combines device authentication, encrypted communication, message integrity verification, replay attack prevention, intrusion detection, and a real-time monitoring dashboard.

## 1. Project Objectives

- Secure communication between healthcare IoT devices and the server.
- Prevent unauthorized devices from sending medical readings.
- Detect message tampering and replay attacks.
- Protect sensitive medical data using encryption.
- Identify suspicious network activity.
- Provide a dashboard for monitoring healthcare devices and security alerts.

## 2. Technologies Used

| Component | Technology |
|---|---|
| Programming language | Python |
| Backend API | FastAPI |
| Dashboard | Streamlit |
| Machine Learning | Scikit-learn |
| ML Algorithm | Random Forest / Extra Trees |
| Encryption | AES-256-GCM |
| Message authentication | HMAC-SHA256 |
| Network packet monitoring | Scapy |
| Database | SQLite |
| Dataset | CICIoMT2024 |
| Development environment | VS Code |

## 3. Healthcare IoT Devices

SecureGuard currently simulates three healthcare devices:

| Device ID | Device Type |
|---|---|
| HR001 | Heart Rate Monitor |
| TEMP001 | Temperature Sensor |
| SPO2001 | Blood Oxygen (SpO2) Monitor |

The simulator generates healthcare readings at approximately five-second intervals.

## 4. Security Features

### Device Authentication
Only registered devices are authorized to communicate with the receiver. Unknown device IDs are rejected.

### AES-256-GCM Encryption
Healthcare readings are encrypted to protect confidentiality during communication.

### HMAC-SHA256
Cryptographic signatures are used to detect unauthorized modifications to transmitted messages.

### Replay Attack Protection
Message nonces are checked to identify and reject repeated transmissions.

### Intrusion Detection System
A machine-learning IDS has been trained using CICIoMT2024 network traffic data, including benign traffic and ARP spoofing attacks.

The project also includes a separate rule-based live network monitoring component for suspicious ARP activity and SYN flooding.

**Note:** The trained ML model is not currently integrated into the live packet detection pipeline. Live traffic detection uses rule-based analysis.

## 5. Project Structure

```text
SecureGuard/
├── backend/            # API, security, authentication, monitoring
├── dashboard/          # Streamlit dashboard
├── simulator/          # Simulated healthcare IoT devices
├── ml_model/           # ML training, prediction, saved models
├── data/
│   ├── train/          # Original training datasets
│   ├── test/           # Original testing datasets
│   └── processed/      # Preprocessed datasets
├── tests/              # Security and integration tests
├── main.py             # Application entry point
├── requirements.txt    # Python dependencies
├── .gitignore
└── README.md
```

## 6. System Requirements

- Windows 10 or Windows 11
- Python 3.12 or a compatible version
- VS Code or another Python development environment
- Internet access for installing dependencies
- Npcap for supported Windows packet capture functionality
- Administrator privileges may be required for live network capture

## 7. Installation

### Step 1: Clone the Repository

```bash
git clone <REPOSITORY_URL>
cd <REPOSITORY_FOLDER>
```

Replace the placeholders with the actual GitHub repository URL and folder name.

### Step 2: Create a Virtual Environment

```powershell
python -m venv .venv
```

### Step 3: Activate the Virtual Environment

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 4: Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### Step 5: Run SecureGuard

```powershell
python main.py
```

The application is designed to launch the backend, dashboard, device simulator, and network monitoring components.

The default local addresses used during development are:

- Backend: http://127.0.0.1:8000
- API documentation: http://127.0.0.1:8000/docs
- Dashboard: http://127.0.0.1:8501

**Important:** Installation on a new laptop has not yet been independently validated. Packet capture configuration, permissions, and environment-specific settings may need adjustment.

## 8. Machine Learning Dataset

The project uses the CICIoMT2024 dataset for training and evaluating an intrusion detection model.

Dataset files:

- `data/train/Benign_train.pcap.csv`
- `data/train/ARP_Spoofing_train.pcap.csv`
- `data/test/Benign_test.pcap.csv`
- `data/test/ARP_Spoofing_test.pcap.csv`

Processed datasets:

- `data/processed/train_processed.csv`
- `data/processed/test_processed.csv`

Trained models:

- `ml_model/ids_model.joblib`
- `ml_model/ids_model_tuned.joblib`
- `ml_model/ids_model_advanced.joblib`

Dataset distribution must comply with the original dataset's license and usage conditions.

## 9. Machine Learning Performance

The advanced IDS model achieved the following evaluation results during development:

| Metric | Result |
|---|---:|
| Accuracy | 93.07% |
| Precision | 38.47% |
| Recall | 93.98% |
| F1 Score | 54.60% |

These results describe the evaluated dataset and should not be interpreted as verified performance on live network traffic.

## 10. API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | API information |
| `/health` | GET | Backend health |
| `/device-data` | POST | Submit secure device messages |
| `/readings` | GET | Retrieve device readings |
| `/alerts` | GET | Retrieve security alerts |
| `/live-traffic` | GET | Retrieve live traffic information |
| `/blocked-attacks` | GET | Retrieve blocked attack records |

## 11. Dashboard

The Streamlit dashboard is designed to display healthcare device readings, monitoring information, security alerts, and live network activity.

## 12. Important Limitations

- Healthcare devices are simulated, not physical medical devices.
- The ML intrusion detection model has been evaluated offline.
- Live packet monitoring uses rule-based detection.
- Network monitoring depends on the host operating system, network adapter, and packet capture permissions.
- In-memory security state may be reset when the application restarts.
- The project is a research and educational prototype, not a certified medical or production security system.

## 13. Future Enhancements

- Integrate ML-based inference into live network monitoring.
- Improve model precision and reduce false-positive alerts.
- Support physical healthcare IoT devices.
- Add persistent device key management.
- Expand attack detection to additional threat categories.
- Improve deployment automation and cross-device compatibility.

---

**SecureGuard — AI-Based Healthcare IoT Cybersecurity System**
