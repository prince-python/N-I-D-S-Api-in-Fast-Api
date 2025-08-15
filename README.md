# Network Intrusion Detection System (NIDS) - Backend

This is the backend for a Network Intrusion Detection System built using **FastAPI** and **SQLite**.  
It captures network packets, stores them in a database, and detects suspicious activity.

---

## 📂 Project Structure

```
backend/
│
├── app/
│   ├── __pycache__/
│   ├── capture.py          # Starts packet capture
│   ├── config.py           # Configuration variables
│   ├── database.py         # SQLite connection setup
│   ├── detection.py        # Intrusion detection logic
│   ├── main.py             # FastAPI entry point
│   ├── models.py           # SQLAlchemy models
│   ├── packet_sniffer.py   # Low-level packet sniffer
│   ├── routes.py           # API routes
│   ├── websocket.py        # WebSocket for live packet data
│
├── nids.db                 # SQLite database file
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

---

## ⚙️ Requirements

- Python **3.9+**
- **pip** package manager

---

## 📥 Installation

1. **Clone the repository**
```bash
git clone https://github.com/your-username/nids-backend.git
cd nids-backend
```

2. **Create a virtual environment** (Recommended)
```bash
python -m venv venv
```

3. **Activate the virtual environment**
- **Windows (PowerShell)**
```bash
venv\Scripts\Activate
```
- **Linux/Mac**
```bash
source venv/bin/activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Backend

Run the backend with:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🛠 API Endpoints

- **`GET /`** – API status
- **`GET /packets`** – Retrieve all captured packets
- **`GET /detections`** – Retrieve detected suspicious packets
- **`WS /ws/packets`** – WebSocket for real-time packet data

---

## 📂 Database

The backend uses **SQLite** (`nids.db`).  
There are two tables:
- **packets** – Stores all captured packets
- **detections** – Stores suspicious packet details

You can view the database using:
```bash
sqlite3 nids.db
```

---

## 🖥 Testing

1. Start the backend
2. Use tools like **Postman** or a browser to test the endpoints
3. For live packet detection, open WebSocket connection at `/ws/packets`

---

## 📜 License

This project is open-source and available under the MIT License.
