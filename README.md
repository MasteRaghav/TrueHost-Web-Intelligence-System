
# 🌐 TrueHost Web Intelligence System  
### Uncover the Real Hosting Origin Behind Suspicious Websites

<p align="center">
    <img src="https://scribeage.com/wp-content/uploads/2024/12/TrueHost.png" alt="TrueHost Banner"/>
</p>

<p align="center">
  <strong>OSINT-Powered • DNS Intelligence • CT Log Analysis • Subdomain Discovery • Origin Server Detection</strong>
</p>

---

# **TrueHost Web Intelligence System**

TrueHost Web Intelligence System is an OSINT-based cybersecurity tool designed to uncover the **real hosting origin** of suspicious websites, even when masked behind CDNs like Cloudflare, Sucuri, Akamai, or Imperva.  
The system performs **DNS lookup, WHOIS extraction, Certificate Transparency (CT) analysis, subdomain enumeration, CDN detection, passive DNS correlation**, and identifies **origin server candidates** with confidence scores.

---

## 🚀 Features

- ✔ Domain validation  
- ✔ DNS lookup (A, NS, MX, TXT)  
- ✔ WHOIS details extraction  
- ✔ Certificate Transparency (CT log) analysis  
- ✔ Subdomain enumeration through CT logs  
- ✔ CDN & Proxy detection (Cloudflare, Sucuri, Akamai, etc.)  
- ✔ Passive DNS correlation (mock/historical dataset)  
- ✔ Origin server candidate identification  
- ✔ Confidence scoring  
- ✔ Clean JSON output & export  
- ✔ Simple and user-friendly web interface (HTML/CSS/JS)  
- ✔ Python Flask backend for investigation API  

---

## 🛠 Technologies Used

### **Frontend**
- HTML, CSS, JavaScript  
- Simple responsive UI  

### **Backend**
- Python 3  
- Flask Framework  
- DNSPython  
- python-whois  
- Requests  

### **OSINT Sources**
- DNS Resolvers  
- WHOIS Servers  
- CT Logs (crt.sh)  
- Passive/Mock Historical DNS  

---

## 📦 Project Structure

```

TrueHost/
│── backend/
│   ├── app.py
│   ├── modules/
│   │   ├── dns_lookup.py
│   │   ├── whois_lookup.py
│   │   ├── ct_logs.py
│   │   ├── subdomains.py
│   │   ├── cdn_detector.py
│   │   ├── origin_detector.py
│   └── utils/
│── frontend/
│   ├── index.html
│   ├── style.css
│   ├── script.js
│── README.md
│── requirements.txt

````

---

# ⚙️ Installation & Setup

## 1. Install Python  
Ensure Python 3.8+ is installed.

```sh
python --version
````

---

## 2. Clone this Repository

```sh
git clone https://github.com/your-repo/TrueHost.git
cd TrueHost/backend
```

---

## 3. Create Virtual Environment (Optional)

```sh
python -m venv venv
source venv/bin/activate     # Linux/Mac
venv\Scripts\activate        # Windows
```

---

## 4. Install Required Dependencies

```sh
pip install -r requirements.txt
```

Packages include:

```
Flask
dnspython
python-whois
requests
```

---

# ▶️ How to Run the System

## Step 1: Start Backend (Flask API)

```sh
python app.py
```

You should see:

```
* Running on http://127.0.0.1:5000
```

---

## Step 2: Start Frontend

### Option A – Open directly

Open:

```
frontend/index.html
```

### Option B – Run a local server

```sh
cd frontend
python -m http.server 5500
```

Open in browser:

```
http://127.0.0.1:5500
```

---

# 🧪 How to Use the Tool

1. Open the **frontend UI**

2. Enter a domain (ex: `example.com`)

3. Click **Investigate**

4. Backend performs:

   * DNS Lookup
   * WHOIS Lookup
   * CT Log Fetch
   * Subdomain Enumeration
   * CDN Detection
   * Origin Identification

5. Results appear in respective sections

6. Click **Export JSON** to download the report

---

# 📊 Sample API Request

### Endpoint:

```
POST /api/investigate
```

### Request Body:

```json
{
  "domain": "example.com"
}
```

---

# 📈 Sample Output

```json
{
  "domain": "example.com",
  "dns": {...},
  "whois": {...},
  "ct_logs": [...],
  "subdomains": [...],
  "origin_candidates": [
    {
      "ip": "93.184.216.34",
      "confidence": 85
    }
  ],
  "cdn_detected": "Cloudflare"
}
```

---

---

# 💡 Future Enhancements

* Integration with SecurityTrails, VirusTotal, Shodan
* Machine-learning based origin confidence scoring
* Threat intelligence dashboard
* Batch investigation for multiple domains

---

# 🤝 Contributors

* **Developer:** Raghav Khatri
* **Project Title:** TrueHost Web Intelligence System

---


