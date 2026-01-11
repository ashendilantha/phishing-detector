# Phishing Detection Toolkit

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Flask](https://img.shields.io/badge/Backend-Flask-yellowgreen)
![Heuristic Analysis](https://img.shields.io/badge/Detection-Heuristic-orange)

A Python-based full-stack toolkit for detecting phishing websites using advanced heuristic analysis and content scanning. The project features a Python backend (Flask REST API and CLI utility) with a modern web interface for easy interaction.

---

## 🛡️ Why This Tool?

This project is built entirely in Python, leveraging its strengths in web APIs, security analysis, and rapid prototyping. The backend handles all core logic for phishing detection using rule-based heuristics and content analysis.

---

## ✨ Features

- **Backend (Python/Flask):**  
  REST API for phishing detection, content scanning, and multilingual educational content.
- **Advanced Heuristic Analysis:**  
  - URL pattern analysis with 150+ suspicious keywords
  - Domain age verification via WHOIS
  - TLD (Top-Level Domain) risk assessment (100+ suspicious TLDs)
  - IP address detection
  - Homograph attack detection
  - URL shortener identification
- **Form Content Scanning:**  
  Analyzes webpage HTML for suspicious forms and phishing indicators.
- **CLI Utility (Python):**  
  Command-line tool for quick phishing checks.
- **Modern Web Interface:**  
  Bootstrap 5-based dashboard with dark mode, multilingual support (English, සිංහල, தமிழ்), and animated results.
- **Educational Content:**  
  Built-in security awareness tips in multiple languages.

---

## 📁 Project Structure

```
backend/
  app.py                # Flask backend API (Python)
  models/
    url_analyzer.py     # Heuristic URL analysis (Python)
    form_detector.py    # HTML form/content analysis (Python)
cli/
  phishing_cli.py       # Command-line interface (Python)
frontend/
  templates/
    index.html          # Web frontend (Bootstrap 5, responsive)
tests/
  test_hello.py         # Unit tests (Python)
requirements.txt        # Python dependencies
```

- 🐍 **All core logic, analysis, and utilities are in Python.**
- 🌐 Frontend provides an intuitive interface for user interaction.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/ashendilantha/phishing-detector.git
   cd phishing-detector
   ```

2. **(Optional) Create and activate a virtual environment:**
   ```sh
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Python dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

---

## ▶️ Running the Application

### Start the Python Backend

```sh
python backend/app.py
```

- The API will be available at `http://localhost:5000/`
- Web interface accessible at `http://localhost:5000/`
- Server runs in debug mode with auto-reload enabled

---

## 💻 Using the CLI (Python)

Analyze a URL directly from your terminal:

```sh
python cli/phishing_cli.py --url https://example.com
```

**Output includes:**
- Heuristic analysis results
- Risk level and score
- Detected features
- Security warnings

---

## 🔌 API Endpoints (Backend - Python)

### Analyze URL
```http
POST /api/analyze-url
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Returns:**
- Risk level (SAFE, LOW, MEDIUM, HIGH)
- Risk score (0-100)
- Feature analysis
- Warnings
- Recommendations

### Analyze Page Content
```http
POST /api/analyze-page
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Returns:**
- Forms found
- Suspicious form details
- Risk indicators
- CSRF token analysis

### Get Educational Content
```http
GET /api/educational-content/{language}
```

Supported languages: `en` (English), `si` (Sinhala), `ta` (Tamil)

---

## 🧪 Testing (Python)

Run unit tests:

```sh
pytest tests/
```

Or test manually:
```sh
python tests/test_hello.py
```

---

## 🎨 Web Interface Features

- **Dark/Light Mode:** Toggle theme with persistent storage
- **Multilingual Support:** English, සිංහල (Sinhala), தமிழ் (Tamil)
- **Real-time Analysis:** Instant feedback with loading animations
- **Risk Visualization:** Color-coded risk meters and badges
- **Responsive Design:** Mobile-friendly Bootstrap 5 layout
- **Toast Notifications:** Non-intrusive alerts
- **Educational Section:** Security tips in selected language

---

## 🔧 Customization

### Heuristics Configuration

**URL Analysis (`backend/models/url_analyzer.py`):**
- Add/remove suspicious keywords
- Adjust suspicious TLD list
- Modify risk scoring weights

**Form Detection (`backend/models/form_detector.py`):**
- Update suspicious form indicators
- Customize risk thresholds
- Add legitimate domain whitelist

### Frontend Customization

**Styling (`frontend/templates/index.html`):**
- Modify CSS variables for colors
- Adjust dark mode theme
- Customize animations

---

## 📊 Detection Methodology

### URL Analysis
1. **Length Check:** Longer URLs often indicate obfuscation
2. **IP Detection:** Direct IP usage is suspicious
3. **Keyword Matching:** 150+ phishing-related keywords
4. **TLD Analysis:** 100+ high-risk top-level domains
5. **Domain Age:** New domains (<30 days) increase risk
6. **HTTPS Presence:** Missing SSL/TLS is a red flag
7. **Special Characters:** Excessive use indicates manipulation
8. **Homograph Detection:** Identifies Unicode/Cyrillic attacks

### Content Analysis
1. **Form Inspection:** Password fields, credit card inputs
2. **Action Verification:** External form submissions
3. **CSRF Protection:** Missing security tokens
4. **Method Check:** Insecure GET requests for sensitive data
5. **Page Indicators:** Urgency language, fake security claims

---

## 🌍 Language Support

- **English:** Full interface and tips
- **සිංහල (Sinhala):** Complete translation
- **தமிழ் (Tamil):** Full localization

---

## 📦 Dependencies

```
flask==2.3.3
requests==2.31.0
beautifulsoup4==4.12.2
tldextract==3.4.4
whois==0.9.27
flask-cors==4.0.0
```

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

## 📝 License

MIT License

---

## 👨‍💻 Developed by

**Ashen Dilantha**

- GitHub: [@ashendilantha](https://github.com/ashendilantha)
- Repository: [phishing-detector](https://github.com/ashendilantha/phishing-detector)

---

## 🔮 Future Enhancements

- Machine learning integration with pre-trained models
- Browser extension development
- Real-time threat intelligence feeds
- Database of known phishing URLs
- API rate limiting and authentication
- Docker containerization
