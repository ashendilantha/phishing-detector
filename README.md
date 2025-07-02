# Phishing Detection Toolkit

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Flask](https://img.shields.io/badge/Backend-Flask-yellowgreen)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--learn-orange)

A Python-based full-stack toolkit for detecting phishing websites using heuristic analysis, machine learning, and content scanning. The project is centered around a Python backend (Flask REST API and CLI utility), with a lightweight web frontend for demonstration purposes.

---

## :snake: Why Python?

This project is built primarily in Python, leveraging its strengths in machine learning, web APIs, and rapid prototyping. The backend handles all the core logic for phishing detection, heuristics, and ML inference.

---

## Features

- **Backend (Python/Flask):**  
  REST API for phishing detection, content scanning, and multilingual educational content.
- **Machine Learning:**  
  Integrates a Python-based ML model for suspicious URL detection.
- **Heuristic Analysis:**  
  Python modules for advanced rule-based checks.
- **CLI Utility (Python):**  
  Command-line tool for quick phishing checks.
- **Frontend (HTML/Bootstrap):**  
  Minimal web interface for demo/testing.

---

## Project Structure

```
backend/
  app.py                # Flask backend API (Python)
  models/
    url_analyzer.py     # Heuristic URL analysis (Python)
    form_detector.py    # HTML form/content analysis (Python)
    ml_model.py         # ML model for phishing detection (Python)
cli/
  phishing_cli.py       # Command-line interface (Python)
frontend/
  templates/
    index.html          # Web frontend (Bootstrap, JS)
tests/
  test_hello.py         # Example unit tests (Python)
requirements.txt        # Python dependencies
```

- :snake: **All core logic, analysis, and utilities are in Python.**
- :globe_with_meridians: Frontend is provided for demonstration and user interaction.

---

## Getting Started

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
   source venv/bin/activate
   ```

3. **Install Python dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

---

## Running the Python Backend

Start the Flask API server:

```sh
cd backend
python app.py
```

- The API will be available at `http://localhost:5000/`
- The frontend (for testing) is accessible at `/`

---

## Using the CLI (Python)

Analyze a URL directly from your terminal:

```sh
python cli/phishing_cli.py --url https://example.com
```

---

## API Endpoints (Backend - Python)

- `POST /api/analyze-url`  
  Analyze a URL for phishing (`{ "url": "<url>" }`).
- `POST /api/analyze-page`  
  Analyze webpage content for suspicious forms (`{ "url": "<url>" }`).
- `GET /api/educational-content/<lang>`  
  Get safety tips in `en`, `si`, or `ta`.

---

## Testing (Python)

Run all unit tests:

```sh
pytest
```

---

## Customization

- **ML Model:**  
  Update/retrain in `backend/models/ml_model.py`.
- **Heuristics:**  
  Adjust in `backend/models/url_analyzer.py` and `form_detector.py`.
- **Frontend:**  
  Edit `frontend/templates/index.html` (optional).

---

## License

MIT License

---

**Developed by:**  
- Ashen Dilantha
