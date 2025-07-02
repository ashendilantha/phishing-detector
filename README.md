# Phishing Detection Toolkit

A full-stack toolkit for detecting phishing websites using heuristic analysis, machine learning, and content scanning. Includes a web frontend, REST API backend, and CLI utility.

## Features

- **URL Analysis:** Detect suspicious URLs using heuristics and machine learning.
- **Content Scan:** Analyze webpage forms for phishing indicators.
- **Educational Content:** Multilingual safety tips for users.
- **REST API:** Endpoints for integration and automation.
- **CLI Tool:** Command-line interface for quick URL checks.

## Project Structure

```
backend/
  app.py                # Flask backend API
  models/
    url_analyzer.py     # Heuristic URL analysis
    form_detector.py    # HTML form/content analysis
    ml_model.py         # ML model for phishing detection
cli/
  phishing_cli.py       # Command-line interface
frontend/
  templates/
    index.html          # Web frontend (Bootstrap, JS)
tests/
  test_hello.py         # Example unit tests
requirements.txt        # Python dependencies
```

## Getting Started

### Prerequisites

- Python 3.9+
- pip

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/phishing-detector.git
   cd phishing-detector
   ```

2. **Create and activate a virtual environment (optional but recommended):**
   ```sh
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

---

### Running the Backend

Start the Flask API server:

```sh
cd backend
python app.py
```

- The API will be available at `http://localhost:5000/`
- The frontend is served at `/` (index page).

### Using the Web Frontend

Open your browser and go to [http://localhost:5000/](http://localhost:5000/).

- Enter a URL to analyze for phishing.
- Analyze page content for suspicious forms.
- View safety tips in English, Sinhala, or Tamil.

### Using the CLI

Analyze a URL from the command line:

```sh
python cli/phishing_cli.py --url https://example.com
```

### API Endpoints

- `POST /api/analyze-url`  
  Analyze a URL for phishing (JSON: `{ "url": "<url>" }`).

- `POST /api/analyze-page`  
  Analyze webpage content for suspicious forms (JSON: `{ "url": "<url>" }`).

- `GET /api/educational-content/<lang>`  
  Get safety tips in `en`, `si`, or `ta`.

### Testing

Run unit tests with pytest:

```sh
pytest
```

## Customization

- **ML Model:**  
  Update or retrain the model in `backend/models/ml_model.py` as needed.
- **Heuristics:**  
  Adjust rules in `backend/models/url_analyzer.py` and `form_detector.py`.
- **Frontend:**  
  Edit `frontend/templates/index.html` for UI changes.

## License

MIT License

---

**Developed by:**  
- Ashen Dilantha
