from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from models.url_analyzer import URLAnalyzer
from models.form_detector import FormDetector
from models.ml_model import PhishingMLModel
import os
import re
import requests

app = Flask(__name__, template_folder='../frontend/templates')
CORS(app)

# Initialize components
url_analyzer = URLAnalyzer()
form_detector = FormDetector()
ml_model = PhishingMLModel()

# Load ML model if available
ml_model.load_model()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing indicators"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Heuristic analysis
        heuristic_result = url_analyzer.analyze_url(url)
        
        # ML prediction if model is available
        ml_prediction = None
        ml_confidence = None
        
        if ml_model.is_trained:
            prediction, confidence = ml_model.predict(heuristic_result['features'])
            if prediction is not None:
                ml_prediction = bool(prediction)
                ml_confidence = float(confidence)
        
        # Combine results
        result = {
            'url': url,
            'heuristic_analysis': heuristic_result,
            'ml_prediction': {
                'is_phishing': ml_prediction,
                'confidence': ml_confidence
            } if ml_prediction is not None else None,
            'recommendations': generate_recommendations(heuristic_result)
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-page', methods=['POST'])
def analyze_page():
    """Analyze webpage for suspicious forms"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Basic URL validation
        if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        result = form_detector.analyze_page(url)
        
        # Ensure result is a dictionary and handle potential errors
        if not isinstance(result, dict) or 'error' in result:
            return jsonify(result if 'error' in result else {'error': 'Analysis failed to produce valid results'}), 500
        
        return jsonify(result)
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Failed to fetch webpage: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/educational-content/<language>')
def get_educational_content(language):
    """Get educational content in specified language"""
    content = {
        'en': {
            'title': 'Phishing Awareness Guide',
            'tips': [
                'Always check the URL carefully before entering personal information',
                'Look for HTTPS and valid SSL certificates',
                'Be suspicious of urgent or threatening messages',
                'Verify sender identity through official channels',
                'Never click suspicious links in emails or SMS'
            ]
        },
        'si': {
            'title': 'ෆිෂිං දැනුවත්කිරීමේ මාර්ගෝපදේශය',
            'tips': [
                'පුද්ගලික තොරතුරු ඇතුළත් කිරීමට පෙර URL එක හොඳින් පරීක්ෂා කරන්න',
                'HTTPS සහ වලංගු SSL සහතික සඳහා බලන්න',
                'හදිසි හෝ තර්ජනාත්මක පණිවිඩ ගැන සැකයෙන් සිටින්න',
                'නිල නාලිකා හරහා යවන්නාගේ අනන්‍යතාවය තහවුරු කරන්න',
                'ඊමේල් හෝ SMS වල සැක සහිත සබැඳි මත ක්ලික් නොකරන්න'
            ]
        },
        'ta': {
            'title': 'ஃபிஷிங் விழிப்புணர்வு வழிகாட்டி',
            'tips': [
                'தனிப்பட்ட தகவலை உள்ளிடுவதற்கு முன் URL ஐ கவனமாக சரிபார்க்கவும்',
                'HTTPS மற்றும் செல்லுபடியாகும் SSL சான்றிதழ்களைத் தேடுங்கள்',
                'அவசர அல்லது அச்சுறுத்தும் செய்திகளில் சந்தேகம் கொள்ளுங்கள்',
                'அதிகாரப்பூர்வ சேனல்கள் மூலம் அனுப்புநரின் அடையாளத்தை சரிபார்க்கவும்',
                'மின்னஞ்சல் அல்லது SMS இல் சந்தேகத்திற்குரிய இணைப்புகளைக் கிளிக் செய்ய வேண்டாம்'
            ]
        }
    }
    
    return jsonify(content.get(language, content['en']))

def generate_recommendations(analysis):
    """Generate safety recommendations based on analysis"""
    recommendations = []
    
    if analysis['risk_level'] == 'HIGH':
        recommendations.extend([
            'DO NOT enter any personal information on this website',
            'Close this page immediately',
            'Report this URL to authorities if received via email/SMS'
        ])
        recommendations.append('Consider blocking this URL or domain if it was sent to you.')
    elif analysis['risk_level'] == 'MEDIUM':
        recommendations.extend([
            'Exercise extreme caution',
            'Verify the website through official channels',
            'Do not enter sensitive information'
        ])
    else:
        recommendations.extend([
            'Website appears relatively safe',
            'Still verify legitimacy for sensitive transactions',
            'Always check for HTTPS when entering personal data'
        ])
    
    return recommendations

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)