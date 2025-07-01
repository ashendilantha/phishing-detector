import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import argparse
from backend.models.url_analyzer import URLAnalyzer
from backend.models.ml_model import PhishingMLModel

def main():
    parser = argparse.ArgumentParser(description="Phishing Detector CLI")
    parser.add_argument('--url', type=str, help='URL to analyze')
    args = parser.parse_args()

    if args.url:
        url_analyzer = URLAnalyzer()
        ml_model = PhishingMLModel()
        ml_model.load_model()
        result = url_analyzer.analyze_url(args.url)
        print("Heuristic analysis:")
        for key, value in result.items():
            if key != 'features':
                print(f"  {key}: {value}")

        # Print features section if available
        features = result.get('features')
        if features:
            print("\nFeatures:")
            for key, value in features.items():
                print(f"  {key}: {value}")

        if ml_model.is_trained and features:
            prediction, confidence = ml_model.predict(features)
            print(f"\nML Prediction: {prediction}, Confidence: {confidence}")

if __name__ == "__main__":
    main()