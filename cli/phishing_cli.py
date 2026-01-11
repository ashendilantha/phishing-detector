import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import argparse
from backend.models.url_analyzer import URLAnalyzer

def main():
    parser = argparse.ArgumentParser(description="Phishing Detector CLI")
    parser.add_argument('--url', type=str, help='URL to analyze')
    args = parser.parse_args()

    if args.url:
        url_analyzer = URLAnalyzer()
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

if __name__ == "__main__":
    main()