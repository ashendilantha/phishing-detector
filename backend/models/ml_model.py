import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO)

class PhishingMLModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        self.model_path = os.path.join(os.path.dirname(__file__), 'model', 'phishing_model.pkl')
        
    def prepare_features(self, url_features):
        required_features = ['length', 'has_ip', 'suspicious_keywords', 'subdomain_count', 
                           'has_suspicious_tld', 'has_url_shorteners', 'has_https', 
                           'domain_age', 'special_chars', 'has_homograph']
        for key in required_features:
            if key not in url_features:
                raise ValueError(f"Missing required feature: {key}")
        
        feature_vector = [
            url_features['length'],
            int(url_features['has_ip']),
            url_features['suspicious_keywords'],
            url_features['subdomain_count'],
            int(url_features['has_suspicious_tld']),
            int(url_features['has_url_shorteners']),
            int(url_features['has_https']),
            url_features['domain_age'] if url_features['domain_age'] >= 0 else 0,
            url_features['special_chars'],
            int(url_features['has_homograph'])
        ]
        
        return np.array(feature_vector).reshape(1, -1)
    
    def train_model(self, training_data_path):
        try:
            # Load training data
            df = pd.read_csv(training_data_path)
            
            # Validate required columns
            required_columns = ['url', 'label'] + self.prepare_features({}).flatten().tolist()
            if not all(col in df.columns for col in required_columns):
                raise ValueError("Training data missing required columns")
            
            X = df.drop(['url', 'label'], axis=1)
            y = df['label']
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train model
            self.model.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logging.info(f"Model accuracy: {accuracy:.2f}")
            logging.info(classification_report(y_test, y_pred))
            
            # Save trained model
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.model, self.model_path)
            self.is_trained = True
            
            return accuracy
        
        except Exception as e:
            logging.error(f"Training failed: {e}")
            return None
        
    def load_model(self):
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.is_trained = True
                return True
        except Exception as e:
            logging.error(f"Failed to load model: {e}")
        return False
    
    def predict(self, url_features):
        # Predict if URL is phishing
        if not self.is_trained:
            if not self.load_model():
                return None, None
    
        try:
            features = self.prepare_features(url_features)
            prediction = self.model.predict(features)[0]
            probability = self.model.predict_proba(features)[0]
            
            return prediction, max(probability)
        
        except Exception as e:
            logging.error(f"Prediction failed: {e}")
            return None, None