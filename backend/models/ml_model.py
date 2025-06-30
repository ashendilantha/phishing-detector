import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

class PhishingMLModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        self.model_path = 'model/phishing_model.pkl'
        
    def prepare_features(self, url_features):
        feature_vector =[url_features['length'],
                         int(url_features['has_ip']),
                         url_features['suspicious_keywords'],
                         url_features['subdomain_count'],
                         int(url_features['has_suspicious_tld']),
                         int(url_features['has_url_shorteners']),
                         int(url_features['has_https']),
                         url_features['domain_age'] if url_features['domain_age'] >= 0 else 0,
                         url_features['special_chars'],
                         int(url_features['has_homograph'])]
        
        return np.array(feature_vector).reshape(1, -1)
    
    def train_model(self, training_data_path):
        try:
            #load trining data
            df = pd.read_csv(training_data_path)
            
            X = df.drop(['url', 'label'], axis=1)
            y = df['label']
            
            #split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            #train model
            self.model.fit(X_train, y_train)
            
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            print(f"Model accuracy: {accuracy:.2f}")
            print(classification_report(y_test, y_pred))
            
            #save trained model
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.model, self.model_path)
            self.is_trained = True
            
            return accuracy
        
        except Exception as e:
            print(f"Training failed: {e}")
            return None
        
    def load_model(self):
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.is_trained = True
                return True
        except Exception as e:
            print(f"Failed to load model: {e}")
        return False
    
    def predict(self, url_features):
        #predict if URL is phishing url
        if not self.is_trained:
            if not self.load_model():
                return None, None
    
        try:
            features = self.prepare_features(url_features)
            prediction = self.model.predict(features)[0]
            probability = self.model.predict_proba(features)[0]
            
            return prediction, max(probability)
        
        except Exception as e:
            print(f"Prediction failed: {e}")
            return None, None