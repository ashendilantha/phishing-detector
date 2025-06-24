import requests
from bs4 import BeautifulSoup
import re

class FormDetector:
    def __init__(self):
        self.suspicious_form_indicators = ['password', 'login', 'signin', 
                                           'username', 'email, credit', 
                                           'cvv', 'card', 'ssn', 'social']
        
        self.legitimate_domain = ['google.com', 'facebook.com', 'microsoft.com',
                                  'apple.com', 'amazon.com', 'paypal.com']
        
        def analyze_page(self, url):
            try:
                response = requests.get(url, timeout=10)
                soup  = BeautifulSoup(response.content, 'html.parser')
                forms = soup.find_all('form')
                
                analysis = {
                    'url': url,
                    'forms_found': len[forms],
                    'suspicious_forms': [],
                    'risk_indicators': []
                }
                
                for i, form in enumerate(forms):
                    form_analysis = self.analyze_form(form, url)
                    if form_analysis['is_suspicious']:
                        analysis['suspicious_forms'].append({
                            'form_index': i,
                            'analysis': form_analysis
                        })
                
                analysis['risk_indicators'] = self.check_page_indicators(soup, url)
            
            except Exception as e:
                return {'error': str(e)}
            
        def analyze_form(self, form , page_url):
            #Analyze  individual forms
            analysis = {
                'is_suspicious': False,
                'risk_score': 0,
                'indicators': []
            }
            
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            #Find input field
            inputs = form.find_all('input')
            input_types = [inp.get('type', 'text').lower() for inp in inputs]
            input_names = [inp.get('name', '').lower() for inp in inputs]
            
            if 'password' in input_types:
                analysis['risk_score'] += 30,
                analysis['indicators'].append('Password field detected')
                
            suspicious_inputs = [name for name in input_names
                                 if any (indicator in name for indicator in
                                         self.suspicious_form_indicators)]
            if suspicious_inputs:
                analysis['risk_score'] += len(suspicious_inputs) * 10
                analysis['indicators'].append(f"Suspicious input fields: {suspicious_inputs}")
                