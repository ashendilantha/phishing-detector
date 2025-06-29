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
            
            if action:
                if action.startswith('http') and not any(domain in action for domain in
                                                         self.legitimate_domains):
                    analysis['risk_score'] += 25
                    analysis['indicators'].append('Form submits to external domain')
                elif action.startswith('javascript:'):
                    analysis['risk_score'] += 20
                    analysis['indicators'].append('Form uses JavaScript action')

            # Check for missing CSRF protection
            csrf_tokens = form.find_all('input', {'type': 'hidden'})
            if not csrf_tokens and 'password' in input_types:
                analysis['risk_score'] += 15
                analysis['indicators'].append('No CSRF protection detected')
            
            # Check method
            if method == 'get' and 'password' in input_types:
                analysis['risk_score'] += 20
                analysis['indicators'].append('Password sent via GET method')
            
            analysis['is_suspicious'] = analysis['risk_score'] >= 30
            
            return analysis
        
        def check_page_indicators(self, soup, url):
            #Check phishing indicators
            indicators = []
            
            # Check for suspicious title
            title = soup.find('title')
            if title:
                title_text = title.get_text().lower()
                if any(word in title_text for word in ['verify', 'suspend', 'urgent', 'security']):
                    indicators.append('Suspicious page title')
            
            # Check for fake SSL indicators
            ssl_indicators = soup.find_all(text=re.compile(r'secure|ssl|encrypted', re.I))
            if ssl_indicators and not url.startswith('https'):
                indicators.append('Claims to be secure but not using HTTPS')
            
            # Check for urgency language
            urgency_words = ['urgent', 'immediate', 'expire', 'suspend', 'limited time']
            page_text = soup.get_text().lower()
            if sum(1 for word in urgency_words if word in page_text) >= 2:
                indicators.append('Uses urgency language')
            