# import re
# import tldextract
# import requests
# from urllib.parse import urlparse
# import whois
# from datetime import datetime

# class URLAnalyzer:
#     def __init__(self):
#         self.suspicious_keywords = ['secure', 'account', 'update', 'verify', 'login', 'paypal', 'amazon', 'microsoft',
#                                      'password', 'credentials', 'urgent', 'security', 'alert', 'suspended', 'locked',
#                                        'banned', 'action', 'required', 'confirm', 'identity', 'bank', 'payment', 'refund',
#                                          'limited', 'offer', 'prize', 'win', 'claim', 'rewards', 'billing', 'invoice',
#                                            'statement', 'unauthorized', 'fraud', 'hacked', 'compromised', 'phishing', 'scam',
#                                              'support', 'helpdesk', 'customer', 'service', 'recovery', 'restore', 'access', 'blocked',
#                                                'expired', 'validation', 'authentication', 'authorize', 'social', 'security', 'number',
#                                                  'ssn', 'credit', 'card', 'debit', 'paypal', 'amazon', 'microsoft', 'google', 'apple', 
#                                                  'netflix', 'ebay', 'instagram', 'facebook', 'twitter', 'whatsapp', 'telegram', 'crypto',
#                                                    'bitcoin', 'wallet', 'exchange', 'login', 'signin', 'portal', 'admin', 'dashboard',
#                                                      'settings', 'profile', 'info', 'personal', 'data', 'breach', 'leak', 'exposed']
        
#         self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf',
#                                 '.gq', '.pw', '.cc', '.xyz',
#                                 '.top', '.club', '.online', '.site',
#                                 '.space', '.webcam', '.work', '.biz',
#                                 '.info', '.download', '.stream', '.gdn',  
#                                 '.loan', '.pro', '.science', '.tech',  
#                                 '.ren', '.win', '.vip', '.bid',  
#                                 '.click', '.country', '.date', '.faith',  
#                                 '.party', '.racing', '.review', '.trade',  
#                                 '.accountant', '.bar', '.cricket', '.men',  
#                                 '.mom', '.photo', '.pics', '.zip',  
#                                 '.cyou', '.rest', '.lol', '.uno',  
#                                 '.buzz', '.nexus', '.yokohama', '.tokyo']
        
#         def analyze_url(self, url):
#             #URL analysis
#             features = self.extract_features(url)
#             risk_score = self.calculate_risk_score(features)

#             return{
#                 'url': url,
#                 'risk_score': risk_score,
#                 'risk_level': self.get_risk_level(risk_score),
#                 'features': features,
#                 'warnings': self.generate_warnings(features)
#             }
        
#         def extract_features(self, url):
#             #Extract heuristic features from URL
#             parsed = urlparse(url)
#             extracted = tldextract.extract(url)

#             features = {
#                 'length': len(url),
#                 'has_ip': self.has_ip_address(parsed.netloc),
#                 'suspicious_keyword': self.count_suspicious_keywords(url.lower()),
#                 'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
#                 'has_suspicious_tld': extracted.suffix in self.suspicious_tlds,
#                 'has_url_shortener': self.is_url_shortener(extracted.domain),
#                 'has_https': parsed.scheme == 'https',
#                 'domain_age': self.get_domain_age(extracted.domain + '.' + extracted.suffix),
#                 'special_chars': len(re.findall(r'[^a-zA-Z0-9./:]',url)),
#                 'has_homograph': self.detect_homograph_attack(extracted.domain)
#             }
#             return features
        
#         def has_ip_address(self, netloc):
#             #Check if url use ip add instead of domain
#             ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
#             return bool(re.search(ip_pattern, netloc))
        
#         def count_suspicious_keywords(self, url):
#             #Count suspicious keywords in url
#             return sum(1 for keyword in self.suspicious_keywords if keyword in url)
        
#         def is_url_shortener(self, domain):
#             shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
#             return domain in shorteners
        
#         def get_domain_age(self, domain):
#             try:
#                 domain_info = whois.whois(domain)
#                 if domain_info.creation_date:
#                     creation_date = domain_info.creation_date
#                     if isinstance(creation_date, list):
#                         creation_date = creation_date[0]
#                     age = (datetime.now() - creation_date).days
#                     return age
#             except:
#                  pass
#             return -1
        
#         def calculate_risk_attack(self, domain):
#             suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у'] 
#             return any(char in domain for char in suspicious_chars)
        
#         def calculate_risk_score(self, features):
#             #calculate risk base on feature
#             score = 0

#             #URL length
#             if features['length'] > 100:
#                 score += 20
#             elif features['length'] > 50:
#                 score += 10

#             #IP usages
#             if features['has_ip']:
#                 score += 30
            
#             #Suspicious keywords
#             score += features['suspicious_keywords'] * 15

#             #Subdomain count
#             if features['subdomain_count'] > 2:
#                 score += 25
            
#             #Suspicious TLD
#             if features['has_suspicious_tld']:
#                 score += 20

#             #url shortener 
#             if features['has_url_shortener']:
#                 score += 20
            
#             #No https
#             if not features['has_https']:
#                 score += 10

#             #new domain
#             if features['domain_age'] < 30:
#                 score += 25
            
#             #special characters
#             if features['special_chars'] > 10:
#                 score += 15
            
#             #homograph attack
#             if features['has_homograph']:
#                 score += 35
            
#             return min(score, 100)
        
#         def get_risk_level(self, score):
#             if score >= 70:
#                 return "HIGH"
#             elif score >= 40:
#                 return "MEDIUM"
#             elif score >= 20:
#                 return "LOW"
#             else:
#                 return "SAFE"
            
#         def generate_warnings(self, features):
#             warnings = []

#             if features['has_ip']:
#                 warnings.append("URL uses IP address instead of domain name")
#             if features['suspicious_keywords'] > 2:
#                 warnings.append("Multiple suspicious keywords detected")
#             if features['has_suspicious_tld']:
#                 warnings.append("Suspicious Top level domain")
#             if features['has_url_shorteners']:
#                 warnings.append("URL shortener detected. destination unknown")
#             if not features['has_https']:
#                 warnings.append("No secure HTTPS connection")
#             if 0 <= features['domain_age'] < 30:
#                 warnings.append("New domain detected (less than 30 days old)")
#             if features['has_homograph']:
#                 warnings.append('Potential homograph attack detected')

#             return warnings



import re
import tldextract
import requests
from urllib.parse import urlparse
import whois
from datetime import datetime

class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = ['secure', 'account', 'update', 'verify', 'login', 'paypal', 'amazon', 'microsoft',
                                   'password', 'credentials', 'urgent', 'security', 'alert', 'suspended', 'locked',
                                   'banned', 'action', 'required', 'confirm', 'identity', 'bank', 'payment', 'refund',
                                   'limited', 'offer', 'prize', 'win', 'claim', 'rewards', 'billing', 'invoice',
                                   'statement', 'unauthorized', 'fraud', 'hacked', 'compromised', 'phishing', 'scam',
                                   'support', 'helpdesk', 'customer', 'service', 'recovery', 'restore', 'access', 'blocked',
                                   'expired', 'validation', 'authentication', 'authorize', 'social', 'security', 'number',
                                   'ssn', 'credit', 'card', 'debit', 'paypal', 'amazon', 'microsoft', 'google', 'apple',
                                   'netflix', 'ebay', 'instagram', 'facebook', 'twitter', 'whatsapp', 'telegram', 'crypto',
                                   'bitcoin', 'wallet', 'exchange', 'login', 'signin', 'portal', 'admin', 'dashboard',
                                   'settings', 'profile', 'info', 'personal', 'data', 'breach', 'leak', 'exposed']
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf',
                               '.gq', '.pw', '.cc', '.xyz',
                               '.top', '.club', '.online', '.site',
                               '.space', '.webcam', '.work', '.biz',
                               '.info', '.download', '.stream', '.gdn',
                               '.loan', '.pro', '.science', '.tech',
                               '.ren', '.win', '.vip', '.bid',
                               '.click', '.country', '.date', '.faith',
                               '.party', '.racing', '.review', '.trade',
                               '.accountant', '.bar', '.cricket', '.men',
                               '.mom', '.photo', '.pics', '.zip',
                               '.cyou', '.rest', '.lol', '.uno',
                               '.buzz', '.nexus', '.yokohama', '.tokyo']
    
    def analyze_url(self, url):
        # URL analysis
        features = self.extract_features(url)
        risk_score = self.calculate_risk_score(features)
        return {
            'url': url,
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score),
            'features': features,
            'warnings': self.generate_warnings(features)
        }
    
    def extract_features(self, url):
        # Extract heuristic features from URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        features = {
            'length': len(url),
            'has_ip': self.has_ip_address(parsed.netloc),
            'suspicious_keywords': self.count_suspicious_keywords(url.lower()),  # Fixed key
            'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
            'has_suspicious_tld': extracted.suffix in self.suspicious_tlds,
            'has_url_shortener': self.is_url_shortener(extracted.domain),
            'has_https': parsed.scheme == 'https',
            'domain_age': self.get_domain_age(extracted.domain + '.' + extracted.suffix),
            'special_chars': len(re.findall(r'[^a-zA-Z0-9./:]', url)),
            'has_homograph': self.detect_homograph_attack(extracted.domain)
        }
        return features
    
    def has_ip_address(self, netloc):
        # Check if URL uses IP address instead of domain
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, netloc))
    
    def count_suspicious_keywords(self, url):
        # Count suspicious keywords in URL
        return sum(1 for keyword in self.suspicious_keywords if keyword in url)
    
    def is_url_shortener(self, domain):
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        return domain in shorteners
    
    def get_domain_age(self, domain):
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age = (datetime.now() - creation_date).days
                return age
        except Exception:
            pass
        return -1
    
    def detect_homograph_attack(self, domain):
        # Detect potential homograph attack using Cyrillic characters
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']
        return any(char in domain for char in suspicious_chars)
    
    def calculate_risk_score(self, features):
        # Calculate risk based on features
        score = 0

        # URL length
        if features['length'] > 100:
            score += 20
        elif features['length'] > 50:
            score += 10

        # IP usage
        if features['has_ip']:
            score += 30
        
        # Suspicious keywords
        score += features['suspicious_keywords'] * 15

        # Subdomain count
        if features['subdomain_count'] > 2:
            score += 25
        
        # Suspicious TLD
        if features['has_suspicious_tld']:
            score += 20

        # URL shortener
        if features['has_url_shortener']:
            score += 20
        
        # No HTTPS
        if not features['has_https']:
            score += 10

        # New domain
        if features['domain_age'] < 30:
            score += 25
        
        # Special characters
        if features['special_chars'] > 10:
            score += 15
        
        # Homograph attack
        if features['has_homograph']:
            score += 35
        
        return min(score, 100)
    
    def get_risk_level(self, score):
        if score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "SAFE"
        
    def generate_warnings(self, features):
        warnings = []

        if features['has_ip']:
            warnings.append("URL uses IP address instead of domain name")
        if features['suspicious_keywords'] > 2:
            warnings.append("Multiple suspicious keywords detected")
        if features['has_suspicious_tld']:
            warnings.append("Suspicious Top level domain")
        if features['has_url_shortener']:
            warnings.append("URL shortener detected. destination unknown")  # Fixed typo
        if not features['has_https']:
            warnings.append("No secure HTTPS connection")
        if 0 <= features['domain_age'] < 30:
            warnings.append("New domain detected (less than 30 days old)")
        if features['has_homograph']:
            warnings.append('Potential homograph attack detected')

        return warnings