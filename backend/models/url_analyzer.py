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
            #URL analysis
            features = self.extract_features(url)
            risk_score = self.calculate_risk_score(features)

            return{
                'url': url,
                'risk_score': risk_score,
                'risk_level': self.get_risk_level(risk_score),
                'features': features,
                'warnings': self.generate_warnings(features)
            }
        
        def extract_features(self, url):
            #Extract heuristic features from URL
            parsed = urlparse(url)
            extracted = tldextract.extract(url)

            features = {
                'length': len(url),
                'has_ip': self.has_ip_address(parsed.netloc),
                'suspicious_keyword': self.count_suspicious_keywords(url.lower()),
                'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
                'has_suspicious_tld': extracted.suffix in self.suspicious_tlds,
                'has_url_shortener': self.is_url_shortener(extracted.domain),
                'has_https': parsed.scheme == 'https',
                'domain_age': self.get_domain_age(extracted.domain + '.' + extracted.suffix),
                'special_chars': len(re.findall(r'[^a-zA-Z0-9./:]',url)),
                'has_homograph': self.detect_homograph_attack(extracted.domain)
            }
            return features
        
        def has_ip_address(self, netloc):
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            return bool(re.search(ip_pattern, netloc))
        
        def count_suspicious_keywords(self, url):
            return sum