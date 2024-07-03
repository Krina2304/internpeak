import re

# Function to detect phishing URLs based on patterns
def detect_phishing(url):
    # Regular expressions to detect common phishing patterns
    patterns = {
        "IP Address in URL": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # Detects IP addresses in URL
        "Tiny URL": r"https?://(bit\.ly|goo\.gl|t\.co|tinyurl|ow\.ly)",  # Detects popular URL shorteners
        "Misleading Domain": r"\b(homograph|[\d\w\-]{10,}\.com)",  # Detects suspiciously long or misleading domains
        "HTTPS Mismatch": r"https://[\w\-\.]+\.(com|net|org|ru|info|biz|co|in)",  # Detects mismatched HTTPS domains
        "Subdomain": r"(http|https)://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(/\S*)?"  # Detects unusual subdomains
    }
    
    # Check each pattern
    for key, pattern in patterns.items():
        if re.search(pattern, url):
            return f"Phishing detected: {key}"
    
    return "No phishing patterns detected"

if __name__ == "__main__":
    # Example URLs to test
    urls = [
        "https://www.google.com",               # Safe URL
        "http://bit.ly/abcde",                  # Phishing URL (URL shortener)
        "https://www.bankofamerica.com",        # Safe URL
        "http://example-secure-site.com",       # Phishing URL (misleading domain)
        "https://www.paypal.com",               # Safe URL
        "https://login.microsoftonline.com",    # Safe URL
        "http://1.1.1.1/",                      # Phishing URL (IP address in URL)
        "https://www.some-long-and-suspicious-domain.com"  # Phishing URL (misleading domain)
    ]
    
    for url in urls:
        result = detect_phishing(url)
        print(f"{url}: {result}")
