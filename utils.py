import requests
import os
import dotenv
import base64
import logging

dotenv.load_dotenv()

class Utils:
    def __init__(self):
        self.api_key = os.getenv('API_KEY')
        self.url = 'https://www.virustotal.com/api/v3/urls/'

    def scan_url(self, url):
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {'x-apikey': self.api_key}

        response = requests.get(f"{self.url}{url_id}", headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)

            if malicious_count > 5:
                return f"⚠️ WARNING: {malicious_count} vendors flagged this URL as malicious!\n"
            elif 1 <= malicious_count <= 5 or suspicious_count > 0:
                return f"⚠️ Caution: {malicious_count} vendors detected it as malicious, {suspicious_count} as suspicious.\n"
            else:
                return "✅ No known threats detected, but always stay cautious.\n"
        else:
            logging.error(f"Error: Failed to fetch URL analysis. Status code: {response.status_code}")
            return None

if __name__ == "__main__":
    utils = Utils()
    print("URL SCANNER\nE.g., http://free-software-download.xyz/\nhttp://paypal-verification-secure.com/login")
    while True:
        url_input = input("\nEnter a link to check: ")
        print(utils.scan_url(url_input))

