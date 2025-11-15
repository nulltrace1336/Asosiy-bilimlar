OWASP Top 10 Zaifliklarini Aniqlash Uchun Instrumentlar
OWASP Top 10 zaifliklarini aniqlash uchun turli xil vosita va texnologiyalar mavjud. Quyida eng muhim instrumentlar va ulardan foydalanish yo'llari batafsil keltirilgan.
1. OWASP ZAP (Zed Attack Proxy)
Tavsif: Bepul va ochiq kodli veb-ilovalar xavfsizligini tekshirish vositasi.
O'rnatish:
bash# Linux
sudo apt install zaproxy

# yoki rasmiy saytdan yuklab olish
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
Asosiy funksiyalar:

Avtomatik zaiflik skanerlash
Manual penetration testing
Spider/crawler
Fuzzing
Intercepting proxy

Foydalanish:
bash# GUI rejimida ishga tushirish
zap.sh

# Headless rejimda quick scan
zap.sh -cmd -quickurl https://example.com -quickprogress

# Baseline scan
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://example.com
OWASP Top 10 aniqlashi:

SQL Injection
XSS (Cross-Site Scripting)
Broken Authentication
Security Misconfiguration
XXE (XML External Entities)

2. Burp Suite
Tavsif: Professional veb-xavfsizlik testing platformasi.
Versiyalar:

Community Edition (bepul)
Professional (pullik)

Asosiy xususiyatlar:

Intercepting Proxy
Scanner (Professional)
Intruder (brute-force tool)
Repeater
Decoder/Encoder

Foydalanish bosqichlari:

Proxy sozlash:

Burp Suite'da Proxy → Options
Brauzerda proxy sozlash (127.0.0.1:8080)
Burp CA sertifikatini o'rnatish


Target aniqlash:

Saytga kirish
HTTP/HTTPS trafikni kuzatish
Target → Site map'da barcha so'rovlarni ko'rish


Scanner ishlatish (Pro versiya):

Target'ni tanlash
Right-click → Scan
Active/Passive scan tanlash


Manual testing:

Intercepted request'ni tahrirlash
Repeater'da qayta-qayta yuborish
Intruder bilan parametrlarni test qilish



3. Nikto
Tavsif: Veb-server zaifliklarini topish uchun scanner.
O'rnatish:
bashsudo apt install nikto
Foydalanish:
bash# Oddiy scan
nikto -h http://example.com

# SSL bilan
nikto -h https://example.com -ssl

# Ma'lum portda
nikto -h example.com -p 8080

# Natijani faylga saqlash
nikto -h example.com -o report.html -Format html

# Ko'proq ma'lumot bilan
nikto -h example.com -Tuning 123456789
Aniqlashi mumkin bo'lgan zaifliklar:

Outdated server versions
Dangerous files/CGI
Server misconfigurations
Default files va folders
Unnecessary HTTP methods

4. SQLMap
Tavsif: SQL injection zaifliklarini avtomatik aniqlash va exploit qilish vositasi.
O'rnatish:
bashsudo apt install sqlmap

# yoki
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
Asosiy foydalanish:
bash# URL orqali test
sqlmap -u "http://example.com/page.php?id=1"

# POST request
sqlmap -u "http://example.com/login.php" --data="username=admin&password=pass"

# Cookie bilan
sqlmap -u "http://example.com/page.php?id=1" --cookie="PHPSESSID=abc123"

# Database ma'lumotlarini olish
sqlmap -u "http://example.com/page.php?id=1" --dbs
sqlmap -u "http://example.com/page.php?id=1" -D database_name --tables
sqlmap -u "http://example.com/page.php?id=1" -D database_name -T users --dump

# Risk va level sozlash
sqlmap -u "http://example.com/page.php?id=1" --level=5 --risk=3

# Proxy orqali
sqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"
5. Nmap + NSE Scripts
Tavsif: Network scanner va zaiflik aniqlash.
OWASP uchun foydali NSE scriptlar:
bash# HTTP zaifliklarni tekshirish
nmap --script http-vuln-* example.com

# SQL injection
nmap --script http-sql-injection example.com -p 80,443

# XSS
nmap --script http-stored-xss,http-dombased-xss example.com

# SSL/TLS zaifliklar
nmap --script ssl-enum-ciphers,ssl-cert,ssl-known-key -p 443 example.com

# Default credentials
nmap --script http-default-accounts example.com
6. Wapiti
Tavsif: Veb-ilovalar uchun vulnerability scanner.
O'rnatish:
bashsudo apt install wapiti
Foydalanish:
bash# Asosiy scan
wapiti -u http://example.com

# Ma'lum modullar bilan
wapiti -u http://example.com -m sql,xss,xxe

# Chuqurroq scan
wapiti -u http://example.com --scope url

# HTML report
wapiti -u http://example.com -f html -o /path/to/report
7. Arachni
Tavsif: Feature-rich veb zaiflik scanneri.
Foydalanish:
bash# Web UI orqali
arachni_web

# CLI orqali
arachni http://example.com

# Ma'lum zaifliklarni tekshirish
arachni http://example.com --checks=sql_injection,xss,code_injection

# Authenticated scanning
arachni http://example.com --plugin=autologin:url=http://example.com/login,parameters='username=user&password=pass'
8. w3af (Web Application Attack Framework)
O'rnatish:
bashgit clone https://github.com/andresriancho/w3af.git
cd w3af
./w3af_console
Foydalanish:
bash# Console rejimda
w3af>>> target set target http://example.com
w3af>>> plugins
w3af>>> audit sql_injection, xss, csrf
w3af>>> start
9. Metasploit Framework
Veb-zaifliklar uchun:
bashmsfconsole

# SQL injection
use auxiliary/scanner/http/sql_injection

# Directory traversal
use auxiliary/scanner/http/dir_scanner

# Web login brute-force
use auxiliary/scanner/http/http_login
10. Custom Scriptlar va Toolchain
Python bilan zaiflik tekshirish:
pythonimport requests
from bs4 import BeautifulSoup

# XSS test
def test_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    
    for payload in payloads:
        response = requests.get(url, params={'input': payload})
        if payload in response.text:
            print(f"Potential XSS found with payload: {payload}")

# SQL injection test
def test_sql(url):
    payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users--"]
    
    for payload in payloads:
        response = requests.get(url, params={'id': payload})
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print(f"Potential SQL injection with payload: {payload}")
Amaliy Ish Jarayoni
1-bosqich: Reconnaissance
bash# Nmap bilan
nmap -sV -sC example.com

# Subdomain enumeration
subfinder -d example.com
2-bosqich: Scanning
bash# ZAP bilan avtomatik scan
zap-cli quick-scan --self-contained http://example.com

# Nikto
nikto -h http://example.com
3-bosqich: Vulnerability Testing
bash# SQLMap
sqlmap -u "http://example.com/page?id=1" --batch

# XSS testing
echo "http://example.com" | dalfox pipe
4-bosqich: Exploitation (faqat ruxsat bilan!)
bash# Burp Suite Professional
# yoki Metasploit
5-bosqich: Reporting

Topilgan zaifliklarni dokumentlashtirish
CVSS score berish
Remediation tavsiyalari

Muhim Eslatmalar
Qonuniy jihat:

Faqat o'z ilovalaringizda yoki yozma ruxsat bilan test qiling
Bug bounty dasturlarida qatnashing
Noqonuniy testing jinoiy javobgarlikka olib keladi

Best Practices:

False positive'larni tekshiring
Production serverlarni ehtiyotkorlik bilan test qiling
Test environmentda ishlash yaxshiroq
Har doim backup oling
Test natijalarini xavfsiz saqlang