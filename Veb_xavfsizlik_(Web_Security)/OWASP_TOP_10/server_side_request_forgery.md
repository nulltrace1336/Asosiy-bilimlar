Server-Side Request Forgery (SSRF) haqida batafsil ma'lumot
SSRF nima?
Server-Side Request Forgery (SSRF) - bu zaiflik bo'lib, hujumchi server tomonidan ichki yoki tashqi resurslarga so'rov yuborishga majbur qiladi. Hujumchi serverning ishonchli maqomidan foydalanib, odatda kirish mumkin bo'lmagan resurslarga murojaat qiladi.
SSRF turlari
1. Basic SSRF
Server URL parametrini qabul qilib, uni so'rov yuborish uchun ishlatadi:
http://vulnerable-site.com/fetch?url=http://internal-server/admin
2. Blind SSRF
Server javobini ko'rsatmaydi, lekin so'rovni bajaradi. DNS yoki HTTP loglar orqali aniqlanadi.
3. Semi-Blind SSRF
Qisman ma'lumot (masalan, xatolik yoki muvaffaqiyat) qaytariladi.
SSRF zaifliklarining asosiy sabablari

Kiritilgan ma'lumotlarni tekshirmaslik
URL filtrlashning zaif bo'lishi
Metadata xizmatlariga kirish imkoniyati
DNS rebinding hujumlari
Redirect-larni to'g'ri boshqarmaslik

Hujum ssenariylari
1. Internal resurslarga kirish
python# Zaif kod
import requests

def fetch_url(url):
    response = requests.get(url)
    return response.content

# Hujum
url = "http://localhost:8080/admin"
# yoki
url = "http://169.254.169.254/latest/meta-data/"  # AWS metadata
```

### 2. Cloud metadata-ga kirish
```
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### 3. Port scanning
```
http://vulnerable-site.com/fetch?url=http://internal-host:22
http://vulnerable-site.com/fetch?url=http://internal-host:3306
Himoya choralari
1. Whitelist yondashuvi
pythonALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def is_safe_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc in ALLOWED_DOMAINS
2. Blacklist (kamroq ishonchli)
pythonBLOCKED_IPS = [
    '127.0.0.0/8',      # localhost
    '10.0.0.0/8',       # Private
    '172.16.0.0/12',    # Private
    '192.168.0.0/16',   # Private
    '169.254.0.0/16',   # Link-local (AWS metadata)
]

def is_blocked_ip(ip):
    import ipaddress
    ip_obj = ipaddress.ip_address(ip)
    for blocked in BLOCKED_IPS:
        if ip_obj in ipaddress.ip_network(blocked):
            return True
    return False
3. DNS resolution tekshiruvi
pythonimport socket
import ipaddress

def resolve_and_validate(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Private va reserved IP'larni bloklash
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return None
            
        return ip
    except:
        return None
4. To'liq himoya namunasi (Python)
pythonimport requests
import socket
import ipaddress
from urllib.parse import urlparse

class SafeSSRFProtection:
    ALLOWED_SCHEMES = ['http', 'https']
    ALLOWED_DOMAINS = ['api.trusted-site.com']
    BLOCKED_PORTS = [22, 23, 25, 3306, 5432, 6379, 27017]
    
    @staticmethod
    def validate_url(url):
        # URL parse qilish
        try:
            parsed = urlparse(url)
        except:
            raise ValueError("Noto'g'ri URL formati")
        
        # Scheme tekshirish
        if parsed.scheme not in SafeSSRFProtection.ALLOWED_SCHEMES:
            raise ValueError("Ruxsat etilmagan protocol")
        
        # Domain whitelist tekshirish
        if parsed.netloc not in SafeSSRFProtection.ALLOWED_DOMAINS:
            raise ValueError("Ruxsat etilmagan domen")
        
        # Port tekshirish
        port = parsed.port or (80 if parsed.scheme == 'http' else 443)
        if port in SafeSSRFProtection.BLOCKED_PORTS:
            raise ValueError("Bloklangan port")
        
        # DNS resolution va IP tekshirish
        try:
            ip = socket.gethostbyname(parsed.netloc)
            ip_obj = ipaddress.ip_address(ip)
            
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_multicast):
                raise ValueError("Ruxsat etilmagan IP manzil")
        except socket.gaierror:
            raise ValueError("DNS resolution xatosi")
        
        return True
    
    @staticmethod
    def safe_fetch(url, timeout=5):
        SafeSSRFProtection.validate_url(url)
        
        # Qo'shimcha himoya: redirect-larni o'chirish
        response = requests.get(
            url, 
            timeout=timeout,
            allow_redirects=False,
            headers={'User-Agent': 'SafeClient/1.0'}
        )
        
        return response

# Foydalanish
try:
    result = SafeSSRFProtection.safe_fetch("https://api.trusted-site.com/data")
    print(result.text)
except ValueError as e:
    print(f"Xavfsizlik xatosi: {e}")
```

### 5. **Network level himoya**
```
- Alohida network segmentatsiya
- Firewall qoidalari
- VPC/Subnet izolyatsiyasi
- Egress traffic cheklash
6. Application level
python# Timeout belgilash
requests.get(url, timeout=5)

# Redirect cheklash
requests.get(url, allow_redirects=False)

# Maksimal hajm cheklash
response = requests.get(url, stream=True)
if int(response.headers.get('content-length', 0)) > 10_000_000:
    raise ValueError("Fayl juda katta")
```

## Real SSRF hujum namunalari

### Capital One ma'lumotlar buzilishi (2019)
AWS metadata xizmatiga SSRF orqali kirish:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Zapier zaiflik
URL validation zaifligidan foydalanish:
```
http://localhost@evil.com/  # DNS rebinding
Testlash vositalari

SSRFmap - avtomatik SSRF aniqlash
Burp Suite - manual testlash
OWASP ZAP - zaifliklarni skanerlash
ffuf - fuzzing

Xulosa
SSRF jiddiy zaiflik bo'lib, to'g'ri himoya choralari zarur:
✅ Doimo whitelist ishlatish
✅ DNS resolution tekshirish
✅ Private IP'larni bloklash
✅ Redirect-larni cheklash
✅ Network segmentatsiya
✅ Metadata xizmatlarini himoyalash
✅ Regular security audit