Security Logging and Monitoring Failures - Batafsil Ma'lumot
Security Logging and Monitoring Failures (Xavfsizlik Jurnali va Monitoring Zaifliklarі) - bu tizimda sodir bo'layotgan xavfsizlik hodisalarini yetarli darajada qayd qilmaslik, aniqlamamaslik yoki ularga javob bermaslik muammolaridir.
Asosiy Muammolar
1. Yetarli Darajada Log Yozilmasligi

Login urinishlari (muvaffaqiyatli va muvaffaqiyatsiz)
Ruxsat huquqlari buzilishi
Input validatsiya xatolari
Muhim ma'lumotlarga kirish urinishlari qayd qilinmaydi

2. Log Ma'lumotlarining Kamchiligi

Foydalanuvchi ID
IP manzil
Vaqt tamg'asi (timestamp)
Bajariladigan amal haqida ma'lumot yetishmasligi

3. Monitoring Tizimining Yo'qligi

Real vaqtda hujumlarni aniqlay olmaslik
Shubhali harakatlar uchun ogohlantirish tizimi yo'q
Loglarni muntazam tahlil qilish jarayoni yo'q

Zaifliklarni Aniqlash Usullari
1. Log Fayllarini Tekshirish
python# Yomon misol - yetarli ma'lumot yo'q
logging.info("Login failed")

# Yaxshi misol - to'liq kontekst
logging.warning(
    f"Login failed - User: {username}, "
    f"IP: {request.remote_addr}, "
    f"Time: {datetime.now()}, "
    f"Attempt: {attempt_number}"
)
2. Audit Rejasini Tuzish

Qaysi hodisalar log qilinishi kerakligini aniqlash
Login/logout hodisalari
Ma'lumotlarga kirish (ayniqsa maxfiy ma'lumotlar)
O'zgarishlar (CREATE, UPDATE, DELETE)
Ruxsat huquqlari o'zgarishi
Xatoliklar va istisnolar

3. Log Qamrovi Testlari
bash# Test: Login muvaffaqiyatsiz bo'lganda log yozilishini tekshirish
# 1. Noto'g'ri parol bilan login urinishi
# 2. Log faylni tekshirish
grep "Login failed" /var/log/application.log

# Test: SQL Injection urinishini qayd qilish
# 1. Malicious input yuborish
# 2. Log faylda qayd etilganligini tekshirish
Chora Ko'rish Usullari
1. To'liq Logging Tizimini Joriy Etish
Python (Flask) misoli:
pythonimport logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Logging konfiguratsiyasi
def configure_logging(app):
    # Fayl handler
    file_handler = RotatingFileHandler(
        'logs/security.log', 
        maxBytes=10240000, 
        backupCount=10
    )
    
    # Format
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

# Security hodisalarini log qilish
def log_security_event(event_type, user_id, details):
    app.logger.warning(
        f"SECURITY_EVENT | Type: {event_type} | "
        f"User: {user_id} | IP: {request.remote_addr} | "
        f"Details: {details} | Time: {datetime.utcnow()}"
    )

# Login muvaffaqiyatsiz bo'lganda
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if not authenticate(username, password):
        log_security_event(
            'LOGIN_FAILED',
            username,
            f'Invalid credentials from {request.remote_addr}'
        )
        return "Login failed", 401
Node.js (Express) misoli:
javascriptconst winston = require('winston');

// Logger konfiguratsiyasi
const securityLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'logs/security.log' 
        }),
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error' 
        })
    ]
});

// Middleware - barcha so'rovlarni log qilish
app.use((req, res, next) => {
    securityLogger.info({
        type: 'HTTP_REQUEST',
        method: req.method,
        url: req.url,
        ip: req.ip,
        user: req.user?.id || 'anonymous'
    });
    next();
});

// Xavfsizlik hodisalarini log qilish
function logSecurityEvent(eventType, userId, details) {
    securityLogger.warn({
        type: 'SECURITY_EVENT',
        eventType: eventType,
        userId: userId,
        details: details,
        timestamp: new Date().toISOString()
    });
}
2. Centralized Logging Tizimi
ELK Stack (Elasticsearch, Logstash, Kibana) yoki alternativalari:

Graylog
Splunk
AWS CloudWatch
Azure Monitor

yaml# Docker Compose - ELK Stack misoli
version: '3'
services:
  elasticsearch:
    image: elasticsearch:7.14.0
    environment:
      - discovery.type=single-node
    ports:
      - 9200:9200

  logstash:
    image: logstash:7.14.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

  kibana:
    image: kibana:7.14.0
    ports:
      - 5601:5601
    depends_on:
      - elasticsearch
3. Real-time Monitoring va Alerting
Shubhali harakatlar uchun alertlar:
python# Brute-force hujumini aniqlash
from collections import defaultdict
from datetime import datetime, timedelta

# Login urinishlarini kuzatish
failed_logins = defaultdict(list)

def check_brute_force(username, ip_address):
    key = f"{username}:{ip_address}"
    current_time = datetime.now()
    
    # Eski urinishlarni tozalash (5 daqiqadan oldingi)
    failed_logins[key] = [
        t for t in failed_logins[key] 
        if current_time - t < timedelta(minutes=5)
    ]
    
    # Yangi muvaffaqiyatsiz urinishni qo'shish
    failed_logins[key].append(current_time)
    
    # 5 daqiqada 5 marta muvaffaqiyatsiz - ALERT
    if len(failed_logins[key]) >= 5:
        send_security_alert(
            f"Brute force detected! "
            f"User: {username}, IP: {ip_address}, "
            f"Attempts: {len(failed_logins[key])}"
        )
        # IP ni vaqtinchalik bloklash
        block_ip(ip_address, duration=30)  # 30 daqiqa
        return True
    return False

def send_security_alert(message):
    # Email yuborish
    # SMS yuborish
    # Slack/Telegram ga xabar yuborish
    logger.critical(f"SECURITY_ALERT: {message}")
4. Log Tahlili va Anomaliyalarni Aniqlash
python# Oddiy anomaliya aniqlash
def detect_anomalies():
    # Odatiy bo'lmagan vaqtlarda kirish
    # Masalan, kechasi 2:00 da admin kirishga urinish
    
    # G'ayritabiiy joy'dan kirish
    # Masalan, foydalanuvchi doimiy Toshkentdan, 
    # to'satdan Amerikadan kirish urinishi
    
    # Ko'p marta parol o'zgartirish
    # Ko'p marta ruxsat huquqlarini o'zgartirish
    
    pass
5. Muhim Hodisalar Ro'yxati
Albatta log qilinishi kerak:

Autentifikatsiya:

Login (muvaffaqiyatli/muvaffaqiyatsiz)
Logout
Parol o'zgartirish
Parol tiklash so'rovi


Avtorizatsiya:

Ruxsatsiz kirish urinishi
Privilegiya oshirish urinishi
Role/permission o'zgarishi


Ma'lumotlar:

Maxfiy ma'lumotlarga kirish
Ma'lumotlarni o'zgartirish (CRUD)
Ma'lumotlarni eksport qilish


Tizim:

Konfiguratsiya o'zgarishi
Xatolar va istisnolar
Servis to'xtashi/qayta ishga tushishi



6. Log Xavfsizligi
python# Log fayllarini shifrlash
from cryptography.fernet import Fernet

def encrypt_sensitive_log_data(data):
    key = load_encryption_key()
    f = Fernet(key)
    return f.encrypt(data.encode())

# Log integrity tekshirish
import hashlib

def create_log_hash(log_entry):
    return hashlib.sha256(log_entry.encode()).hexdigest()

# Loglarni o'zgartirishdan himoya qilish
# - Append-only fayl tizimi
# - Tezkor boshqa joyga nusxa olish
# - Blockchain asosidagi log tizimi
7. Compliance va Standartlar

PCI DSS - to'lov kartasi ma'lumotlari uchun
GDPR - shaxsiy ma'lumotlar uchun
HIPAA - tibbiy ma'lumotlar uchun
ISO 27001 - umumiy xavfsizlik

python# GDPR talablari uchun - maxfiy ma'lumotlarni maskirovka
def mask_sensitive_data(log_entry):
    # Email: user@example.com → u***@example.com
    # Telefon: +998901234567 → +998****4567
    # Karta raqami: 1234567890123456 → ****3456
    import re
    
    # Email maskirovka
    log_entry = re.sub(
        r'([a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]*@',
        r'\1***@',
        log_entry
    )
    
    return log_entry
Best Practices

Barcha muhim hodisalarni log qiling
Centralized logging tizimini ishlating
Real-time monitoring o'rnating
Alertlar sozlang
Loglarni xavfsiz saqlang
Muntazam tahlil qiling
Retention policy belgilang (qancha vaqt saqlash kerak)
Anomaliyalarni avtomatik aniqlang
Incident response rejasi tuzing
Loglarni audit qiling

Xulosa
Security Logging and Monitoring - bu zamonaviy ilovalar uchun juda muhim. Bu sizga:

Hujumlarni tezda aniqlash imkonini beradi
Incident investigation uchun zarur ma'lumotlar taqdim etadi
Compliance talablariga javob beradi
Tizim xavfsizligini yaxshilash yo'llarini ko'rsatadi