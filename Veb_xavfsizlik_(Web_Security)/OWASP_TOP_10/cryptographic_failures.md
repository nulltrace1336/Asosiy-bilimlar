Cryptographic Failures - Batafsil Ma'lumot
Nima bu?
Cryptographic Failures (ilgari "Sensitive Data Exposure" deb atalgan) - bu ma'lumotlarni shifrlash bilan bog'liq xatoliklar va zaifliklar. OWASP Top 10 (2021) ro'yxatida #2 o'rinda turadi.
Asosiy Muammolar
1. Ma'lumotlarni Shifrlashda Xatolar

Parollarni ochiq (plaintext) saqlash
Zaif shifrlash algoritmlaridan foydalanish
Noto'g'ri shifrlash implementatsiyasi

2. Transport Layer Xavfsizligi

HTTP orqali sensitive data yuborish (HTTPS o'rniga)
SSL/TLS noto'g'ri konfiguratsiya
Eski TLS versiyalari (TLS 1.0, 1.1)

3. Key Management Muammolari

Hardcoded kalitlar
Kuchsiz kalitlar
Kalitlarni noto'g'ri saqlash

Keng Tarqalgan Zaifliklar
❌ Xavfli Misollar
python# 1. PAROLNI OCHIQ SAQLASH
user = {
    'username': 'john',
    'password': 'mypassword123'  # ❌ JUDA XAVFLI!
}

# 2. ZAIF HASH ALGORITM
import hashlib
password_hash = hashlib.md5('password'.encode()).hexdigest()  
# ❌ MD5 zaif va tezlik hujumlariga ochiq

# 3. HARDCODED KALIT
SECRET_KEY = "my_secret_key_12345"  # ❌ Kodda ko'rinib turibdi!

# 4. HTTP ORQALI SENSITIVE DATA
curl http://api.example.com/user/credit-card  # ❌ Shifrlashsiz

# 5. ZAIF SHIFRLASH
from Crypto.Cipher import DES  # ❌ DES zaif algoritm
javascript// 6. CLIENT-SIDE ENCRYPTION FAQAT
const encrypted = btoa(password);  // ❌ Base64 shifrlash EMAS!

// 7. PREDICTABLE IV (Initialization Vector)
const iv = Buffer.from('1234567890123456');  // ❌ Static IV

// 8. SENSITIVE DATA LOCAL STORAGE'DA
localStorage.setItem('creditCard', '4111-1111-1111-1111');  // ❌
```

## Himoya qilish kerak bo'lgan ma'lumotlar
```
🔒 CRITICAL (Juda muhim):
- Parollar
- Kredit karta ma'lumotlari
- SSN / Passport raqamlari
- Tibbiy ma'lumotlar
- Biometrik data
- API kalitlari va tokenlar

⚠️ IMPORTANT (Muhim):
- Email manzillar
- Telefon raqamlari
- Manzil ma'lumotlari
- IP manzillar
- Session ID'lar
- Shaxsiy xabarlar
To'g'ri Himoya Choralari
1. Parollarni Xavfsiz Saqlash ✅
python# Python - bcrypt ishlatish
import bcrypt

# Parolni hash qilish
password = "user_password"
salt = bcrypt.gensalt(rounds=12)  # Cost factor: 12
hashed = bcrypt.hashpw(password.encode(), salt)

# Parolni tekshirish
if bcrypt.checkpw(password.encode(), hashed):
    print("Password correct!")
javascript// Node.js - bcrypt
const bcrypt = require('bcrypt');

// Hash qilish
const saltRounds = 12;
const hash = await bcrypt.hash('myPassword', saltRounds);

// Tekshirish
const match = await bcrypt.compare('myPassword', hash);
php// PHP - built-in funksiyalar
// Hash qilish
$hash = password_hash($password, PASSWORD_ARGON2ID);

// Tekshirish
if (password_verify($password, $hash)) {
    echo "Password correct!";
}
2. Ma'lumotlarni Shifrlash (Encryption) ✅
python# Python - Fernet (symmetric encryption)
from cryptography.fernet import Fernet

# Kalit generatsiya
key = Fernet.generate_key()
cipher = Fernet(key)

# Shifrlash
plaintext = b"Sensitive data"
encrypted = cipher.encrypt(plaintext)

# Deshifrlash
decrypted = cipher.decrypt(encrypted)
javascript// Node.js - crypto module (AES-256-GCM)
const crypto = require('crypto');

function encrypt(text, key) {
    const iv = crypto.randomBytes(16);  // Random IV
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
        iv: iv.toString('hex'),
        encrypted: encrypted,
        authTag: authTag.toString('hex')
    };
}

function decrypt(encrypted, key, iv, authTag) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

// Ishlatish
const key = crypto.randomBytes(32); // 256-bit kalit
const result = encrypt('Sensitive data', key);
const original = decrypt(result.encrypted, key, result.iv, result.authTag);
3. HTTPS (TLS/SSL) Konfiguratsiyasi ✅
nginx# Nginx konfiguratsiyasi
server {
    listen 443 ssl http2;
    server_name example.com;

    # Zamonaviy TLS versiyalari
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Kuchli cipher suite'lar
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    
    # Sertifikatlar
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # HTTP dan HTTPS ga redirect
    if ($scheme != "https") {
        return 301 https://$server_name$request_uri;
    }
}
javascript// Node.js - Express bilan HTTPS
const https = require('https');
const fs = require('fs');
const express = require('express');

const app = express();

const options = {
    key: fs.readFileSync('private-key.pem'),
    cert: fs.readFileSync('certificate.pem')
};

// HSTS middleware
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 
                  'max-age=31536000; includeSubDomains');
    next();
});

https.createServer(options, app).listen(443);
4. Environment Variables (Kalitlarni saqlash) ✅
bash# .env fayli (gitignore'da bo'lishi kerak!)
DATABASE_URL=postgresql://user:pass@localhost/db
SECRET_KEY=your-very-long-random-secret-key-here
API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz
ENCRYPTION_KEY=base64:random32ByteKeyInBase64Format==
python# Python - dotenv
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')

# ❌ ASLO BUNI QILMANG:
# SECRET_KEY = "hardcoded_key_123"
javascript// Node.js
require('dotenv').config();

const secretKey = process.env.SECRET_KEY;
const dbUrl = process.env.DATABASE_URL;
5. Database Encryption ✅
sql-- PostgreSQL - pg_crypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Ma'lumotni shifrlangan holda saqlash
INSERT INTO users (email, encrypted_ssn)
VALUES (
    'user@example.com',
    pgp_sym_encrypt('123-45-6789', 'encryption_key')
);

-- Ma'lumotni o'qish
SELECT 
    email,
    pgp_sym_decrypt(encrypted_ssn, 'encryption_key') as ssn
FROM users;
python# Django - encrypted fields
from django_cryptography.fields import encrypt

class User(models.Model):
    email = models.EmailField()
    ssn = encrypt(models.CharField(max_length=11))
    credit_card = encrypt(models.CharField(max_length=19))
6. Xavfsiz Random Number Generation ✅
python# Python
import secrets

# Xavfsiz random string
token = secrets.token_urlsafe(32)

# Xavfsiz random bytes
random_bytes = secrets.token_bytes(32)

# ❌ BUNI QILMANG:
import random
weak_token = str(random.randint(1000, 9999))  # Predictable!
javascript// Node.js
const crypto = require('crypto');

// Xavfsiz random string
const token = crypto.randomBytes(32).toString('hex');

// ❌ BUNI QILMANG:
const weakToken = Math.random().toString(36);  // Predictable!
```

## Tavsiya etiladigan Algoritmlar

### ✅ **Hashing (bir tomonlama)**
```
YAXSHI:
- Argon2id (eng yaxshi)
- bcrypt
- scrypt
- PBKDF2

QILMANG:
❌ MD5
❌ SHA-1
❌ Plain SHA-256 (parollar uchun)
```

### ✅ **Symmetric Encryption**
```
YAXSHI:
- AES-256-GCM (authenticated)
- ChaCha20-Poly1305
- AES-256-CBC (faqat HMAC bilan)

QILMANG:
❌ DES
❌ 3DES
❌ RC4
❌ AES-ECB mode
```

### ✅ **Asymmetric Encryption**
```
YAXSHI:
- RSA (minimum 2048-bit, yaxshisi 4096)
- ECC (Elliptic Curve - P-256 yoki yuqori)
- Ed25519 (signatures uchun)

QILMANG:
❌ RSA 1024-bit yoki past
Security Headers ✅
javascript// Express.js - helmet middleware
const helmet = require('helmet');
app.use(helmet());

// Yoki qo'lda:
app.use((req, res, next) => {
    // HTTPS majburiy
    res.setHeader('Strict-Transport-Security', 
                  'max-age=31536000; includeSubDomains; preload');
    
    // XSS himoya
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Content Security Policy
    res.setHeader('Content-Security-Policy', 
                  "default-src 'self'; script-src 'self'");
    
    next();
});
Certificate Pinning (Mobile Apps)
swift// iOS - Swift
let session = URLSession(configuration: .default, 
                        delegate: self, 
                        delegateQueue: nil)

func urlSession(_ session: URLSession, 
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    
    // Certificate pinning logic
    guard let serverTrust = challenge.protectionSpace.serverTrust else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    
    // Verify certificate
    // ...
}
Testing va Aniqlash
1. SSL/TLS Test Qilish
bash# SSL Labs test
# Online: https://www.ssllabs.com/ssltest/

# nmap bilan
nmap --script ssl-enum-ciphers -p 443 example.com

# testssl.sh
./testssl.sh https://example.com

# OpenSSL
openssl s_client -connect example.com:443 -tls1_2
2. Ma'lumotlar Bazasini Tekshirish
sql-- Parollar hash qilinganmi?
SELECT username, password FROM users LIMIT 5;
-- Agar qiymatlar plaintext ko'rinsa - XAVFLI!

-- Sensitive data shifrlangan mi?
SELECT * FROM credit_cards LIMIT 5;
3. Network Traffic Analiz
bash# Wireshark yoki tcpdump
tcpdump -i any -w capture.pcap port 80

# HTTP traffic uchun sensitive data qidirish
tcpdump -A -i any port 80 | grep -i "password\|credit"
4. Code Review Checklist
python# Qidiruv pattern'lari
grep -r "password\s*=\s*['\"]" .
grep -r "api_key\s*=\s*['\"]" .
grep -r "secret\s*=\s*['\"]" .
grep -r "md5\|sha1" .
grep -r "localStorage.setItem.*password" .
Best Practices
✅ QILING:

Har doim HTTPS ishlatng (HTTP yo'q!)
Zamonaviy algoritmlar: AES-256-GCM, bcrypt, Argon2
Kalitlarni environment variables'da saqlang
Regular security audit o'tkazing
Sensitive data log'larda ko'rinmasin
Database encryption ishlatng
Strong random generation (crypto.randomBytes)
Security headers qo'shing
Certificate pinning (mobile apps)
Regular dependency updates

❌ QILMANG:

Parollarni plaintext saqlash
MD5, SHA-1 ishlatish
Kalitlarni kodda yozish
HTTP orqali sensitive data yuborish
Client-side encryption'ga tayanish
Static IV ishlatish
Zaif TLS konfiguratsiya
localStorage'da sensitive data
Error message'larda sensitive info
Custom crypto implementatsiya (library ishlating!)

Real-World Misollar
LinkedIn (2012) - 6.5 million parollar MD5 bilan hash qilingan (salt siz) 💔
Adobe (2013) - 150 million parollar zaif encryption bilan saqlangan 💔
Equifax (2017) - SSL sertifikat muddati o'tgan 💔
